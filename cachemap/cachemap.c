#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include "cachemap.h"

static inline uint64_t
get_time_ns() {
	struct timespec tp;
	(void)clock_gettime(CLOCK_REALTIME_COARSE, &tp);
	return ((tp.tv_sec * 1000000000UL) + tp.tv_nsec);
}

static void
cachemap_put_work(struct cachemap *cm, struct addr_work *w)
{
	// is the cachemap full, evict
	if (filemap_entries(cm->pages) >= cm->capacity) {
		uint64_t a, b, c;
		uint128_t addra, addrb, addrc;

		// select MIN from 3 random timestamps
		filemap_get_rand(cm->pages, &addra, &a);
		filemap_get_rand(cm->pages, &addrb, &b);
		filemap_get_rand(cm->pages, &addrc, &c);

		uint128_t *smallest_addr;
		if (a < b) {
			if (a > c) {
				smallest_addr = &addrc;
			} else { // a <= c
				smallest_addr = &addra;
			}
		} else { // a >= b
			if (b > c) {
				smallest_addr = &addrc;
			} else { // b <= c
				smallest_addr = &addrb;
			}
		}
		filemap_unset(cm->pages, smallest_addr);
	}

	filemap_set(cm->pages, &w->addr, w->page, w->ts);
}

static void
addr_enqueue(struct cachemap *cm, struct addr_work *w)
{
	struct addr_node *temp = (struct addr_node *)malloc(sizeof(struct addr_node));
	temp->work = *w;
	temp->next = NULL;

	if (cm->front == NULL && cm->rear == NULL) {
		cm->front = cm->rear = temp;
		return;
	}
	cm->rear->next = temp;
	cm->rear = temp;
}

static int
addr_dequeue(struct cachemap *cm, struct addr_work *w_out)
{
	struct addr_node *temp = cm->front;

	if (cm->front == NULL) {
		return 0;
	}

	if (cm->front == cm->rear) {
		cm->front = cm->rear = NULL;
	} else {
		cm->front = cm->front->next;
	}
	*w_out = temp->work;
	free(temp);
	return 1;
}

static void
cachemap_thread(void *arg)
{
	struct cachemap *cm = arg;
	struct addr_work work;

	pthread_mutex_lock(&cm->cm_mutex);
	while (cm->front || !cm->cm_thread_stop) {
		if (!cm->front)
			pthread_cond_wait(&cm->step_condvar, &cm->cm_mutex);
		if (!addr_dequeue(cm, &work))
			continue;
		pthread_mutex_unlock(&cm->cm_mutex);

		cachemap_put_work(cm, &work);
		free(work.page);

		pthread_mutex_lock(&cm->cm_mutex);
	}
	pthread_mutex_unlock(&cm->cm_mutex);
	pthread_exit(0);
}

struct cachemap *
cachemap_create(char *destdir, int capacity, int comp_accel, int pshift)
{
	struct stat sb;
	int err;

	if (!(stat(destdir, &sb) == 0) || !S_ISDIR(sb.st_mode))
		return NULL;

	struct cachemap *cm = calloc(1, sizeof(struct cachemap));

	cm->pages = filemap_create(destdir, capacity, comp_accel, pshift);
	if (!cm->pages) {
		goto _exit;
	}

	for (int i = 0; i < PUT_THREADS; i++) {
		err = pthread_create(&cm->cm_thread[i], NULL,
		    (void *)&cachemap_thread, (void *)cm);
		if (err) {
			goto _exit;
		}
	}

	err = pthread_mutex_init(&cm->cm_mutex, NULL);
	if (err) {
		goto _exit;
	}

	err = pthread_cond_init(&cm->step_condvar, NULL);
	if (err) {
		goto _exit;
	}

	cm->capacity = capacity;

	return cm;
_exit:
	if (cm->pages)
		filemap_free(cm->pages);
	free(cm);
	return NULL;
}

static inline int
to_uint128_addr(struct cachemap *cm, uint64_t offset, uint64_t nhid_small,
    uint32_t genid, uint128_t *addr_out)
{
#define PNUM_SHIFT 44
	uint64_t l = offset >> cm->pages->pshift;

	if (l >> PNUM_SHIFT)
		return -1;

	l |= ((uint64_t)genid << PNUM_SHIFT);

	addr_out->l = l;
	addr_out->u = nhid_small;
	return 0;
}

void *
cachemap_get(struct cachemap *cm, uint64_t offset, uint64_t nhid_small,
    uint32_t genid)
{
	uint128_t addr;
	if (to_uint128_addr(cm, offset, nhid_small, genid, &addr) != 0)
		return NULL;

	cm->requests++;

	// is page already in cachemap - hit
	void *page = filemap_get(cm->pages, &addr);
	if (page) {
		cm->hits++;
	}
	return page;
}

void
cachemap_put(struct cachemap *cm, uint64_t offset, uint64_t nhid_small,
    uint32_t genid, void *page)
{
	struct addr_work work;
	if (to_uint128_addr(cm, offset, nhid_small, genid, &work.addr) != 0)
		return;

	work.page = page;
	work.ts = get_time_ns();
	cachemap_put_work(cm, &work);
}

void
cachemap_put_async(struct cachemap *cm, uint64_t offset, uint64_t nhid_small,
    uint32_t genid, void *page)
{
	struct addr_work work;
	if (to_uint128_addr(cm, offset, nhid_small, genid, &work.addr) != 0)
		return;

	work.page = malloc(cm->pages->bsize);
	memcpy(work.page, page, cm->pages->bsize);

	work.ts = get_time_ns();

	pthread_mutex_lock(&cm->cm_mutex);
	addr_enqueue(cm, &work);
	pthread_cond_broadcast(&cm->step_condvar);
	pthread_mutex_unlock(&cm->cm_mutex);
}

void
cachemap_free(struct cachemap *cm)
{
	pthread_mutex_lock(&cm->cm_mutex);
	cm->cm_thread_stop = 1;
	pthread_cond_broadcast(&cm->step_condvar);
	pthread_mutex_unlock(&cm->cm_mutex);

	for (int i = 0; i < PUT_THREADS; i++) {
		pthread_join(cm->cm_thread[i], NULL);
	}
	pthread_mutex_destroy(&cm->cm_mutex);
	filemap_free(cm->pages);
	free(cm);
}

void
cachemap_print_stats(struct cachemap *cm)
{
	printf("requests: %lu, hits: %lu, ratio: %5.2f\n",
	    cm->requests, cm->hits, cm->hits*100/(float)cm->requests);
}
