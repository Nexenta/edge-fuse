#ifndef CACHEMAP_H
#define CACHEMAP_H

#include <pthread.h>
#include "filemap.h"

#define PUT_THREADS	4

struct addr_work {
	uint128_t addr;
	void *page;
	uint64_t ts;
};

struct addr_node {
	struct addr_node *next;
	struct addr_work work;
};

struct cachemap {
	struct filemap *pages;
	struct addr_node *front;
	struct addr_node *rear;
	pthread_t cm_thread[PUT_THREADS];
	pthread_cond_t step_condvar;
	pthread_mutex_t cm_mutex;
	int cm_thread_stop;
	uint64_t capacity;
	uint64_t requests;
	uint64_t hits;
};

struct cachemap * cachemap_create (char *destdir, int capacity, int comp_accel,
    int bsize);

void cachemap_free(struct cachemap *cm);

void * cachemap_get(struct cachemap *cm, uint64_t offset,
    uint64_t nhid_small, uint32_t genid);

void cachemap_put(struct cachemap *cm, uint64_t offset,
    uint64_t nhid_small, uint32_t genid, void *page);

void cachemap_put_async(struct cachemap *cm, uint64_t offset,
    uint64_t nhid_small, uint32_t genid, void *page);

void cachemap_print_stats(struct cachemap *cm);

#endif
