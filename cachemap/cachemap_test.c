#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

#include "cachemap.h"

#define MAXOBJ 10*32768
#define COMP_ACCEL 8
#define PAGE_SHIFT 14
#define PAGE_SIZE (1<<PAGE_SHIFT)

struct obj {
	uint64_t offset;
	uint64_t nhid_small;
	uint32_t genid;
	char page[PAGE_SIZE];
};

static int
test(char *destdir)
{
	srandom(time(NULL));
	clock_t t1, t2;
	uint64_t bytes = 0;

	struct cachemap *cm = cachemap_create(destdir, MAXOBJ, COMP_ACCEL, PAGE_SHIFT);

	if (!cm) {
		printf("Error: directory %s not found\n", destdir);
		return -1;
	}

	printf("Preparing test..\n");
	struct obj *objs[MAXOBJ];
	for (int i = 0; i < MAXOBJ; ++i) {
		objs[i] = malloc(sizeof(struct obj));
		objs[i]->offset = i * 4096UL;
		objs[i]->genid = i;
		objs[i]->nhid_small = i * random();
		objs[i]->page[0] = i;
		bytes += PAGE_SIZE;
	}

	printf("Now running test on %ldMB of data\n", bytes/1024UL/1024UL);

	t1 = clock();
	for (int i = 0; i < MAXOBJ; ++i) {
		cachemap_put_async(cm, objs[i]->offset, objs[i]->nhid_small,
		    objs[i]->genid, objs[i]->page);
	}
	t2 = clock();

	usleep(1000000);

	printf("Inserted %d objects in %.6fs\n", MAXOBJ, ((double)(t2-t1))/CLOCKS_PER_SEC);
	cachemap_print_stats(cm);

	t1 = clock();
	for (int i = 0; i < MAXOBJ; ++i) {
		void *p = cachemap_get(cm, objs[i]->offset, objs[i]->nhid_small,
		    objs[i]->genid);
		free(p);
	}
	t2 = clock();

	printf("Read %d objects in %.6fs\n", MAXOBJ, ((double)(t2-t1))/CLOCKS_PER_SEC);
	cachemap_print_stats(cm);

	t1 = clock();
	for (int i = 0; i < MAXOBJ; ++i) {
		void *p = cachemap_get(cm, objs[i]->offset, objs[i]->nhid_small,
		    objs[i]->genid);
		free(p);
	}
	t2 = clock();

	printf("Re-read %d objects in %.6fs\n", MAXOBJ, ((double)(t2-t1))/CLOCKS_PER_SEC);
	cachemap_print_stats(cm);

	t1 = clock();
	for (int i = 0; i < MAXOBJ/2; ++i) {
		objs[i]->genid = random();
		cachemap_put_async(cm, objs[i]->offset, objs[i]->nhid_small,
		    objs[i]->genid, objs[i]->page);
	}
	t2 = clock();

	printf("Added %d objects in %.6fs\n", MAXOBJ/2, ((double)(t2-t1))/CLOCKS_PER_SEC);
	cachemap_print_stats(cm);

	t1 = clock();
	for (int i = 0; i < MAXOBJ; ++i) {
		void *p = cachemap_get(cm, objs[i]->offset, objs[i]->nhid_small,
		    objs[i]->genid);
		free(p);
	}
	t2 = clock();

	printf("Read %d objects in %.6fs\n", MAXOBJ, ((double)(t2-t1))/CLOCKS_PER_SEC);
	cachemap_print_stats(cm);

	t1 = clock();
	for (int i = 0; i < MAXOBJ; ++i) {
		void *p = cachemap_get(cm, objs[i]->offset, objs[i]->nhid_small,
		    objs[i]->genid);
		free(p);
	}
	t2 = clock();

	printf("Re-read %d objects in %.6fs\n", MAXOBJ, ((double)(t2-t1))/CLOCKS_PER_SEC);
	cachemap_print_stats(cm);

	cachemap_free(cm);
	for (int i = 0; i < MAXOBJ; ++i) {
		free(objs[i]);
	}

	return 0;
}

int
main (int argc, char **argv)
{
	if (argc != 2) {
		printf("Usage: cachemap_test <TESTDIR>\n");
		return -1;
	}
	test(argv[1]);
	return 0;
}
