#ifndef FILEMAP_H
#define FILEMAP_H

#include <lmdb.h>
#include "uint128.h"

#define FILEMAP_SHARD_NUM	32
#define FILEMAP_SHARD_FACTOR	1024

struct filemap {
	uint64_t n;		// number of buckets
	int compress;		// enable compression (LZ4 acceleration)
	int bsize;		// cached block size
	uint64_t pshift;	// cached block size associated page shift
	char destdir[2048];	// location where cache files should be stored
	MDB_env *env[FILEMAP_SHARD_NUM];
};

struct filemap *filemap_create(char *destdir, uint64_t n, int compress_accel,
    int pshift);
void filemap_free(struct filemap *m);

void filemap_set(struct filemap *m, uint128_t *key, void *value, uint64_t attr);
void filemap_unset(struct filemap *m, uint128_t *key);

void *filemap_get(struct filemap *m, uint128_t *key);
int filemap_get_rand(struct filemap *m, uint128_t *key, uint64_t *ts);

uint64_t filemap_entries(struct filemap *m);

#endif
