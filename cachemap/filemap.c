#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lmdb.h>

#include "filemap.h"
#include "lz4.h"

struct data_prefix {
	uint128_t addr;
	int compressed_length;
};

#define DEBUG_ON	1
#define DBG_TRACE() \
	if (DEBUG_ON) printf("%s:%d : err %d\n", __func__, __LINE__, err)

static inline uint64_t
addr_key(uint128_t *addr)
{
	uint64_t hv;
	FNV_hash(addr, sizeof(uint128_t), &hv);
	return hv;
}

static inline MDB_env *
filemap_get_shard(struct filemap *m, uint128_t *addr, uint64_t *hv_out)
{
	uint64_t hv = addr_key(addr);
	int i = hv & (FILEMAP_SHARD_NUM - 1);
	*hv_out = hv;
	return m->env[i];
}

struct filemap *
filemap_create(char *destdir, uint64_t n, int compress_accel, int pshift)
{
	int err, i;
	MDB_dbi dbi = 0;
	MDB_txn *txn = NULL;
	struct filemap *m = (struct filemap*)calloc(1, sizeof(struct filemap));
	m->n = n;
	m->compress = compress_accel;
	m->bsize = 1 << pshift;
	m->pshift = pshift;

	strcpy(m->destdir, destdir);

	uint64_t shard_n = n / FILEMAP_SHARD_NUM;

	if (n < FILEMAP_SHARD_FACTOR)
		goto _exit;

	for (i = 0; i < FILEMAP_SHARD_NUM; i++) {
		char dbpath[2048];

		sprintf(dbpath, "%s/filemap.%d", m->destdir, i);

		err = mdb_env_create(&m->env[i]);
		if (err)
			goto _exit;

		err = mdb_env_set_maxreaders(m->env[i], 32);
		if (err)
			goto _exit;

		err = mdb_env_set_mapsize(m->env[i], 4 * shard_n * m->bsize);
		if (err)
			goto _exit;

		err = mdb_env_open(m->env[i], dbpath,
		    MDB_NOTLS | MDB_NOSYNC | MDB_NOSUBDIR | MDB_NORDAHEAD | MDB_NOMEMINIT, 0664);
		if (err)
			goto _exit;

		err = mdb_txn_begin(m->env[i], NULL, 0, &txn);
		if (err)
			goto _exit;

		err = mdb_dbi_open(txn, NULL, MDB_CREATE | MDB_INTEGERKEY, &dbi);
		if (err)
			goto _exit;

		err = mdb_txn_commit(txn);
		if (err)
			goto _exit;

		dbi = 0;
		txn = NULL;
	}
	return m;

_exit:
	if (dbi)
		mdb_dbi_close(m->env[i], dbi);
	if (txn)
		mdb_txn_abort(txn);
	filemap_free(m);
	DBG_TRACE();
	return NULL;
}

void
filemap_free(struct filemap *m)
{
	for (int i = 0; i < FILEMAP_SHARD_NUM; i++) {
		mdb_env_close(m->env[i]);
	}
	free(m);
}

void
filemap_set(struct filemap *m, uint128_t *addr, void *value, uint64_t attr)
{
	int err;
	uint64_t key;
	MDB_env *env = filemap_get_shard(m, addr, &key);
	MDB_txn *txn = NULL;
	char dest[m->bsize + 128];
	int actual;
	char *value_ptr;
	size_t value_size;

	if (m->compress) {
		/* compress outside of transaction to keep it scope short */
		actual = LZ4_compress_fast(value, &dest[0], m->bsize, m->bsize + 128,
		    m->compress);
		value_ptr = &dest[0];
		value_size = actual;
	} else {
		actual = 0;
		value_ptr = value;
		value_size = m->bsize;
	}

	err = mdb_txn_begin(env, NULL, 0, &txn);
	if (err)
		goto _exit;

	struct data_prefix prefix = { .addr = *addr, .compressed_length = actual };
	MDB_val k = { .mv_size = sizeof(uint64_t), .mv_data = &key };
	MDB_val page = { .mv_size = sizeof(struct data_prefix) + value_size, .mv_data = NULL };
	err = mdb_put_attr(txn, 1, &k, &page, attr, MDB_RESERVE);
	if (err)
		goto _exit;
	memcpy(page.mv_data, &prefix, sizeof(struct data_prefix));
	memcpy((char*)page.mv_data + sizeof(struct data_prefix), value_ptr, value_size);

	err = mdb_txn_commit(txn);
	if (err)
		goto _exit;

	return;
_exit:
	if (txn)
		mdb_txn_abort(txn);
	DBG_TRACE();
}

void
filemap_set_attr(struct filemap *m, uint128_t *addr, uint64_t attr)
{
	int err;
	uint64_t key;
	MDB_env *env = filemap_get_shard(m, addr, &key);
	MDB_txn *txn = NULL;

	err = mdb_txn_begin(env, NULL, 0, &txn);
	if (err)
		goto _exit;

	MDB_val k = { .mv_size = sizeof(uint64_t), .mv_data = &key };
	err = mdb_set_attr(txn, 1, &k, NULL, attr);
	if (err)
		goto _exit;

	err = mdb_txn_commit(txn);
	if (err)
		goto _exit;

	return;
_exit:
	if (txn)
		mdb_txn_abort(txn);
	DBG_TRACE();
}

void
filemap_unset(struct filemap *m, uint128_t *addr)
{
	int err;
	uint64_t key;
	MDB_env *env = filemap_get_shard(m, addr, &key);
	MDB_txn *txn = NULL;

	err = mdb_txn_begin(env, NULL, 0, &txn);
	if (err)
		goto _exit;

	MDB_val k = { .mv_size = sizeof(uint64_t), .mv_data = &key };
	err = mdb_del(txn, 1, &k, NULL);
	if (err)
		goto _exit;

	err = mdb_txn_commit(txn);
	if (err)
		goto _exit;

	return;
_exit:
	if (txn)
		mdb_txn_abort(txn);
	if (err != MDB_NOTFOUND)
		DBG_TRACE();
}

void *
filemap_get(struct filemap *m, uint128_t *addr)
{
	int err;
	uint64_t key;
	MDB_env *env = filemap_get_shard(m, addr, &key);
	MDB_txn *txn = NULL;

	err = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (err)
		goto _exit;

	MDB_val k = { .mv_size = sizeof(uint64_t), .mv_data = &key };
	MDB_val page;
	err = mdb_get(txn, 1, &k, &page);
	if (err)
		goto _exit;
	struct data_prefix *prefix = (struct data_prefix *)page.mv_data;

	if (memcmp(&prefix->addr, addr, sizeof(uint128_t)) != 0) {
printf("bad entry\n");
		err = MDB_NOTFOUND;
		goto _exit;
	}

	void *data = malloc(m->bsize);
	if (prefix->compressed_length) {
		int actual = LZ4_decompress_fast((char *)page.mv_data + sizeof(struct data_prefix), data, m->bsize);
		if (actual != prefix->compressed_length) {
			free(data);
			goto _exit;
		}
	} else {
		memcpy(data, (char *)page.mv_data + sizeof(struct data_prefix), m->bsize);
	}

	mdb_txn_abort(txn);

	return data;
_exit:
	if (txn)
		mdb_txn_abort(txn);
	if (err != MDB_NOTFOUND)
		DBG_TRACE();
	return NULL;
}

int
filemap_get_rand(struct filemap *m, uint128_t *addr, uint64_t *attrp)
{
	int err;
	MDB_txn *txn = NULL;
	MDB_cursor *cursor = NULL;

	uint64_t key = 0;
	for (int i = 0; i < 64; i += 30) {
		key = key * ((uint64_t)RAND_MAX + 1) + rand();
	}

	int i = key & (FILEMAP_SHARD_NUM - 1);
	MDB_env *env = m->env[i];

	err = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (err)
		goto _exit;

	err = mdb_cursor_open(txn, 1, &cursor);
	if (err)
		goto _exit;

	MDB_val k = { .mv_size = sizeof(uint64_t), .mv_data = &key };
	err = mdb_cursor_get(cursor, &k, NULL, MDB_SET_RANGE);
	if (err == MDB_NOTFOUND)
		err = mdb_cursor_get(cursor, &k, NULL, MDB_PREV);
	if (err)
		goto _exit;
	key = *(uint64_t *)k.mv_data;
	k.mv_data = &key;

	MDB_val v;
	err = mdb_cursor_get_attr(cursor, &k, &v, attrp);
	if (err)
		goto _exit;
	*addr = *(uint128_t *)v.mv_data;

	mdb_cursor_close(cursor);

	mdb_txn_abort(txn);

	return 1;
_exit:
	if (cursor)
		mdb_cursor_close(cursor);
	if (txn)
		mdb_txn_abort(txn);
	DBG_TRACE();
	return 0;
}

uint64_t
filemap_entries(struct filemap *m)
{
	int err;
	MDB_stat stat;
	uint64_t entries = 0;

	for (int i = 0; i < FILEMAP_SHARD_NUM; i++) {
		err = mdb_env_stat(m->env[i], &stat);
		if (err)
			return 0;
		entries += stat.ms_entries;
	}
	return entries;
}
