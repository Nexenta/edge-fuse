#ifndef UINT128_H
#define UINT128_H

typedef struct { uint64_t u; uint64_t l; } uint128_t;

static inline void
FNV_hash(const void *key, int length, uint64_t *out)
{
	unsigned char* p = (unsigned char *)key;
	uint64_t fnv64offset = 14695981039346656037ULL;
	uint64_t fnv64prime = 0x100000001b3ULL;
	uint64_t h = fnv64offset;
	int i;

	for (i = 0; i < length; i++) {
		h = h ^ p[i];
		h *= fnv64prime;
	}

	*out = h;
}

#endif
