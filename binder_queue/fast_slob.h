/*
 * fast_slob.h: a simple but fast linked-list based buffer allocator
 * Copyright (c) 2012 Rong Shen <rong1129@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#ifndef _FAST_SLOB_H
#define _FAST_SLOB_H

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/cache.h>


#define MIN_ALLOC_SIZE		sizeof(char *)

//一个slob有多个桶，桶的大小由size和num_buckets决定，固定。
//而size决定了end的位置（start+size）
//初始化的时候需要提供size和桶的数目即可。同时制定最大分配大小，以及相邻桶的大小倍数关系
struct fast_slob {
	spinlock_t lock;

	size_t bucket_size;
	int min_alloc_size;
	int max_alloc_size;//和num_buckets，alloc_size_shift来一起决定min_alloc_size
	int alloc_size_shift;
	int num_buckets;

	char *start, *end;

	char *buckets[0];
};


static inline struct fast_slob *fast_slob_create(size_t size, int max_alloc_size, int alloc_size_shift, int num_buckets)
{
	struct fast_slob *slob;
	size_t bucket_size, min_alloc_size;
	char *start, *end, *buf;
	int i;
	//MIN_ALLOC_SIZE=4（32bit os），=8（64bit os）。一下当32bit os来讨论
	//确保max_alloc_size >=4，alloc_size_shift >=2,num_buckets>=1
	if (max_alloc_size < MIN_ALLOC_SIZE || alloc_size_shift < 1 || num_buckets < 1)
		return NULL;
	//bucket_size按照L1cache对齐，一般为64B，所以是向上取整。
	//如果size=64，num_buckets=1，则bucket_size=64刚好。
	//如果size=65，num_buckets=1，则bucket_size=128刚好。发现bucket_size * num_buckets > size，然后
	//修正为64。
	//整体操作即为：向下按照L1_CACHE对齐。
	bucket_size = L1_CACHE_ALIGN(size / num_buckets);
	if (bucket_size * num_buckets > size)
		bucket_size = (size / num_buckets) & ~(L1_CACHE_BYTES - 1);

	//确保bucket_size 大于最大分配大小
	if (bucket_size < max_alloc_size)
		return NULL;

	//最小分配大小由最大分配大小决定。
	min_alloc_size = max_alloc_size >> (alloc_size_shift * (num_buckets - 1));
	if (min_alloc_size < MIN_ALLOC_SIZE)
		return NULL;

	slob = kmalloc(sizeof(*slob) + num_buckets * sizeof(char *), GFP_KERNEL);
	if (!slob)
		return NULL;

	slob->start = vmalloc_user(size);
	if (!slob->start) {
		kfree(slob);
		return NULL;
	}

	slob->end = slob->start + size;
	slob->bucket_size = bucket_size;
	slob->min_alloc_size = min_alloc_size;
	slob->max_alloc_size = max_alloc_size;
	slob->alloc_size_shift = alloc_size_shift;
	slob->num_buckets = num_buckets;

	for (i = 0; i < num_buckets; i++) {
		start = slob->start + i * bucket_size;
		end = start + bucket_size;
		slob->buckets[i] = start;

		while (start < end) {
			buf = start;
			start += ALIGN(min_alloc_size, MIN_ALLOC_SIZE);
			*(char **)buf = (start < end) ? start : NULL;
		}

		min_alloc_size <<= alloc_size_shift;
	}

	spin_lock_init(&slob->lock);
	return slob;
}

static inline void fast_slob_destroy(struct fast_slob *slob)
{
	vfree(slob->start);
	kfree(slob);
}

static inline void *fast_slob_alloc(struct fast_slob *slob, size_t size)
{
	size_t alloc_size = slob->min_alloc_size;
	char *p;
	int i;

	spin_lock(&slob->lock);
	for (i = 0; i < slob->num_buckets; i++) {
		if (alloc_size >= size && slob->buckets[i]) {
			p = slob->buckets[i];
			slob->buckets[i] = *(char **)p;
			spin_unlock(&slob->lock);
			return p;
		}
		alloc_size <<= slob->alloc_size_shift;
	}
	spin_unlock(&slob->lock);

	return NULL;
}

static inline int fast_slob_bucket(struct fast_slob *slob, void *p)
{
	size_t off, alloc_size;
	int idx;

	if ((char *)p < slob->start || (char *)p >= slob->end)
		return -1;

	off = (char *)p - slob->start;
	idx = off / slob->bucket_size;
	alloc_size = slob->min_alloc_size << (idx * slob->alloc_size_shift);
	if ((off - idx * slob->bucket_size) % ALIGN(alloc_size, MIN_ALLOC_SIZE))
		return -1;

	return idx;
}

static inline void _fast_slob_free(struct fast_slob *slob, int idx, void *p)
{
	spin_lock(&slob->lock);
	*(char **)p = slob->buckets[idx];
	slob->buckets[idx] = p;
	spin_unlock(&slob->lock);
}

static inline void fast_slob_free(struct fast_slob *slob, void *p)
{
	int idx;

	if ((idx = fast_slob_bucket(slob, p)) < 0) {
		printk(KERN_WARNING "fast_slob: try to free an invalid buffer with address %p\n", p);
		return;
	}

	_fast_slob_free(slob, idx, p);
}

#endif	/* _FAST_SLOB_H */
