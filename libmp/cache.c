/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* TODO This seems remarkabily like the linux slab allocator.  I think it should
 * be replaced with that.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/smp_lock.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/delay.h>
#include <asm-generic/errno.h>

#include "cache.h"

#ifndef NDEBUG
const uint32_t redzone_pattern = 0xdeadbeef;
int cache_error = 0;
#endif

const size_t initial_pool_size = 64;

static char* strdup(const char *str){
    char *new = kmalloc(strlen(str)+1, GFP_KERNEL);
    if (new == NULL)
        return NULL;
    strcpy(new,str);
    return new;
}

cache_t* cache_create(const char *name, size_t bufsize, size_t align,
                      cache_constructor_t* constructor,
                      cache_destructor_t* destructor) {
    cache_t* ret = kcalloc(1, sizeof(cache_t), GFP_KERNEL);
    char* nm = strdup(name);
    void** ptr = kcalloc(initial_pool_size, bufsize, GFP_KERNEL);
    if (ret == NULL || nm == NULL || ptr == NULL /*||
        pthread_mutex_init(&ret->mutex, NULL) == -1*/) {
        kfree(ret);
        kfree(nm);
        kfree(ptr);
        return NULL;
    }

    ret->name = nm;
    ret->ptr = ptr;
    ret->freetotal = initial_pool_size;
    ret->constructor = constructor;
    ret->destructor = destructor;

#ifndef NDEBUG
    ret->bufsize = bufsize + 2 * sizeof(redzone_pattern);
#else
    ret->bufsize = bufsize;
#endif

    (void)align;

    return ret;
}

static inline void* get_object(void *ptr) {
#ifndef NDEBUG
    uint64_t *pre = ptr;
    return pre + 1;
#else
    return ptr;
#endif
}

void cache_destroy(cache_t *cache) {
    while (cache->freecurr > 0) {
        void *ptr = cache->ptr[--cache->freecurr];
        if (cache->destructor) {
            cache->destructor(get_object(ptr), NULL);
        }
        kfree(ptr);
    }
    kfree(cache->name);
    kfree(cache->ptr);
    //pthread_mutex_destroy(&cache->mutex);
}

void* cache_alloc(cache_t *cache) {
    void *ret;
    void *object;
    //pthread_mutex_lock(&cache->mutex);
    if (cache->freecurr > 0) {
        ret = cache->ptr[--cache->freecurr];
        object = get_object(ret);
    } else {
        object = ret = kmalloc(cache->bufsize, GFP_KERNEL);
        if (ret != NULL) {
            object = get_object(ret);

            if (cache->constructor != NULL &&
                cache->constructor(object, NULL, 0) != 0) {
                kfree(ret);
                object = NULL;
            }
        }
    }
    //pthread_mutex_unlock(&cache->mutex);

#ifndef NDEBUG
    if (object != NULL) {
        /* add a simple form of buffer-check */
        uint64_t *pre = ret;
        *pre = redzone_pattern;
        ret = pre+1;
        memcpy(((char*)ret) + cache->bufsize - (2 * sizeof(redzone_pattern)),
               &redzone_pattern, sizeof(redzone_pattern));
    }
#endif

    return object;
}

void cache_free(cache_t *cache, void *ptr) {
    //pthread_mutex_lock(&cache->mutex);
    uint64_t *pre;

#ifndef NDEBUG
    /* validate redzone... */
    if (memcmp(((char*)ptr) + cache->bufsize - (2 * sizeof(redzone_pattern)),
               &redzone_pattern, sizeof(redzone_pattern)) != 0) {
        BUG();
        cache_error = 1;
        //pthread_mutex_unlock(&cache->mutex);
        return;
    }
    pre = ptr;
    --pre;
    if (*pre != redzone_pattern) {
        BUG();
        cache_error = -1;
        //pthread_mutex_unlock(&cache->mutex);
        return;
    }
    ptr = pre;
#endif
    if (cache->freecurr < cache->freetotal) {
        cache->ptr[cache->freecurr++] = ptr;
    } else {
        /* try to enlarge free connections array */
        size_t newtotal = cache->freetotal * 2;
        void **new_free = krealloc(cache->ptr, sizeof(char *) * newtotal, GFP_KERNEL);
        if (new_free) {
            cache->freetotal = newtotal;
            cache->ptr = new_free;
            cache->ptr[cache->freecurr++] = ptr;
        } else {
            if (cache->destructor) {
                cache->destructor(ptr, NULL);
            }
            kfree(ptr);

        }
    }
    //pthread_mutex_unlock(&cache->mutex);
}

