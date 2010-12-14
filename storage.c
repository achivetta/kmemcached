/** Hash table / Storage Engine
 *
 * This file is based on assoc.c from the memcached source.  It is the storage
 * engine for kmemcaced.  It was designed to be easily upgraded/replaced
 * independent from the rest of the projec.
 *
 * TODO This file contains code for resizing the hast table in another thread.
 * At the moment we've wrapped this code in ifdef ASSOC_SUPPORT_EXPAND to
 * disable it until we can implement this multi-threaded operation in the
 * kernel.
 *
 * TODO At the moment, there is no support for locking items or multi-threaded
 * operation.
 *
 * TODO At the moment, there is no support for eviction or expiration.  This
 * should be added.  It is likely that he reference memcached implementation
 * will be of some help in this regard.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "storage.h"
#include "hash.h"

#ifdef ASSOC_SUPPORT_EXPAND
static pthread_cond_t maintenance_cond = PTHREAD_COND_INITIALIZER;
#endif

typedef  unsigned long  int  ub4;   /* unsigned 4-byte quantities */
typedef  unsigned       char ub1;   /* unsigned 1-byte quantities */

/** how many powers of 2's worth of buckets we use 
 *
 * For the moment, this is an important configuration value as the hash table
 * will never be resized.
 */
static unsigned int hashpower = 18;

#define hashsize(n) ((ub4)1<<(n))
#define hashmask(n) (hashsize(n)-1)

/* Main hash table. This is where we look except during expansion. */
static item_t** primary_hashtable = 0;

#ifdef ASSOC_SUPPORT_EXPAND
/*
 * Previous hash table. During expansion, we look here for keys that haven't
 * been moved over to the primary yet.
 */
static item_t** old_hashtable = 0;
#endif

/* Number of items in the hash table. */
static unsigned int hash_items = 0;

#ifdef ASSOC_SUPPORT_EXPAND
/* Flag: Are we in the middle of expanding now? */
static bool expanding = false;

/*
 * During expansion we migrate values with bucket granularity; this is how
 * far we've gotten so far. Ranges from 0 .. hashsize(hashpower - 1) - 1.
 */
static unsigned int expand_bucket = 0;

void do_assoc_move_next_bucket(void);
int start_assoc_maintenance_thread(void);
void stop_assoc_maintenance_thread(void);
#endif

static uint64_t cas;
static void update_cas(item_t* item)
{
  item->cas= ++cas;
}

bool initialize_storage(void) {
    // TODO should this be vmalloc()?
    primary_hashtable = kcalloc(hashsize(hashpower), sizeof(void *),GFP_KERNEL);
    if (! primary_hashtable) {
        printk(KERN_INFO "assoc.c: Failed to init hashtable.\n");
        return false;
    }
    return true;
}

void shutdown_storage(void)
{
    flush(0);
    kfree(primary_hashtable);
}

/** Create a new item.
 *
 * TODO This is one place that could use a lot of work.  For example, we
 * currently allocate the item, key and value seperately.  Putting the key at
 * the end of the struct and allocating them togeather would be a huge
 * improvement.  As would investigation into the best way to store the values.
 */
item_t* create_item(const char* key, size_t nkey, const char* data,
                         size_t size, uint32_t flags, time_t exp)
{
  item_t* ret= kcalloc(1, sizeof(item_t), GFP_KERNEL);

  if (ret != NULL)
  {
    ret->key= kmalloc(nkey, GFP_KERNEL);
    if (size > 0)
    {
      /* TODO We need to do some investigation into the best way to store data.
       * This seems to run out of memory fast.
       */
      ret->data= vmalloc(size);
    }

    if (ret->key == NULL || (size > 0 && ret->data == NULL))
    {
      kfree(ret->key);
      vfree(ret->data);
      kfree(ret);
      return NULL;
    }

    memcpy(ret->key, key, nkey);
    if (data != NULL)
    {
      memcpy(ret->data, data, size);
    }

    ret->nkey= nkey;
    ret->size= size;
    ret->flags= flags;
    ret->exp= exp;
  }

  return ret;
}

/** Get an item.
 *
 * TODO To implement multi-threaded operation, this should lock the item in some
 * way.  The item is then unlocked by release_item().
 */
item_t *get_item(const char *key, const size_t nkey) {
    uint32_t hv = hash(key, nkey, 0);
    item_t *it, *ret = NULL;
#ifdef ASSOC_SUPPORT_EXPAND
    unsigned int oldbucket;
#endif
    int depth = 0;

#ifdef ASSOC_SUPPORT_EXPAND
    if (expanding &&
        (oldbucket = (hv & hashmask(hashpower - 1))) >= expand_bucket)
    {
        it = old_hashtable[oldbucket];
    } else {
        it = primary_hashtable[hv & hashmask(hashpower)];
    }
#else
    it = primary_hashtable[hv & hashmask(hashpower)];
#endif

    while (it) {
        if ((nkey == it->nkey) && (memcmp(key, it->key, nkey) == 0)) {
            ret = it;
            break;
        }
        it = it->h_next;
        ++depth;
    }
    return ret;
}

/* returns the address of the item pointer before the key.  if *item == 0,
   the item wasn't found */
static item_t** _hashitem_before (const char *key, const size_t nkey) {
    uint32_t hv = hash(key, nkey, 0);
    item_t **pos;
#ifdef ASSOC_SUPPORT_EXPAND
    unsigned int oldbucket;

    if (expanding &&
        (oldbucket = (hv & hashmask(hashpower - 1))) >= expand_bucket)
    {
        pos = &old_hashtable[oldbucket];
    } else {
        pos = &primary_hashtable[hv & hashmask(hashpower)];
    }
#else
    pos = &primary_hashtable[hv & hashmask(hashpower)];
#endif

    while (*pos && ((nkey != (*pos)->nkey) || memcmp(key, (*pos)->key, nkey))) {
        pos = &(*pos)->h_next;
    }
    return pos;
}

/** Removes from the hash table and free()s an item
 */
bool delete_item(const char *key, const size_t nkey) {
    item_t **before = _hashitem_before(key, nkey);

    if (*before) {
        item_t *nxt;
        hash_items--;
        nxt = (*before)->h_next;
        (*before)->h_next = 0;   /* probably pointless, but whatever. */
        free_item(*before);
        *before = nxt;
        return true;
    }
    return false;
}

/* Note: this isn't an update.  The key must not already exist to call this */
void put_item(item_t *it) {
    uint32_t hv;
#ifdef ASSOC_SUPPORT_EXPAND
    unsigned int oldbucket;
#endif

#ifndef NDEBUG
    BUG_ON(get_item(it->key, it->nkey) != 0);  /* shouldn't have duplicately named things defined */
#endif

    update_cas(it);

    hv = hash(it->key, it->nkey, 0);

#ifdef ASSOC_SUPPORT_EXPAND
    if (expanding &&
        (oldbucket = (hv & hashmask(hashpower - 1))) >= expand_bucket)
    {
        it->h_next = old_hashtable[oldbucket];
        old_hashtable[oldbucket] = it;
    } else {
        it->h_next = primary_hashtable[hv & hashmask(hashpower)];
        primary_hashtable[hv & hashmask(hashpower)] = it;
    }
#else
    it->h_next = primary_hashtable[hv & hashmask(hashpower)];
    primary_hashtable[hv & hashmask(hashpower)] = it;
#endif

    hash_items++;
#ifdef ASSOC_SUPPORT_EXPAND
    if (! expanding && hash_items > (hashsize(hashpower) * 3) / 2) {
        assoc_expand();
    }
#endif
}

/** Release all locks on an item
 *
 * TODO Item locking needs to be implemented.
 */
void release_item(item_t* item){
    /* does nothing, currently */
}

/** Free the memory assocaited with an item.
 *
 * TODO You should hold the lock to an item when calling this.  The lock will
 * then be released.  If another thread has also got the same item, the free
 * will occur when the final thread has released the item.
 */
void free_item(item_t* item)
{
    kfree(item->key);
    vfree(item->data);
    kfree(item);
}

/** Purge ALL keys from the datastore
 *
 * TODO If provided, the when parameter specifies how far in the future the release
 * should occur.  Note that the release is not guarenteed to happen at this
 * time, only after it
 */
void flush(uint32_t when){
    int i;

    (void)when; //FIXME

    for(i = 0; i < hashsize(hashpower); i++){
        item_t *it = primary_hashtable[i], *next;
        while (it){
            next = it->h_next;
            free_item(it);
            it = next;
        }
        primary_hashtable[i] = NULL;
    }
}

#ifdef ASSOC_SUPPORT_EXPAND
/***************************************************************************
 * HERE LIES THINGS THAT INCREASE THE SIZE OF THE HASH SPACE               *
 ***************************************************************************/

/* grows the hashtable to the next power of 2. */
static void assoc_expand(void) {
    old_hashtable = primary_hashtable;

    primary_hashtable = calloc(hashsize(hashpower + 1), sizeof(void *));
    if (primary_hashtable) {
        if (settings.verbose > 1)
            fprintf(stderr, "Hash table expansion starting\n");
        hashpower++;
        expanding = true;
        expand_bucket = 0;
        pthread_cond_signal(&maintenance_cond);
    } else {
        primary_hashtable = old_hashtable;
        /* Bad news, but we can keep running. */
    }
}

static volatile int do_run_maintenance_thread = 1;

#define DEFAULT_HASH_BULK_MOVE 1
int hash_bulk_move = DEFAULT_HASH_BULK_MOVE;

static void *assoc_maintenance_thread(void *arg) {

    while (do_run_maintenance_thread) {
        int ii = 0;

        /* Lock the cache, and bulk move multiple buckets to the new
         * hash table. */
        pthread_mutex_lock(&cache_lock);

        for (ii = 0; ii < hash_bulk_move && expanding; ++ii) {
            item_t *it, *next;
            int bucket;

            for (it = old_hashtable[expand_bucket]; NULL != it; it = next) {
                next = it->h_next;

                bucket = hash(ITEM_key(it), it->nkey, 0) & hashmask(hashpower);
                it->h_next = primary_hashtable[bucket];
                primary_hashtable[bucket] = it;
            }

            old_hashtable[expand_bucket] = NULL;

            expand_bucket++;
            if (expand_bucket == hashsize(hashpower - 1)) {
                expanding = false;
                free(old_hashtable);
                if (settings.verbose > 1)
                    fprintf(stderr, "Hash table expansion done\n");
            }
        }

        if (!expanding) {
            /* We are done expanding.. just wait for next invocation */
            pthread_cond_wait(&maintenance_cond, &cache_lock);
        }

        pthread_mutex_unlock(&cache_lock);
    }
    return NULL;
}

static pthread_t maintenance_tid;

int start_assoc_maintenance_thread() {
    int ret;
    char *env = getenv("MEMCACHED_HASH_BULK_MOVE");
    if (env != NULL) {
        hash_bulk_move = atoi(env);
        if (hash_bulk_move == 0) {
            hash_bulk_move = DEFAULT_HASH_BULK_MOVE;
        }
    }
    if ((ret = pthread_create(&maintenance_tid, NULL,
                              assoc_maintenance_thread, NULL)) != 0) {
        fprintf(stderr, "Can't create thread: %s\n", strerror(ret));
        return -1;
    }
    return 0;
}

void stop_assoc_maintenance_thread() {
    pthread_mutex_lock(&cache_lock);
    do_run_maintenance_thread = 0;
    pthread_cond_signal(&maintenance_cond);
    pthread_mutex_unlock(&cache_lock);

    /* Wait for the maintenance thread to stop */
    pthread_join(maintenance_tid, NULL);
}

#endif
