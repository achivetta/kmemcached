/** Hash table / Storage Engine
 *
 * This file is based on assoc.c from the memcached source.  It is the storage
 * engine for kmemcaced.  It was designed to be easily upgraded/replaced
 * independent from the rest of the projec.
 *
 * TODO This file contains code for resizing the hash table in another thread.
 * At the moment we've wrapped this code in ifdef ASSOC_SUPPORT_EXPAND to
 * disable it until we can implement this multi-threaded operation in the
 * kernel.
 *
 * TODO At the moment, there is no support for locking items or multi-threaded
 * operation.
 *
 * TODO At the moment, there is no support for eviction or expiration.  This
 * should be added.  It is likely that the reference memcached implementation
 * will be of some help in this regard.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "storage.h"
#include "hash.h"

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

/** Main hash table. */
static item_t** primary_hashtable = 0;

/** Number of items in the hash table. */
static unsigned int hash_items = 0;

static uint64_t cas;
static void update_cas(item_t* item){
  item->cas= ++cas;
}

bool initialize_storage(void) {
    primary_hashtable = vzalloc(hashsize(hashpower) * sizeof(void *));
    if (! primary_hashtable) {
        printk(KERN_INFO "assoc.c: Failed to init hashtable.\n");
        return false;
    }
    return true;
}

void shutdown_storage(void)
{
    flush(0);
    vfree(primary_hashtable);
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
    int depth = 0;

    it = primary_hashtable[hv & hashmask(hashpower)];

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

    pos = &primary_hashtable[hv & hashmask(hashpower)];

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

#ifndef NDEBUG
    BUG_ON(get_item(it->key, it->nkey) != 0);  /* shouldn't have duplicately named things defined */
#endif

    update_cas(it);

    hv = hash(it->key, it->nkey, 0);

    it->h_next = primary_hashtable[hv & hashmask(hashpower)];
    primary_hashtable[hv & hashmask(hashpower)] = it;

    hash_items++;
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
