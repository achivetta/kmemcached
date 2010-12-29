/** Hash table / Storage Engine
 *
 * This file is based on assoc.c from the memcached source.  It is the storage
 * engine for kmemcaced.  
 *
 * The scope of the operations in this file is the minimum necessairy to ensure
 * the entire memcached protocol can be supported atomically while not ever
 * allowing a caller to hold a write lock across calls.  Operations such as
 * append are to be implemented via optimistic locking using the cas values of
 * the items.
 *
 * TODO Add support for resizing the hash table.
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

#ifdef CONFIG_LOCKDEP
# define HASH_LOCK_SZ	256
#else
# if NR_CPUS >= 32
#  define HASH_LOCK_SZ	((uint32_t)1<<(hashpower-5))
# elif NR_CPUS >= 16
#  define HASH_LOCK_SZ	((uint32_t)1<<(hashpower-6))
# elif NR_CPUS >= 8
#  define HASH_LOCK_SZ	((uint32_t)1<<(hashpower-7))
# elif NR_CPUS >= 4
#  define HASH_LOCK_SZ	((uint32_t)1<<(hashpower-8))
# else
#  define HASH_LOCK_SZ	((uint32_t)1<<(hashpower-9))
# endif
#endif

static spinlock_t *hash_locks;
# define hash_lock_addr(slot) &hash_locks[(slot) & (HASH_LOCK_SZ - 1)]

/** how many powers of 2's worth of buckets we use 
 *
 * For the moment, this is an important configuration value as the hash table
 * is never resized.
 */
static const unsigned int hashpower = 18;

#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

/** Main hash table. */
static item_t** hashtable = 0;

/** Number of items in the hash table. */
static atomic_t hash_items;

static uint64_t cas;
// FIXME it seems we never use this, that's obviousily wrong...
static void update_cas(item_t* item){ item->cas= ++cas; }

bool initialize_storage(void) 
{
    int i;

    hashtable = vzalloc(hashsize(hashpower) * sizeof(void *));

    if (!hashtable) {
        printk(KERN_INFO "assoc.c: Failed to init hashtable.\n");
        return false;
    }

    hash_locks = vmalloc(sizeof(spinlock_t) * HASH_LOCK_SZ);
	if (!hash_locks){
        printk(KERN_INFO "assoc.c: Failed to init hashtable locks.\n");
        vfree(hashtable);
    }

	for (i = 0; i < HASH_LOCK_SZ; i++)
		spin_lock_init(&hash_locks[i]);

    atomic_set(&hash_items,0);

    return true;
}

void shutdown_storage(void)
{
    flush(0);
    vfree(hashtable);
    vfree(hash_locks);
}

/** Create a new item.
 *
 * The caller will hold a reference to the item after creation.
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

    if (ret != NULL){
        ret->key= kmalloc(nkey, GFP_KERNEL);
        if (size > 0)
            ret->data= vmalloc(size);
            /* TODO We need to do some investigation into the best way to store data.
             * This seems to run out of memory fast. */

        if (ret->key == NULL || (size > 0 && ret->data == NULL)){
            kfree(ret->key);
            vfree(ret->data);
            kfree(ret);
            return NULL;
        }

        memcpy(ret->key, key, nkey);
        if (data != NULL)
            memcpy(ret->data, data, size);

        ret->nkey= nkey;
        ret->size= size;
        ret->flags= flags;
        ret->exp= exp;
        atomic_set(&ret->refcount,1);
    }

    return ret;
}

/** Clone an item. */
item_t* clone_item(item_t *item){
    return NULL;
}

/** Fetch an item.
 *
 * This will get a reference to an item and increment its reference count.  You
 * must then release the reference by calling release_item() when done with it.
 */
item_t *get_item(const char *key, const size_t nkey) 
{
    uint32_t hv = hash(key, nkey, 0);
    item_t *it;

    rcu_read_lock();

    it = hashtable[hv & hashmask(hashpower)];

    while (it) {
        if ((nkey == it->nkey) && (memcmp(key, it->key, nkey) == 0))
            break;
        it = it->h_next;
    }

    if (!atomic_inc_not_zero(&it->refcount)) {
        rcu_read_unlock();
        return NULL;
    }

    rcu_read_unlock();

    return it;
}

/** Delete an item with the specified key. 
 *
 * The caller may or may not hold a reference to this item.  If any references
 * are outstanding, the item will persist until the last reference is released.
 *
 * returns:  0 on success
 *          -1 if item did not exist
 *          -2 if item's cas did not match
 */
int delete_item(const char *key, const size_t nkey, uint64_t cas) 
{
    uint32_t hv = hash(key, nkey, 0);
    int bucket = hv & hashmask(hashpower);
    item_t **ptr, *item;

    spin_lock(hash_lock_addr(bucket));

    ptr = &hashtable[bucket];

    while (*ptr && ((nkey != (*ptr)->nkey) || memcmp(key, (*ptr)->key, nkey))) {
        ptr = &(*ptr)->h_next;
    }

    if ((item = *ptr) == NULL) {
        spin_unlock(hash_lock_addr(bucket));
        return -1; /* item not found */
    }

    if (item->cas != cas){
        spin_unlock(hash_lock_addr(bucket));
        return -2; /* cas did not match */
    }

    *ptr = item->h_next;;

    spin_unlock(hash_lock_addr(bucket));

    atomic_dec(&hash_items);

    release_item(item);

    return 0;
}

/** Insert an item unconditionally. */
void set_item(item_t* item)
{
    uint32_t hv = hash(item->key, item->nkey, 0);
    int bucket = hv & hashmask(hashpower);
    item_t **ptr, *old_item;

    spin_lock(hash_lock_addr(bucket));

    ptr = &hashtable[bucket];

    while (*ptr && ((item->nkey != (*ptr)->nkey) || memcmp(item->key, (*ptr)->key, item->nkey))) {
        ptr = &(*ptr)->h_next;
    }

    old_item = *ptr;

    if (old_item){
        item->h_next = old_item->h_next;
        wmb();
    }

    *ptr = item;

    atomic_inc(&item->refcount);

    spin_unlock(hash_lock_addr(bucket));

    if (old_item)
        release_item(old_item);
    else 
        atomic_inc(&hash_items);
}

/** Update an item if it already exists. 
 *
 * A reference must be held on the item passed.
 *
 * returns: 0 on success
 *          -1 if item did not exist
 *          -2 if item's cas did not match
 */
int replace_item(item_t* item, uint64_t cas)
{
    uint32_t hv = hash(item->key, item->nkey, 0);
    int bucket = hv & hashmask(hashpower);
    item_t **ptr, *old_item;

    spin_lock(hash_lock_addr(bucket));

    ptr = &hashtable[bucket];

    while (*ptr && ((item->nkey != (*ptr)->nkey) || memcmp(item->key, (*ptr)->key, item->nkey))) {
        ptr = &(*ptr)->h_next;
    }

    if ((old_item = *ptr) == NULL) {
        spin_unlock(hash_lock_addr(bucket));
        return -1; /* item did not exist */
    }

    if (old_item->cas != cas){
        spin_unlock(hash_lock_addr(bucket));
        return -2; /* cas did not match */
    }

    item->h_next = old_item->h_next;
    wmb();
    *ptr = item;

    atomic_inc(&item->refcount);

    spin_unlock(hash_lock_addr(bucket));

    release_item(old_item);

    return 0;
}

/** Insert an item if it does not already exist. */
bool add_item(item_t* item)
{
    uint32_t hv = hash(item->key, item->nkey, 0);
    int bucket = hv & hashmask(hashpower);
    item_t **ptr;

    spin_lock(hash_lock_addr(bucket));

    ptr = &hashtable[bucket];

    while (*ptr && ((item->nkey != (*ptr)->nkey) || memcmp(item->key, (*ptr)->key, item->nkey))) {
        ptr = &(*ptr)->h_next;
    }

    if (*ptr != NULL) {
        spin_unlock(hash_lock_addr(bucket));
        return false; /* item did exist */
    }

    *ptr = item;

    atomic_inc(&item->refcount);

    spin_unlock(hash_lock_addr(bucket));

    atomic_inc(&hash_items);

    return 0;
}

/** Free the memory assocaited with an item. */
static void free_item(item_t *item){
    kfree(item->key);
    vfree(item->data);
    kfree(item);
}

static void rcu_free_item(struct rcu_head *head)
{
    free_item(container_of(head, item_t, rcu_head));
}


/** Release the reference to an item. */
void release_item(item_t* item)
{
    if (atomic_dec_and_test(&item->refcount)){
        call_rcu(&item->rcu_head,rcu_free_item);
    }
}

/** Flush all items
 *
 * TODO If provided, the when parameter specifies how far in the future the release
 * should occur.  Note that the release is not guarenteed to happen at this
 * time, only after it.
 */
void flush(uint32_t when)
{
    /*
    int i;

    (void)when;

    for(i = 0; i < hashsize(hashpower); i++){
        item_t *it = hashtable[i], *next;
        while (it){
            next = it->h_next;
            free_item(it);
            it = next;
        }
        hashtable[i] = NULL;
    }
    */
}
