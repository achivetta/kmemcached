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

/** how many powers of 2's worth of buckets we use 
 *
 * For the moment, this is an important configuration value as the hash table
 * will never be resized.
 */
static unsigned int hashpower = 18;

#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

/** Main hash table. */
static item_t** hashtable = 0;

/** Number of items in the hash table. */
static unsigned int hash_items = 0;

static uint64_t cas;
static void update_cas(item_t* item){ item->cas= ++cas; }

bool initialize_storage(void) 
{
    hashtable = vzalloc(hashsize(hashpower) * sizeof(void *));
    if (! hashtable) {
        printk(KERN_INFO "assoc.c: Failed to init hashtable.\n");
        return false;
    }
    return true;
}

void shutdown_storage(void)
{
    flush(0);
    vfree(hashtable);
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
        if (size > 0){
            /* TODO We need to do some investigation into the best way to store data.
             * This seems to run out of memory fast.
             */
            ret->data= vmalloc(size);
        }

        if (ret->key == NULL || (size > 0 && ret->data == NULL)){
            kfree(ret->key);
            vfree(ret->data);
            kfree(ret);
            return NULL;
        }

        memcpy(ret->key, key, nkey);
        if (data != NULL){
            memcpy(ret->data, data, size);
        }

        ret->nkey= nkey;
        ret->size= size;
        ret->flags= flags;
        ret->exp= exp;
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
    item_t *it, *ret = NULL;
    int depth = 0;

    it = hashtable[hv & hashmask(hashpower)];

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
static item_t** _hashitem_before (const char *key, const size_t nkey) 
{
    uint32_t hv = hash(key, nkey, 0);
    item_t **pos;

    pos = &hashtable[hv & hashmask(hashpower)];

    while (*pos && ((nkey != (*pos)->nkey) || memcmp(key, (*pos)->key, nkey))) {
        pos = &(*pos)->h_next;
    }
    return pos;
}

/** Delete an item with the specified key. 
 *
 * The caller may or may not hold a reference to this item.  If any references
 * are outstanding, the item will persist until the last reference is released.
 *
 * returns: 0 on success
 *          -1 if item did not exist
 *          -2 if item's cas did not match
 */
int delete_item(const char *key, const size_t nkey, uint64_t cas) 
{
    item_t **before = _hashitem_before(key, nkey);

    if (*before) {
        item_t *nxt;
        hash_items--;
        nxt = (*before)->h_next;
        (*before)->h_next = 0;   /* probably pointless, but whatever. */
        //free_item(*before);
        *before = nxt;
        return true;
    }
    return false;
}

/** Insert an item unconditionally. */
void set_item(item_t* item)
{
}

/** Update an item if it already exists. 
 *
 * A reference must be held on the item.
 *
 * returns: 0 on success
 *          -1 if item did not exist
 *          -2 if item's cas did not match
 */
int replace_item(item_t* item, uint64_t cas)
{
    return false;
}

/** Insert an item if it does not already exist. */
bool add_item(item_t* it)
{
    uint32_t hv;

#ifndef NDEBUG
    BUG_ON(get_item(it->key, it->nkey) != 0);  /* shouldn't have duplicately named things defined */
#endif

    update_cas(it);

    hv = hash(it->key, it->nkey, 0);

    it->h_next = hashtable[hv & hashmask(hashpower)];
    hashtable[hv & hashmask(hashpower)] = it;

    hash_items++;
    return true;
}

/** Free the memory assocaited with an item. */
static void free_item(item_t* item)
{
    kfree(item->key);
    vfree(item->data);
    kfree(item);
}

/** Release the reference to an item. */
void release_item(item_t* item)
{
    /* does nothing, currently */
}


/** Flush all items
 *
 * TODO If provided, the when parameter specifies how far in the future the release
 * should occur.  Note that the release is not guarenteed to happen at this
 * time, only after it
 */
void flush(uint32_t when)
{
    int i;

    (void)when; //FIXME

    for(i = 0; i < hashsize(hashpower); i++){
        item_t *it = hashtable[i], *next;
        while (it){
            next = it->h_next;
            free_item(it);
            it = next;
        }
        hashtable[i] = NULL;
    }
}
