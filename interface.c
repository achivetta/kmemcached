/** Implementation of memcached protocol.
 *
 * This is an implementation of v1 of the libmemcachedprotocol interface.  This
 * file is based off the example implementation of a memcached server in the
 * libmemcached source code.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/delay.h>
#include <asm-generic/errno.h>

#include "libmp/protocol_handler.h"
#include "libmp/byteorder.h"
#include "storage.h"

static protocol_binary_response_status add_handler(const void *cookie,
                                                   const void *key,
                                                   uint16_t keylen,
                                                   const void *data,
                                                   uint32_t datalen,
                                                   uint32_t flags,
                                                   uint32_t exptime,
                                                   uint64_t *cas)
{
    item_t* item;

    (void)cookie;

    item= create_item(key, keylen, data, datalen, flags, (time_t)exptime);
    if (item == 0) 
        return PROTOCOL_BINARY_RESPONSE_ENOMEM;

    if (add_item(item)){
        *cas= item->cas;
        release_item(item);
        return PROTOCOL_BINARY_RESPONSE_SUCCESS;
    } else {
        return PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
    }
}

static protocol_binary_response_status append_handler(const void *cookie,
                                                      const void *key,
                                                      uint16_t keylen,
                                                      const void* val,
                                                      uint32_t vallen,
                                                      uint64_t cas,
                                                      uint64_t *result_cas)
{
    (void)cookie;

    while (1){
        item_t *item, *nitem;
        uint64_t replace_cas;

        item= get_item(key, keylen);

        if (item == NULL)
            return PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
        
        if (cas != 0 && cas != item->cas){
            release_item(item);
            return PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
        }
        replace_cas = item->cas;
        
        if ((nitem= create_item(key, keylen, NULL, item->size + vallen,
                                       item->flags, item->exp)) == NULL) {
            release_item(item);
            return PROTOCOL_BINARY_RESPONSE_ENOMEM;
        }

        memcpy(nitem->data, item->data, item->size);
        memcpy(((char*)(nitem->data)) + item->size, val, vallen);

        release_item(item);

        if (replace_item(nitem, replace_cas) == 0){
            *result_cas= nitem->cas;
            release_item(nitem);
            return PROTOCOL_BINARY_RESPONSE_SUCCESS;
        }

        if (cas){
            *result_cas= nitem->cas;
            release_item(nitem);
            return PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
        }

        /* We had our item to append to switched out from under us, but that's
         * okay since we weren't trying to replace an item with a specific cas.
         * Now, we'll just try again. 
         */
    }
}

static protocol_binary_response_status decrement_handler(const void *cookie,
                                                         const void *key,
                                                         uint16_t keylen,
                                                         uint64_t delta,
                                                         uint64_t initial,
                                                         uint32_t expiration,
                                                         uint64_t *result,
                                                         uint64_t *result_cas) {

    // FIXME: How should this behave if the data is longer that 8 bytes? Shorter?
    // FIXME: "If the counter does not exist ... If the expiration value is all
    // one-bits (0xffffffff), the operation will fail with NOT_FOUND."

    while (1){
        item_t *item;
        uint64_t cas = 0;
        uint64_t val= initial;
        uint32_t new_expiration = expiration;

        item= get_item(key, keylen);

        if (item != NULL) {
            if (delta > *(uint64_t*)item->data)
                val= 0;
            else
                val= *(uint64_t*)item->data - delta;

            new_expiration= (uint32_t)item->exp;
            cas = item->cas;
            release_item(item);
        } 

        item= create_item(key, keylen, NULL, sizeof(initial), 0,
                          (time_t)expiration);
        if (item == NULL) {
            return PROTOCOL_BINARY_RESPONSE_ENOMEM;
        } else {
            memcpy(item->data, &val, sizeof(val));
            *result= val;
        }

        if ((cas && (replace_item(item,cas) == 0)) || add_item(item)){
            *result_cas= item->cas;
            release_item(item);
            return PROTOCOL_BINARY_RESPONSE_SUCCESS;
        }

        release_item(item);

        /* We had our item to decrement switched out from under us, but that's
         * okay since we weren't trying to replace an item with a specific cas.
         * Now, we'll just try again. 
         */
    }
}

static protocol_binary_response_status delete_handler(const void *cookie,
                                                      const void *key,
                                                      uint16_t keylen,
                                                      uint64_t cas) {
    (void)cookie;

    switch (delete_item(key,keylen,cas)){
        case 0: return PROTOCOL_BINARY_RESPONSE_SUCCESS;
        case -1: return PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
        case -2: return PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
        default: BUG(); return 0;
    }
}


static protocol_binary_response_status flush_handler(const void *cookie,
                                                     uint32_t when) {

    (void)cookie;
    flush(when);
    return PROTOCOL_BINARY_RESPONSE_SUCCESS;
}

static protocol_binary_response_status get_handler(const void *cookie,
                                                   const void *key,
                                                   uint16_t keylen,
                                                   memcached_binary_protocol_get_response_handler response_handler) {
    protocol_binary_response_status rc;
    item_t *item = get_item(key, keylen);


    if (item == NULL)
        return PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;

    rc= response_handler(cookie, key, (uint16_t)keylen, item->data,
                         (uint32_t)item->size, item->flags, item->cas);

    release_item(item);

    return rc;
}

static protocol_binary_response_status increment_handler(const void *cookie,
                                                         const void *key,
                                                         uint16_t keylen,
                                                         uint64_t delta,
                                                         uint64_t initial,
                                                         uint32_t expiration,
                                                         uint64_t *result,
                                                         uint64_t *result_cas) {
    // FIXME: How should this behave if the data is longer that 8 bytes? Shorter?
    // FIXME: "If the counter does not exist ... If the expiration value is all
    // one-bits (0xffffffff), the operation will fail with NOT_FOUND."

    while (1){
        item_t *item;
        uint64_t cas = 0;
        uint64_t val= initial;
        uint32_t new_expiration = expiration;

        item= get_item(key, keylen);

        if (item != NULL) {
            val= (*(uint64_t*)item->data) + delta;
            new_expiration= (uint32_t)item->exp;
            cas = item->cas;
            release_item(item);
        } 

        item= create_item(key, keylen, NULL, sizeof(initial), 0,
                          (time_t)expiration);
        if (item == NULL) {
            return PROTOCOL_BINARY_RESPONSE_ENOMEM;
        } else {
            memcpy(item->data, &val, sizeof(val));
            *result= val;
        }

        if ((cas && (replace_item(item,cas) == 0)) || add_item(item)){
                *result_cas= item->cas;
                release_item(item);
                return PROTOCOL_BINARY_RESPONSE_SUCCESS;
        }

        release_item(item);

        /* We had our item switched out from under us, but that's okay since we
         * weren't trying to replace an item with a specific cas.  Now, we'll
         * just try again. 
         */
    }
}

static protocol_binary_response_status noop_handler(const void *cookie) {
  (void)cookie;
  return PROTOCOL_BINARY_RESPONSE_SUCCESS;
}

static protocol_binary_response_status prepend_handler(const void *cookie,
                                                       const void *key,
                                                       uint16_t keylen,
                                                       const void* val,
                                                       uint32_t vallen,
                                                       uint64_t cas,
                                                       uint64_t *result_cas) {
    while (1){
        item_t *item, *nitem;
        uint64_t replace_cas;

        item= get_item(key, keylen);

        if (item == NULL)
            return PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
        
        if (cas != 0 && cas != item->cas){
            release_item(item);
            return PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
        }
        replace_cas = item->cas;
        
        if ((nitem= create_item(key, keylen, NULL, item->size + vallen,
                                       item->flags, item->exp)) == NULL) {
            release_item(item);
            return PROTOCOL_BINARY_RESPONSE_ENOMEM;
        }

        memcpy(nitem->data, val, vallen);
        memcpy(((char*)(nitem->data)) + vallen, item->data, item->size);

        release_item(item);

        if (replace_item(nitem, replace_cas) == 0){
            *result_cas= nitem->cas;
            release_item(nitem);
            return PROTOCOL_BINARY_RESPONSE_SUCCESS;
        }

        if (cas){
            *result_cas= nitem->cas;
            release_item(nitem);
            return PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
        }

        /* We had our item to prepend switched out from under us, but that's
         * okay since we weren't trying to replace an item with a specific cas.
         * Now, we'll just try again. 
         */
    }
}

static protocol_binary_response_status quit_handler(const void *cookie) {
  (void)cookie;
  return PROTOCOL_BINARY_RESPONSE_SUCCESS;
}

static protocol_binary_response_status replace_handler(const void *cookie,
                                                       const void *key,
                                                       uint16_t keylen,
                                                       const void* data,
                                                       uint32_t datalen,
                                                       uint32_t flags,
                                                       uint32_t exptime,
                                                       uint64_t cas,
                                                       uint64_t *result_cas) {
    item_t* item; 
    int ret;
    (void)cookie;

    item= create_item(key, keylen, data, datalen, flags, (time_t)exptime);
    if (item == NULL)
        return PROTOCOL_BINARY_RESPONSE_ENOMEM;

    ret = replace_item(item,cas);
    *result_cas = item->cas;
    release_item(item);

    switch (ret){
        case 0: return PROTOCOL_BINARY_RESPONSE_SUCCESS;
        case -1: return PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
        case -2: return PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
        default: BUG(); return 0;
    }
}

static protocol_binary_response_status set_handler(const void *cookie,
                                                   const void *key,
                                                   uint16_t keylen,
                                                   const void* data,
                                                   uint32_t datalen,
                                                   uint32_t flags,
                                                   uint32_t exptime,
                                                   uint64_t cas,
                                                   uint64_t *result_cas) {
    item_t* item;

    (void)cookie;

    if (cas != 0)
        return replace_handler(cookie, key, keylen, data, datalen, flags,
                               exptime, cas, result_cas);

    item= create_item(key, keylen, data, datalen, flags, (time_t)exptime);
    if (item == 0)
        return PROTOCOL_BINARY_RESPONSE_ENOMEM;

    set_item(item);
    *result_cas= item->cas;
    release_item(item);

    return PROTOCOL_BINARY_RESPONSE_SUCCESS;;
}

static protocol_binary_response_status stat_handler(const void *cookie,
                                                    const void *key,
                                                    uint16_t keylen,
                                                    memcached_binary_protocol_stat_response_handler response_handler) {
  (void)key;
  (void)keylen;
  /* Just return an empty packet */
  return response_handler(cookie, NULL, 0, NULL, 0);
}

static protocol_binary_response_status version_handler(const void *cookie,
                                                       memcached_binary_protocol_version_response_handler response_handler) {
  const char *version= "0.1.1";
  return response_handler(cookie, version, (uint32_t)strlen(version));
}

memcached_binary_protocol_callback_st interface_impl= {
  .interface_version= MEMCACHED_PROTOCOL_HANDLER_V1,
  .interface.v1= {
    .add= add_handler,
    .append= append_handler,
    .decrement= decrement_handler,
    .delete= delete_handler,
    .flush= flush_handler,
    .get= get_handler,
    .increment= increment_handler,
    .noop= noop_handler,
    .prepend= prepend_handler,
    .quit= quit_handler,
    .replace= replace_handler,
    .set= set_handler,
    .stat= stat_handler,
    .version= version_handler
  }
};
