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
    protocol_binary_response_status rval= PROTOCOL_BINARY_RESPONSE_SUCCESS;
    item_t* item;

    (void)cookie;
    write_lock(&storage_lock);

    item = get_item(key, keylen);

    if (item == NULL) {
        item= create_item(key, keylen, data, datalen, flags, (time_t)exptime);
        if (item == 0) {
            rval= PROTOCOL_BINARY_RESPONSE_ENOMEM;
        } else {
            put_item(item);
            *cas= item->cas;
            release_item(item);
        }
    } else {
        rval= PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
    }

    write_unlock(&storage_lock);
    return rval;
}

static protocol_binary_response_status append_handler(const void *cookie,
                                                      const void *key,
                                                      uint16_t keylen,
                                                      const void* val,
                                                      uint32_t vallen,
                                                      uint64_t cas,
                                                      uint64_t *result_cas)
{
    protocol_binary_response_status rval= PROTOCOL_BINARY_RESPONSE_SUCCESS;
    item_t *item, *nitem;

    write_lock(&storage_lock);
    (void)cookie;

    item= get_item(key, keylen);

    if (item == NULL) {
        rval= PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
    } else if (cas != 0 && cas != item->cas) {
        rval= PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
    } else if ((nitem= create_item(key, keylen, NULL, item->size + vallen,
                                   item->flags, item->exp)) == NULL) {
        release_item(item);
        rval= PROTOCOL_BINARY_RESPONSE_ENOMEM;
    } else {
        memcpy(nitem->data, item->data, item->size);
        memcpy(((char*)(nitem->data)) + item->size, val, vallen);
        release_item(item);
        delete_item(key, keylen);
        put_item(nitem);
        *result_cas= nitem->cas;
        release_item(nitem);
    }

    write_unlock(&storage_lock);
    return rval;
}

static protocol_binary_response_status decrement_handler(const void *cookie,
                                                         const void *key,
                                                         uint16_t keylen,
                                                         uint64_t delta,
                                                         uint64_t initial,
                                                         uint32_t expiration,
                                                         uint64_t *result,
                                                         uint64_t *result_cas) {
    protocol_binary_response_status rval= PROTOCOL_BINARY_RESPONSE_SUCCESS;
    uint64_t val= initial;
    item_t *item;

    (void)cookie;
    write_lock(&storage_lock);

    item = get_item(key, keylen);

    if (item != NULL) {
        if (delta > *(uint64_t*)item->data)
            val= 0;
        else
            val= *(uint64_t*)item->data - delta;

        expiration= (uint32_t)item->exp;
        release_item(item);
        delete_item(key, keylen);
    }

    item= create_item(key, keylen, NULL, sizeof(initial), 0, (time_t)expiration);
    if (item == 0) {
        rval= PROTOCOL_BINARY_RESPONSE_ENOMEM;
    } else {
        memcpy(item->data, &val, sizeof(val));
        put_item(item);
        *result= val;
        *result_cas= item->cas;
        release_item(item);
    }

    write_unlock(&storage_lock);
    return rval;
}

static protocol_binary_response_status delete_handler(const void *cookie,
                                                      const void *key,
                                                      uint16_t keylen,
                                                      uint64_t cas) {
    protocol_binary_response_status rval= PROTOCOL_BINARY_RESPONSE_SUCCESS;

    (void)cookie;
    write_lock(&storage_lock);

    if (cas != 0) {
        item_t *item= get_item(key, keylen);
        if (item != NULL) {
            if (item->cas != cas) {
                release_item(item);
                write_unlock(&storage_lock);
                return PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
            }
            release_item(item);
        }
    }

    if (!delete_item(key, keylen)) {
        rval= PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
    }

    write_unlock(&storage_lock);
    return rval;
}


static protocol_binary_response_status flush_handler(const void *cookie,
                                                     uint32_t when) {

    (void)cookie;
    write_lock(&storage_lock);
    flush(when);
    write_unlock(&storage_lock);
    return PROTOCOL_BINARY_RESPONSE_SUCCESS;
}

static protocol_binary_response_status get_handler(const void *cookie,
                                                   const void *key,
                                                   uint16_t keylen,
                                                   memcached_binary_protocol_get_response_handler response_handler) {
    protocol_binary_response_status rc;
    item_t *item;

    read_lock(&storage_lock);
    item = get_item(key, keylen);

    if (item == NULL) {
        read_unlock(&storage_lock);
        return PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
    }

    rc= response_handler(cookie, key, (uint16_t)keylen,
                         item->data, (uint32_t)item->size, item->flags,
                         item->cas);
    release_item(item);

    read_unlock(&storage_lock);
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
    protocol_binary_response_status rval= PROTOCOL_BINARY_RESPONSE_SUCCESS;
    uint64_t val= initial;
    item_t *item;
    
    (void)cookie;
    write_lock(&storage_lock);

    item = get_item(key, keylen);

    if (item != NULL) {
        val= (*(uint64_t*)item->data) + delta;
        expiration= (uint32_t)item->exp;
        release_item(item);
        delete_item(key, keylen);
    }

    item= create_item(key, keylen, NULL, sizeof(initial), 0, (time_t)expiration);
    if (item == NULL) {
        rval= PROTOCOL_BINARY_RESPONSE_ENOMEM;
    } else {
        char buffer[1024] = {0}; // FIXME: does this need to be so big ~ajc
        memcpy(buffer, key, keylen);
        memcpy(item->data, &val, sizeof(val));
        put_item(item);
        *result= val;
        *result_cas= item->cas;
        release_item(item);
    }

    write_unlock(&storage_lock);

    return rval;
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
    protocol_binary_response_status rval= PROTOCOL_BINARY_RESPONSE_SUCCESS;

    item_t *nitem= NULL;
    item_t *item;

    (void)cookie;
    write_lock(&storage_lock);

    item = get_item(key, keylen);

    if (item == NULL) {
        rval= PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
    } else if (cas != 0 && cas != item->cas) {
        rval= PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
    } else if ((nitem= create_item(key, keylen, NULL, item->size + vallen,
                                   item->flags, item->exp)) == NULL) {
        rval= PROTOCOL_BINARY_RESPONSE_ENOMEM;
    } else {
        memcpy(nitem->data, val, vallen);
        memcpy(((char*)(nitem->data)) + vallen, item->data, item->size);
        release_item(item);
        item= NULL;
        delete_item(key, keylen);
        put_item(nitem);
        *result_cas= nitem->cas;
    }

    if (item)
        release_item(item);

    if (nitem)
        release_item(nitem);

    write_unlock(&storage_lock);
    return rval;
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
    protocol_binary_response_status rval= PROTOCOL_BINARY_RESPONSE_SUCCESS;
    item_t* item; 

    write_lock(&storage_lock);
    (void)cookie;

    item= get_item(key, keylen);

    if (item == NULL) {
        rval= PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
    } else if (cas == 0 || cas == item->cas) {
        release_item(item);
        delete_item(key, keylen);
        item= create_item(key, keylen, data, datalen, flags, (time_t)exptime);
        if (item == 0) {
            rval= PROTOCOL_BINARY_RESPONSE_ENOMEM;
        } else {
            put_item(item);
            *result_cas= item->cas;
            release_item(item);
        }
    } else {
        rval= PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
        release_item(item);
    }

    write_unlock(&storage_lock);
    return rval;
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
    protocol_binary_response_status rval= PROTOCOL_BINARY_RESPONSE_SUCCESS;
    item_t* item;

    (void)cookie;
    write_lock(&storage_lock);

    if (cas != 0) {
        item_t* item= get_item(key, keylen);
        if (item != NULL && cas != item->cas) {
            /* Invalid CAS value */
            release_item(item);
            write_unlock(&storage_lock);
            return PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
        }
    }

    delete_item(key, keylen);
    item= create_item(key, keylen, data, datalen, flags, (time_t)exptime);
    if (item == 0) {
        rval= PROTOCOL_BINARY_RESPONSE_ENOMEM;
    } else {
        put_item(item);
        *result_cas= item->cas;
        release_item(item);
    }

    write_unlock(&storage_lock);
    return rval;
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
