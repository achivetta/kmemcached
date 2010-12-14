/* LibMemcached
 * Copyright (C) 2006-2009 Brian Aker
 * All rights reserved.
 *
 * Use and distribution licensed under the BSD license.  See
 * the COPYING file in the parent directory for full text.
 *
 * Summary:
 *
 */

#ifndef __LIBMEMCACHED_BYTEORDER_H__
#define __LIBMEMCACHED_BYTEORDER_H__

// Why do we need this?
//#include "memcached.h"

#include <linux/types.h>

#define ntohll(a) memcached_ntohll(a)
#define htonll(a) memcached_htonll(a)

uint64_t memcached_ntohll(uint64_t);
uint64_t memcached_htonll(uint64_t);

#endif /*__LIBMEMCACHED_BYTEORDER_H__ */
