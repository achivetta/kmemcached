/* -*- Mode: C; tab-width: 2; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef LIBMEMCACHED_PROTOCOL_ASCII_HANDLER_H
#define LIBMEMCACHED_PROTOCOL_ASCII_HANDLER_H

memcached_protocol_event_t memcached_ascii_protocol_process_data(memcached_protocol_client_st *client, ssize_t *length, void **endptr);

#endif
