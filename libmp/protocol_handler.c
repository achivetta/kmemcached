/* -*- Mode: C; tab-width: 2; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "protocol_handler.h"
#include "common.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/delay.h>
#include <asm-generic/errno.h>

/*
** **********************************************************************
** INTERNAL INTERFACE
** **********************************************************************
*/

/**
 * The default function to receive data from the client. This function
 * just wraps the recv function to receive from a socket.
 * See man -s3socket recv for more information.
 *
 * @param cookie cookie indentifying a client, not used
 * @param sock socket to read from
 * @param buf the destination buffer
 * @param nbytes the number of bytes to read
 * @return the number of bytes transferred of -1 upon error
 */
static ssize_t default_recv(const void *cookie,
                            memcached_socket_t sock,
                            void *buf,
                            size_t len)
{
  struct msghdr msg;
  struct iovec iov;
  mm_segment_t oldfs;
  int size = 0;

  (void)cookie;

  /* if there is no backing sock... */
  if (sock->sk==NULL) return 0;

  iov.iov_base = buf;
  iov.iov_len = len;

  msg.msg_flags = MSG_DONTWAIT;
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;

  oldfs = get_fs();
  set_fs(KERNEL_DS);
  size = sock_recvmsg(sock,&msg,len,msg.msg_flags);
  set_fs(oldfs);

  return size;
}

// FIXME: This can be more efficint, look at net/ceph/messenger.c
/**
 * The default function to send data to the server. This function
 * just wraps the send function to send through a socket.
 * See man -s3socket send for more information.
 *
 * @param cookie cookie indentifying a client, not used
 * @param sock socket to send to
 * @param buf the source buffer
 * @param nbytes the number of bytes to send
 * @return the number of bytes transferred of -1 upon error
 */
static ssize_t default_send(const void *cookie,
                            memcached_socket_t sock,
                            const void *buf,
                            size_t len)
{
  struct msghdr msg;
  struct iovec iov;
  mm_segment_t oldfs;
  int size = 0;

  (void)cookie;

  /* if there is no backing sock... 
   * TODO: when would this be the case? */
  if (sock->sk==NULL)
      return 0;

  /* Construct our scatter/gather list */
  iov.iov_base = (void*)buf;
  iov.iov_len = len;

  msg.msg_flags = MSG_DONTWAIT;
  msg.msg_name = NULL;
  msg.msg_namelen  = 0;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  /* TODO: what does this do? */
  // http://mail.nl.linux.org/kernelnewbies/2005-12/msg00282.html
  oldfs = get_fs();
  set_fs(KERNEL_DS);
  size = sock_sendmsg(sock,&msg,len);
  set_fs(oldfs);

  return size;
}

/**
 * Try to drain the output buffers without blocking
 *
 * @param client the client to drain
 * @return false if an error occured (connection should be shut down)
 *         true otherwise (please note that there may be more data to
 *              left in the buffer to send)
 */
static bool drain_output(struct memcached_protocol_client_st *client)
{
  ssize_t len;

  /* Do we have pending data to send? */
  while (client->output != NULL)
  {
    if (client->sock == NULL) {
        return false;
    }
    len= client->root->send(client,
                            client->sock,
                            client->output->data + client->output->offset,
                            client->output->nbytes - client->output->offset);
    if (len < 0)
    {
      if (len == -EWOULDBLOCK)
      {
        return true;
      }
      printk(KERN_ERR "libmp:drain_output send returned error %lu; assuming connection closed\n", -len);
      return false;
    }
    else
    {
      client->output->offset += (size_t)len;
      if (client->output->offset == client->output->nbytes)
      {
        /* This was the complete buffer */
        struct chunk_st *old= client->output;
        client->output= client->output->next;
        if (client->output == NULL)
        {
          client->output_tail= NULL;
        }
        cache_free(client->root->buffer_cache, old);
      }
    }
  }

  return true;
}

/**
 * Allocate an output buffer and chain it into the output list
 *
 * @param client the client that needs the buffer
 * @return pointer to the new chunk if the allocation succeeds, NULL otherwise
 */
static struct chunk_st *allocate_output_chunk(struct memcached_protocol_client_st *client)
{
  struct chunk_st *ret= cache_alloc(client->root->buffer_cache);

  if (ret == NULL)
  {
    return NULL;
  }

  ret->offset= ret->nbytes= 0;
  ret->next= NULL;
  ret->size= CHUNK_BUFFERSIZE;
  ret->data= (void*)(ret + 1);
  if (client->output == NULL)
  {
    client->output= client->output_tail= ret;
  }
  else
  {
    client->output_tail->next= ret;
    client->output_tail= ret;
  }

  return ret;
}

/**
 * Spool data into the send-buffer for a client.
 *
 * @param client the client to spool the data for
 * @param data the data to spool
 * @param length the number of bytes of data to spool
 * @return PROTOCOL_BINARY_RESPONSE_SUCCESS if success,
 *         PROTOCOL_BINARY_RESPONSE_ENOMEM if we failed to allocate memory
 */
static protocol_binary_response_status spool_output(struct memcached_protocol_client_st *client,
                                                    const void *data,
                                                    size_t length)
{
  size_t offset= 0;
  struct chunk_st *chunk= client->output;

  if (client->mute)
  {
    return PROTOCOL_BINARY_RESPONSE_SUCCESS;
  }

  while (offset < length)
  {
    size_t bulk= length - offset;

    if (chunk == NULL || (chunk->size - chunk->nbytes) == 0)
    {
      if ((chunk= allocate_output_chunk(client)) == NULL)
      {
        return PROTOCOL_BINARY_RESPONSE_ENOMEM;
      }
    }

    if (bulk > chunk->size - chunk->nbytes)
    {
      bulk= chunk->size - chunk->nbytes;
    }

    memcpy(chunk->data + chunk->nbytes, data, bulk);
    chunk->nbytes += bulk;
    offset += bulk;
  }

  return PROTOCOL_BINARY_RESPONSE_SUCCESS;
}

/**
 * Try to determine the protocol used on this connection.
 * If the first byte contains the magic byte PROTOCOL_BINARY_REQ we should
 * be using the binary protocol on the connection. I implemented the support
 * for the ASCII protocol by wrapping into the simple interface (aka v1),
 * so the implementors needs to provide an implementation of that interface
 *
 */
static memcached_protocol_event_t determine_protocol(struct memcached_protocol_client_st *client, ssize_t *length, void **endptr)
{
  if (*client->root->input_buffer == (uint8_t)PROTOCOL_BINARY_REQ)
  {
    client->work= memcached_binary_protocol_process_data;
  }
  else if (client->root->callback->interface_version == 1)
  {
    /*
     * The ASCII protocol can only be used if the implementors provide
     * an implementation for the version 1 of the interface..
     *
     * @todo I should allow the implementors to provide an implementation
     *       for version 0 and 1 at the same time and set the preferred
     *       interface to use...
     */
    client->work= memcached_ascii_protocol_process_data;
  }
  else
  {
    /* Let's just output a warning the way it is supposed to look like
     * in the ASCII protocol...
     */
    const char *err= "CLIENT_ERROR: Unsupported protocol\r\n";
    client->root->spool(client, err, strlen(err));
    client->root->drain(client);
    printk(KERN_INFO "libmp: Client speaks an unsupported protocol.\n");
    return MEMCACHED_PROTOCOL_ERROR_EVENT; /* Unsupported protocol */
  }

  return client->work(client, length, endptr);
}

/*
** **********************************************************************
** * PUBLIC INTERFACE
** * See protocol_handler.h for function description
** **********************************************************************
*/
struct memcached_protocol_st *memcached_protocol_create_instance(void)
{
  struct memcached_protocol_st *ret= kcalloc(1, sizeof(*ret), GFP_KERNEL);
  if (ret != NULL)
  {
    ret->recv= default_recv;
    ret->send= default_send;
    ret->drain= drain_output;
    ret->spool= spool_output;
    ret->input_buffer_size= 1 * 1024 * 1024;
    ret->input_buffer= kmalloc(ret->input_buffer_size, GFP_KERNEL);
    if (ret->input_buffer == NULL)
    {
      kfree(ret);
      ret= NULL;
      return NULL;
    }

    ret->buffer_cache= cache_create("protocol_handler",
                                     CHUNK_BUFFERSIZE + sizeof(struct chunk_st),
                                     0, NULL, NULL);
    if (ret->buffer_cache == NULL)
    {
      kfree(ret->input_buffer);
      kfree(ret);
    }
  }

  return ret;
}

void memcached_protocol_destroy_instance(struct memcached_protocol_st *instance)
{
  cache_destroy(instance->buffer_cache);
  kfree(instance->input_buffer);
  kfree(instance);
}

/** Our implementation of the memcached protocol callbacks */
extern memcached_binary_protocol_callback_st interface_impl;

struct memcached_protocol_client_st *memcached_protocol_create_client(memcached_socket_t sock)
{
  struct memcached_protocol_client_st *ret= kcalloc(1, sizeof(*ret), GFP_KERNEL);
  if (ret != NULL)
  {
    ret->root = memcached_protocol_create_instance();
    if (ret->root == NULL) {
      kfree(ret);
      return NULL;
    }
    memcached_binary_protocol_set_callbacks(ret->root, &interface_impl);
    memcached_binary_protocol_set_pedantic(ret->root, false);
    ret->sock= sock;
    ret->work= determine_protocol;
  }
  return ret;
}

void memcached_protocol_client_destroy(struct memcached_protocol_client_st *client)
{
  kfree(client->root);
  kfree(client);
}

memcached_protocol_event_t memcached_protocol_client_work(struct memcached_protocol_client_st *client)
{
  /* Try to send data and read from the socket */
  memcached_protocol_event_t ret;

  ssize_t len= client->root->recv(client,
                                  client->sock,
                                  client->root->input_buffer + client->input_buffer_offset,
                                  client->root->input_buffer_size - client->input_buffer_offset);

  if (len > 0)
  {
    void *endptr;
    memcached_protocol_event_t events;

    len += client->input_buffer_offset;
    events = client->work(client, &len, &endptr);
    if (events == MEMCACHED_PROTOCOL_ERROR_EVENT)
    {
      return MEMCACHED_PROTOCOL_ERROR_EVENT;
    }
    // save the data for later.
    client->input_buffer_offset = len;
    memmove(client->root->input_buffer, endptr, (size_t)len);
  }
  else if (len < 0)
  {
    if (len != -EWOULDBLOCK)
    {
      printk(KERN_ERR "libmp: clien_work recv returned error %lu; assuming connection closed\n", -len);
      client->error= -len;
      /* mark this client as terminated! */
      return MEMCACHED_PROTOCOL_ERROR_EVENT;
    }
  }

  if (!drain_output(client))
  {
    printk(KERN_INFO "libmp: clien_work error draining output\n");
    return MEMCACHED_PROTOCOL_ERROR_EVENT;
  }

  ret = MEMCACHED_PROTOCOL_READ_EVENT;
  if (client->output)
    ret |= MEMCACHED_PROTOCOL_WRITE_EVENT;

  return ret;
}
/* vim: set ts=2 sts=2 sw=2 expandtab : */
