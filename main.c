/* Kernel Memcached
 * Anthony Chivetta <anthony@chivetta.org>
 *
 * Please see LICENSE for copyright information.  This file is origional to the
 * kmemcached project.  Some inspiration for this file was taken from
 * http://kernelnewbies.org/Simple_UDP_Server and linux's net/ceph/messenger.c.
 *
 * This file is the main routene for kmemcached.  The initialization code
 * creates a listening socket, initializes the protocol parser and storage
 * enginge, and spins off a kthread which is pulling work from a kthread_worker
 * workqueue.  This workqueue design is necessairy as socket callbacks are
 * called in interrupt context and so should be quick and may not sleep.  The
 * listening socket's data_ready callback is set to callback_listen() which will
 * queue up listen_work() to be executed whenever a new connection is received.
 * listen_work() will accept the connection, create and initialize the
 * per-client data structures and set the callbacks on the socket.
 * callback_{write_space,data_ready,state_change}() handle events on the client
 * sockets adding them to the worqueue as necessairy.
 *
 * A LOT of work still needs to be done here.  Please see the TODOs littered
 * throughout the file for an idea.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/smp_lock.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/delay.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#include "libmp/protocol_handler.h"
#include "libmp/common.h"
#include "storage.h"

/** The port we listen on.
 *
 * TODO: This should be configurable as a parameter passed to the module at load
 * time.  Currently, it must be set here at compile time.
 */
#define DEFAULT_PORT 11212

/** The module name.
 *
 * TODO: This should be moved to a global header somewhere to be consumed by
 * printk() in other files.
 */
#define MODULE_NAME "kmemcached"

/** The number of clients to allow in the accept() queue.
 * TODO: This should also be an option set by a module argument.
 */
#define SOCKET_BACKLOG 100

/* Client States */

/** Client is active.
 *
 * This flag is set when a client is initialized and unset when the client is
 * due to be free()d.  It is used to ignore surpurflious callbacks on dieing
 * clients.
 */
#define STATE_ACTIVE 1 

/** More data to be written.
 *
 * This flag indicates that there is more data in the send queue for the client.
 * This allows us to ignore write_space callbacks when no write is needed.
 */
#define STATE_WRITING 2 

/** This client should be closed.
 *
 * This flag indicates that due to either client hangup or error condition the
 * client's connection should be closed.
 */
#define STATE_CLOSE 3

/** Our implementation of the memcached protocol callbacks */
extern memcached_binary_protocol_callback_st interface_impl;

/** Client data structure. */
typedef struct client_t{
    /** Pointer to socket for this client's connection. */
    struct socket *sock;

    /** Pointer to memcached protocol struct for this client. */
    struct memcached_protocol_client_st *libmp;
    
    /** The work object associated with this client.  This is added to the
     * workqueue when there is work to be done by this client. */
    struct work_struct work;

    /** For clients list. */
    struct list_head list;

    /** One or more of the STATE_* macros above. */
    long unsigned int state;
} client_t;

/** List of all clients.
 *
 * Used to free the clients when module is unloaded.
 */
static LIST_HEAD(clients);

static void listen_work(struct work_struct *work);
static void client_work(struct work_struct *work);
static void close_connection(client_t *client);

/** Workqueue for working on connections or the listening socket*/
struct workqueue_struct *workqueue;
/** Work for processing an incoming connection */
DECLARE_WORK(listen_job,listen_work);

/** Listening Socket
 *
 * TODO: This is our listening socket.  Ideally, this shouldn't just be a single
 * socket.  In the future, we should adapt this to support multiple listening
 * sockets.
 */
struct socket *listen_socket;

/** libmemcachedprotocol handle */
struct memcached_protocol_st *protocol_handle;

/** Equeue a client on the workqueue */
static void queue_client(client_t *client){
    queue_work(workqueue, &(client->work));
}

/** Callback for new data on a listening socket */
static void callback_listen(struct sock *sk, int bytes){
    if (sk->sk_state != TCP_LISTEN)
        return;

    queue_work(workqueue, &listen_job);
}

/** Callback for availability of write space on a socket. 
 *
 * TODO: Maybe, we should be using our own buffers and supplying them to the
 * socket.  I think the ceph/messanger.c has a good example of this.  When we do
 * this, we should look at executing 
 *     clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
 * in this callback.
 */
static void callback_write_space(struct sock *sk){
    client_t *client = (client_t*) sk->sk_user_data;

    if (!test_bit(STATE_ACTIVE, &client->state))
        return;

    if (test_bit(WRITE, &client->state))
        queue_client(client);
}

/** Callback for availability of data to read from a socket. */
static void callback_data_ready(struct sock *sk, int bytes){
    client_t *client = (client_t*) sk->sk_user_data;

    if (!test_bit(STATE_ACTIVE, &client->state))
        return;

    if (sk->sk_state != TCP_CLOSE_WAIT)
        queue_client(client);
}

/** Callback to indicate a state change on a socket, typically a disconnect. */
static void callback_state_change(struct sock *sk){
    client_t *client = (client_t*) sk->sk_user_data;

    if (!test_bit(STATE_ACTIVE, &client->state))
        return;

    switch(sk->sk_state){
        case TCP_CLOSE:
        case TCP_CLOSE_WAIT:
            if (test_and_set_bit(STATE_CLOSE, &client->state) == 0)
                queue_client(client);
            break;
    }
}

/** Work to handle an incoming connection on a listening socket */
static void listen_work(struct work_struct *work){
    (void)work;

    while (1){
        int err = 0;
        client_t *client = NULL;
        struct socket *new_sock = NULL;

        if ((err = kernel_accept(listen_socket, &new_sock, O_NONBLOCK)) < 0){
            if (err != -EAGAIN)
                printk(KERN_INFO MODULE_NAME": Could not accept incoming connection, error = %d\n",-err);
            break;
        } 

        if (!(client = kmalloc(sizeof(client_t), GFP_KERNEL))){
            printk(KERN_INFO MODULE_NAME": Unable to allocate space for new client_t.\n");
            kernel_sock_shutdown(new_sock, SHUT_RDWR);
            sock_release(new_sock);
            break;
        }

        client->sock = new_sock;
        client->libmp = NULL;
        INIT_WORK(&client->work, client_work);
        INIT_LIST_HEAD(&client->list);
        client->state = 0;
        set_bit(STATE_ACTIVE, &client->state);

        client->libmp = memcached_protocol_create_client(protocol_handle, client->sock);
        if (client->libmp == NULL){
            printk(KERN_INFO MODULE_NAME": Could not allocate memory for memcached_protocol_client_st.");
            sock_release(client->sock);
            kfree(client);
            break;
        }

        list_add(&client->list, &clients);

        client->sock->sk->sk_user_data = client;
        client->sock->sk->sk_data_ready = callback_data_ready;
        client->sock->sk->sk_write_space = callback_write_space;
        client->sock->sk->sk_state_change = callback_state_change;

        /* TODO: Other things we should really do (see kernel_sock_ioctl)
         *   * Set SO_SNDBUF and SO_RCVBUF, if we don't supply our own
         *     look at net/sunrpc/svnsock.c:svn_sock_setbufsize for this
         *   * Disable Nagle algorithm (sk->nonagle |= TCP_NAGLE_OFF
         *   * Other socket magic?
         */

        queue_client(client);

        printk(KERN_INFO MODULE_NAME": Accepted incoming connection.\n");
        /* TODO: output the IP of the connecting host, see __svc_print_addr */
    }
}

/** Work on a client connection */
static void client_work(struct work_struct *work){
    memcached_protocol_event_t events;
    client_t *client = container_of(work, client_t, work);

    if (!client->sock) // FIXME: when would this be true? error handleing?
        return;  

    /* If we are working on a non-active client, something went very wrong */
    BUG_ON(!test_bit(STATE_ACTIVE, &client->state));

    /* Do some work! */
    events = memcached_protocol_client_work(client->libmp);

    /* The goal here is for the buffers to be emptied before we shutdown the
     * socket */

    if (events & MEMCACHED_PROTOCOL_ERROR_EVENT)
        set_bit(STATE_CLOSE, &client->state);

    if (events & MEMCACHED_PROTOCOL_WRITE_EVENT){
        set_bit(STATE_WRITING, &client->state);
    } else {
        clear_bit(STATE_WRITING, &client->state);
        if (test_bit(STATE_CLOSE, &client->state) == 1)
            close_connection(client);
    }
}

/** Open an listening socket */
static int open_listen_socket(void){
    int err;
    struct sockaddr_in listen_address;

    /* create a socket */
    if ( (err = sock_create_kern(AF_INET, SOCK_STREAM , IPPROTO_TCP, &listen_socket)) < 0)
    {
        printk(KERN_INFO MODULE_NAME": Could not create a TCP socket, error = %d\n", -err);
        return -1;
    }

    memset(&listen_address, 0, sizeof(struct sockaddr_in));
    listen_address.sin_family      = AF_INET;
    listen_address.sin_addr.s_addr      = htonl(INADDR_ANY);
    listen_address.sin_port      = htons(DEFAULT_PORT);

    if ( (err = kernel_bind(listen_socket, (struct sockaddr *)&listen_address, sizeof(struct sockaddr_in) ) ) < 0) 
    {
        printk(KERN_INFO MODULE_NAME": Could not bind or connect to socket, error = %d\n", -err);
        return -2;
    }

    if ( ( err = kernel_listen(listen_socket, SOCKET_BACKLOG)) < 0){
        printk(KERN_INFO MODULE_NAME": Could not listen on socket, error = %d\n", -err);
        return -2;
    }

    listen_socket->sk->sk_data_ready = callback_listen;

    printk(KERN_INFO MODULE_NAME": Started, listening on port %d.\n", DEFAULT_PORT);
    return 0;
}

/** Close a listening socket 
 *
 * TODO We should ensure that this is all which is needed to listen on that
 * socket again in the future.  Previous attempts to use that listening port
 * again after unloading the module have resulted in errors.
 */
static void close_listen_socket(void){
    kernel_sock_shutdown(listen_socket, SHUT_RDWR);
    sock_release(listen_socket);
    listen_socket = NULL;
}

/** Close a client 
 *
 * FIXME: "It is permissible to free the struct work_struct from inside the
 * function that is called from it." (workqueue.c)
 */ 
static void close_connection(client_t *client){
    printk(KERN_INFO MODULE_NAME": Closing connection.\n");

    clear_bit(STATE_ACTIVE, &client->state);
    kernel_sock_shutdown(client->sock, SHUT_RDWR);
    sock_release(client->sock);
    client->sock = NULL;
    clear_bit(STATE_CLOSE, &client->state);

    memcached_protocol_client_destroy(client->libmp);
    list_del(&client->list);
    // FIXME see TODO above. 
    //kfree(client);  
}

/** Load the module */
int __init kmemcached_init(void)
{
    int ret;
    
    /* open listening socket */
    if ((ret = open_listen_socket()) < 0){
        if (ret == -2) close_listen_socket();
        return -ENXIO; // FIXME use better error code
    }

    /* setup protocol library */
    if ((protocol_handle = memcached_protocol_create_instance()) == NULL){
        printk(KERN_INFO MODULE_NAME": unable to allocate protocol handle\n");
        return -ENOMEM;
    }
    memcached_binary_protocol_set_callbacks(protocol_handle,&interface_impl);
    memcached_binary_protocol_set_pedantic(protocol_handle, false);

    if (initialize_storage() == false){
        printk(KERN_INFO MODULE_NAME": unable to initialize storage engine\n");
        return -ENOMEM;
        // FIXME leak in error condition
    }

    /* start kernel thread */
#ifdef alloc_workqueue
    workqueue = alloc_workqueue(MODULE_NAME, WQ_NON_REENTRANT | WQ_FREEZEABLE, 0);
#else
    workqueue = create_freezeable_workqueue(MODULE_NAME);
#endif

    return 0;
}

/** Unload the module 
 *
 * TODO This is currently a little clunky.  In particular, we should be really
 * be ensureing that each client closes cleanly including flushing write
 * buffers.  Likely, this involves flushing each client off the workqueue
 * individually as we close their connections.
 */
void __exit kmemcached_exit(void){
    struct list_head *p;
    close_listen_socket();

    // FIXME do this client-by-client, see above
    flush_workqueue(workqueue);

    while (!list_empty(&clients)) {
        client_t *client = container_of(clients.next, client_t, list);
        close_connection(client);
    }

    destroy_workqueue(workqueue);

    shutdown_storage();

    if (protocol_handle != NULL){
        memcached_protocol_destroy_instance(protocol_handle);
        protocol_handle = NULL;
    }

    if (listen_socket != NULL) {
        sock_release(listen_socket);
        listen_socket = NULL;
    }

    rcu_barrier();
    printk(KERN_INFO MODULE_NAME": module unloaded\n");
}

/* init and cleanup functions */
module_init(kmemcached_init);
module_exit(kmemcached_exit);

/* module information */
MODULE_DESCRIPTION("kmemcached");
MODULE_AUTHOR("Anthony Chivetta <anthony@chivetta.org>");
MODULE_LICENSE("Dual BSD/GPL");
