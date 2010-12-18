kmemcached - a Linux Kernel Memcached
================
by [Anthony Chivetta](http://chivetta.org)

Background
------------

[Memcached](http://memcached.org "Memcached") is an in-memory key/value cache
service used by nearly all large websites as a lookaside cache to scale their
authoritative database.  It supports simple operations such as `GET`, `SET`,
`PUT`, `INCREMENT`, etc. on a in-memory hash table of key/value pairs.
Servers typically operate as a LRU cache with additional per-item expire times.

Memcached's use case in web applications means that it is highly
latency-sensitive.  Further, the dumb nature of the cache means that very little
of the time spent servicing a request is spent doing business processing.  These
two factors make memcached a prime candidate to move into the kernel as a means
of removing sources of latency and experimenting with different techniques for
servicing requests.

Usually, in-kernel servers are considered a Bad Thing(TM).  On the security
front an in-kernel server makes any vulnerabilities much more dangerous as they
effect the kernel directly and have full access to the system.
However, memcached was never designed to be exposed to untrusted users and so
this issue is minimized by the network security already in place.  Stability and
complexity of kernel code are also issues -- writing robust kernel code is
generally considered more difficult than writing equivalent user-space code and
bugs can have system-wide effects.  Fortunately, memcached has a simple protocol
and application logic to make bug-free implementation easier.  Finally, an
in-kernel server is typically much harder to setup and maintain than a
user-space server.  In the case of memcached, users are typically seasoned
system administrators who are likely to already be experienced in compiling
their own kernels.

The Project
-----------

As an experiment, we've ported memcached to the Linux kernel as a dynamically
loadable module that exists outside of the Linux kernel source tree.  The
current code is highly experimental and may be used for further development into
a production system or experimental endeavors.  It is the hope that with further
development it can be demonstrated that in-kernel servers can achieve
lower-latency in simple applications with minimal complexity increase.

Structure
---------

There are four main components:

Core: The core of the module is contained in `main.c`.  This is responsible for
startup and teardown.  It interfaces with the kernel's networking layer and
provides dispatch for client work.  You should start here to get a feel for the
code.  All code in this file is original to the project.

libmemcachedprotocol: The folder `libmp/` contains the library used to parse
incoming memcached requests.  It was taken from the 
[libmemcached](libmemcached.org "libMemcached") library and modified to run in
the kernel.  The file `protocol_handler.c` contains the default_send and
default_recv functions which write to a kernel socket and may be of interest.

Memcached Logic: The file `interface.c` contains the implementation of the
memcached business logic.  This is also pulled from the libmemcached source.

Storage Engine: The file `storage.c` contains a hash table implementation taken
from the memcached source code. 

Current Limitations
-------------------

This code is not yet anywhere near production ready, however it does pass the
[memcapable](http://libmemcached.org/Memcapable.html "Memcapable") binary tests.
Most of the significant limitations are documented by comments containing the
string "TODO" (try `make todo` to see them).  Some of the most significant
include a lock of support for:

 - Multi-threading
 - Support for hash table expansion
 - Freeing disconnected client structures
 - Eviction or expiration of items

Any help to fix these limitations would be appreciated.

Possible Future Investigations
------------------------------

Some avenues for future development include

 - Paging aware storage structures
 - Tighter integration with sockets, scheduler or VM system.

Licencing
---------

Some code has been adopted from the memcached and libmemcache projects.  All
code is licenced under the BSD license (see the `LICENSE` file).  Additionally,
all code is dual licenced under the GNU General Public License v2.
