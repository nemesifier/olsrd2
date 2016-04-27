
/*
 * The olsr.org Optimized Link-State Routing daemon version 2 (olsrd2)
 * Copyright (c) 2004-2015, the olsr.org team - see HISTORY file
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */

/**
 * @file
 */

#include <errno.h>
#include <fcntl.h>

#include "common/common_types.h"
#include "common/netaddr.h"
#include "common/string.h"
#include "core/oonf_logging.h"
#include "subsystems/os_interface.h"

#include "subsystems/os_fd.h"
#include "subsystems/os_generic/os_fd_generic_configsocket.h"

/**
 * Configure a network socket
 * @param sock filedescriptor
 * @param bind_to ip/port to bind the socket to
 * @param recvbuf size of input buffer for socket
 * @param rawip true if socket is a raw ip socket, false otherwise
 * @param os_if pointer to interface to bind socket on,
 *   NULL if socket should not be bound to an interface
 * @param log_src logging source for error messages
 * @return -1 if an error happened, 0 otherwise
 */
int
os_fd_generic_configsocket(struct os_fd *sock,
    const union netaddr_socket *bind_to, size_t recvbuf,
    bool rawip, const struct os_interface *os_if, enum oonf_log_source log_src) {
  union netaddr_socket bindto;
  struct netaddr_str buf;
  socklen_t addrlen;
  int value;

  /* temporary copy bindto address */
  memcpy(&bindto, bind_to, sizeof(bindto));

  if (os_fd_set_nonblocking(sock)) {
    OONF_WARN(log_src, "Cannot make socket non-blocking %s: %s (%d)\n",
        netaddr_socket_to_string(&buf, &bindto), strerror(errno), errno);
    return -1;
  }

#if defined(IPV6_V6ONLY)
  if (!rawip && bind_to->std.sa_family == AF_INET6) {
    value = 1;
    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&value, sizeof(value)) < 0) {
        OONF_WARN(log_src, "Could not force socket to IPv6 only, continue: %s (%d)\n",
            strerror(errno), errno);
    }
  }
#endif

#if defined(SO_BINDTODEVICE)
  /* this is binding the socket, not a multicast address */
  if (os_if != NULL && setsockopt(sock->fd, SOL_SOCKET, SO_BINDTODEVICE,
      os_if->name, strlen(os_if->name) + 1) < 0) {
    OONF_WARN(log_src, "Cannot bind socket to interface %s: %s (%d)\n",
        os_if->name, strerror(errno), errno);
    return -1;
  }
#endif

#if defined(SO_REUSEADDR)
  /* allow to reuse address */
  value = 1;
  if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
    OONF_WARN(log_src, "Cannot reuse address for %s: %s (%d)\n",
        netaddr_socket_to_string(&buf, &bindto), strerror(errno), errno);
    return -1;
  }
#endif

#if defined(IP_RECVIF)
  if (os_if != NULL
      && setsockopt(sock, IPPROTO_IP, IP_RECVIF, &yes, sizeof(yes)) < 0) {
    OONF_WARN(log_src, "Cannot apply IP_RECVIF for %s: %s (%d)\n",
        netaddr_socket_to_string(&buf, &bindto), strerror(errno), errno);
    return -1;
  }
#endif

#if defined(SO_RCVBUF)
  if (recvbuf > 0) {
    while (recvbuf > 8192) {
      if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF,
          (void *)&recvbuf, sizeof(recvbuf)) == 0) {
        break;
      }

      recvbuf -= 1024;
    }

    if (recvbuf < 8192) {
      OONF_WARN(log_src, "Cannot setup receive buffer size for %s: %s (%d)\n",
          netaddr_socket_to_string(&buf, &bindto), strerror(errno), errno);
      return -1;
    }
  }
#endif

  /* add ipv6 interface scope if necessary */
  if (os_if != NULL && netaddr_socket_get_addressfamily(&bindto) == AF_INET6) {
    bindto.v6.sin6_scope_id = os_if->index;
  }

  /* bind the socket to the port number */
  addrlen = sizeof(bindto);
  if (bind(sock->fd, &bindto.std, addrlen) < 0) {
    OONF_WARN(log_src, "Cannot bind socket to address %s: %s (%d)\n",
        netaddr_socket_to_string(&buf, &bindto), strerror(errno), errno);

    return -1;
  }

  return 0;
}
