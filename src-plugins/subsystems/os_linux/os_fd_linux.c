
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

#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "common/common_types.h"
#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_clock.h"

#include "subsystems/os_fd.h"

/* Defintions */
#define LOG_OS_SOCKET _oonf_os_fd_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_CLOCK_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_os_fd_subsystem = {
  .name = OONF_OS_FD_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_os_fd_subsystem);

/**
 * Initialize os_net subsystem
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  return 0;
}

/**
 * Cleanup os_net subsystem
 */
static void
_cleanup(void) {
}

/**
 * wait for a network event on multiple sockets
 * @param sel socket selector set
 * @return number of events that happened, 0 if a timeout happened
 */
int
os_fd_linux_event_wait(struct os_fd_select *sel) {
  struct os_fd *sock;
  uint64_t maxdelay;
  int i;

  maxdelay = oonf_clock_get_relative(sel->deadline);
  if (maxdelay > INT32_MAX) {
    maxdelay = INT32_MAX;
  }

  sel->_event_count = epoll_wait(sel->_epoll_fd, sel->_events,
      ARRAYSIZE(sel->_events), maxdelay);

  OONF_DEBUG(LOG_OS_SOCKET, "epoll_wait(maxdelay = %"PRIu64"): %d",
      maxdelay, sel->_event_count);

  for (i=0; i<sel->_event_count; i++) {
    sock = os_fd_event_get(sel, i);
    sock->received_events = sel->_events[i].events;

    OONF_DEBUG(LOG_OS_SOCKET, "event %d: %x", i, sock->received_events);
  }
  return sel->_event_count;
}

/**
 * Move the wanted events of a socket into a selector set
 * @param sel socket selector set
 * @param sock os socket
 * @return -1 if an error happened, 0 otherwise
 */
int
os_fd_linux_event_socket_modify(struct os_fd_select *sel,
    struct os_fd *sock) {
  struct epoll_event event;

  memset(&event,0,sizeof(event));

  event.events = sock->wanted_events;
  event.data.ptr = sock;

  OONF_DEBUG(LOG_OS_SOCKET, "Modify socket %d to events 0x%x",
      sock->fd, sock->wanted_events);
  return epoll_ctl(sel->_epoll_fd, EPOLL_CTL_MOD, sock->fd, &event);
}

/**
 * Raw IP sockets sometimes deliver the whole IP header instead of just
 * the content. This function skips the IP header and modifies the length
 * of the buffer.
 * @param ptr pointer to the beginning of the buffer
 * @param len pointer to length of buffer
 * @param af_type address family of data in buffer
 * @return pointer to transport layer data
 */
uint8_t *
os_fd_linux_skip_rawsocket_prefix(uint8_t *ptr, ssize_t *len, int af_type) {
  int header_size;

  if (af_type != AF_INET) {
    return ptr;
  }

  /* skip IPv4 header */
  header_size = (ptr[0] & 0x0f) << 2;

  *len -= header_size;
  return ptr + header_size;
}
