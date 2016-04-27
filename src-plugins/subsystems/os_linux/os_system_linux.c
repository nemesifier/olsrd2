
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

/* must be first because of a problem with linux/rtnetlink.h */
#include <sys/socket.h>

/* and now the rest of the includes */
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>

#include "common/common_types.h"
#include "common/string.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_socket.h"

#include "subsystems/os_system.h"
#include "subsystems/os_linux/os_system_linux.h"

#include <stdio.h>

#ifndef SOL_NETLINK
/*! socket netlink type */
#define SOL_NETLINK 270
#endif

/* Definitions */
#define LOG_OS_SYSTEM _oonf_os_system_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

static void _cb_handle_netlink_timeout(struct oonf_timer_instance *);
static void _netlink_handler(struct oonf_socket_entry *entry);
static void _enqueue_netlink_buffer(struct os_system_netlink *nl);
static void _handle_nl_err(struct os_system_netlink *, struct nlmsghdr *);
static void _flush_netlink_buffer(struct os_system_netlink *nl);

/* static buffers for receiving/sending a netlink message */
static struct sockaddr_nl _netlink_nladdr = {
  .nl_family = AF_NETLINK
};

static struct iovec _netlink_rcv_iov;
static struct msghdr _netlink_rcv_msg = {
  &_netlink_nladdr,
  sizeof(_netlink_nladdr),
  &_netlink_rcv_iov,
  1,
  NULL,
  0,
  0
};

static struct nlmsghdr _netlink_hdr_done = {
  .nlmsg_len = sizeof(struct nlmsghdr),
  .nlmsg_type = NLMSG_DONE
};

static struct iovec _netlink_send_iov[] = {
    { NULL, 0 },
    { &_netlink_hdr_done, sizeof(_netlink_hdr_done) },
};

static struct msghdr _netlink_send_msg = {
  &_netlink_nladdr,
  sizeof(_netlink_nladdr),
  _netlink_send_iov,
  ARRAYSIZE(_netlink_send_iov),
  NULL,
  0,
  0
};

/* netlink timeout handling */
static struct oonf_timer_class _netlink_timer= {
  .name = "netlink feedback timer",
  .callback = _cb_handle_netlink_timeout,
};

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_SOCKET_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_os_system_subsystem = {
  .name = OONF_OS_SYSTEM_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_os_system_subsystem);

static uint32_t _socket_count = 0;

/* tracking of used netlink sequence numbers */
static uint32_t _seq_used = 0;

/* global ioctl sockets for ipv4 and ipv6 */
static int _ioctl_v4, _ioctl_v6;

/* empty netlink buffer */
static struct os_system_netlink_buffer _dummy_buffer;

/**
 * Initialize os-specific subsystem
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  _ioctl_v4 = socket(AF_INET, SOCK_DGRAM, 0);
  if (_ioctl_v4 == -1) {
    OONF_WARN(LOG_OS_SYSTEM, "Cannot open ipv4 ioctl socket: %s (%d)",
        strerror(errno), errno);
    return -1;
  }

  _ioctl_v6 = socket(AF_INET6, SOCK_DGRAM, 0);
  if (_ioctl_v6 == -1) {
    OONF_INFO(LOG_OS_SYSTEM, "Node is not IPv6 capable");
  }

  oonf_timer_add(&_netlink_timer);
  return 0;
}

/**
 * Cleanup os-specific subsystem
 */
static void
_cleanup(void) {
  oonf_timer_remove(&_netlink_timer);
  close (_ioctl_v4);
  if (_ioctl_v6 != -1) {
    close (_ioctl_v6);
  }
}

/**
 * @return true if IPv6 is supported, false otherwise
 */
bool
os_system_linux_is_ipv6_supported(void) {
  return _ioctl_v6 != -1;
}

/**
 * @param v1 first version number part
 * @param v2 second version number part
 * @param v3 third version number part
 * @return true if linux kernel is at least a specific version
 */
bool
os_system_linux_is_minimal_kernel(int v1, int v2, int v3) {
  struct utsname uts;
  char *next;
  int first = 0, second = 0, third = 0;

  memset(&uts, 0, sizeof(uts));
  if (uname(&uts)) {
    OONF_WARN(LOG_OS_SYSTEM,
        "Error, could not read kernel version: %s (%d)\n",
        strerror(errno), errno);
    return false;
  }

  first = strtol(uts.release, &next, 10);
  /* check for linux 3.x */
  if (first > v1) {
    return true;
  }
  else if (first < v1) {
    return false;
  }

  if (*next != '.') {
    goto kernel_parse_error;
  }

  second = strtol(next+1, &next, 10);
  if (second > v2) {
    return true;
  }
  if (second < v2) {
    return false;
  }
  if (*next != '.') {
    goto kernel_parse_error;
  }

  third = strtol(next+1, NULL, 10);
  return third >= v3;

kernel_parse_error:
  OONF_WARN(LOG_OS_SYSTEM,
      "Error, cannot parse kernel version: %s\n", uts.release);
  return false;
}

/**
 * Returns an operation system socket for ioctl usage
 * @param af_type address family type
 * @return socket file descriptor, -1 if not surrported
 */
int
os_system_linux_linux_get_ioctl_fd(int af_type) {
  switch (af_type) {
    case AF_INET:
      return _ioctl_v4;
    case AF_INET6:
      return _ioctl_v6;
    default:
      return -1;
  }
}

/**
 * Open a new bidirectional netlink socket
 * @param nl pointer to initialized netlink socket handler
 * @param protocol protocol id (NETLINK_ROUTING for example)
 * @return -1 if an error happened, 0 otherwise
 */
int
os_system_linux_netlink_add(struct os_system_netlink *nl, int protocol) {
  struct sockaddr_nl addr;
  int recvbuf;
  int fd;

  fd = socket(PF_NETLINK, SOCK_RAW, protocol);
  if (fd < 0) {
    OONF_WARN(nl->used_by->logging, "Cannot open netlink socket '%s': %s (%d)",
        nl->name, strerror(errno), errno);
    goto os_add_netlink_fail;
  }

  if (os_fd_init(&nl->socket.fd, fd)) {
    OONF_WARN(nl->used_by->logging, "Could not initialize socket representation");
    goto os_add_netlink_fail;
  }
  if (abuf_init(&nl->out)) {
    OONF_WARN(nl->used_by->logging, "Not enough memory for"
        " netlink '%s'output buffer", nl->name);
    goto os_add_netlink_fail;
  }
  abuf_memcpy(&nl->out, &_dummy_buffer, sizeof(_dummy_buffer));

  nl->in = calloc(1, getpagesize());
  if (nl->in == NULL) {
    OONF_WARN(nl->used_by->logging, "Not enough memory for netlink '%s' input buffer",
        nl->name);
    goto os_add_netlink_fail;
  }
  nl->in_len = getpagesize();

  memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;

  addr.nl_pid = getpid() + (_socket_count << 22);
  _socket_count++;

#if defined(SO_RCVBUF)
  recvbuf = 65536*16;
  if (setsockopt(nl->socket.fd.fd, SOL_SOCKET, SO_RCVBUF,
      &recvbuf, sizeof(recvbuf))) {
    OONF_WARN(nl->used_by->logging, "Cannot setup receive buffer size for"
        " netlink socket '%s': %s (%d)\n", nl->name, strerror(errno), errno);
  }
#endif

  if (bind(nl->socket.fd.fd, (struct sockaddr *)&addr, sizeof(addr))<0) {
    OONF_WARN(nl->used_by->logging, "Could not bind netlink socket %s: %s (%d)",
        nl->name, strerror(errno), errno);
    goto os_add_netlink_fail;
  }

  nl->socket.process = _netlink_handler;
  oonf_socket_add(&nl->socket);
  oonf_socket_set_read(&nl->socket, true);

  nl->timeout.class = &_netlink_timer;

  list_init_head(&nl->buffered);
  return 0;

os_add_netlink_fail:
  if (fd != -1) {
    close(fd);
  }
  free (nl->in);
  abuf_free(&nl->out);
  return -1;
}

/**
 * Close a netlink socket handler
 * @param nl pointer to handler
 */
void
os_system_linux_netlink_remove(struct os_system_netlink *nl) {
  oonf_socket_remove(&nl->socket);

  os_fd_close(&nl->socket.fd);
  free (nl->in);
  abuf_free(&nl->out);
}

/**
 * add netlink message to buffer
 * @param nl netlink message
 */
static void
_enqueue_netlink_buffer(struct os_system_netlink *nl) {
  struct os_system_netlink_buffer *bufptr;

  /* initialize new buffer */
  bufptr = (struct os_system_netlink_buffer *)abuf_getptr(&nl->out);
  bufptr->total = abuf_getlen(&nl->out) - sizeof(*bufptr);
  bufptr->messages = nl->out_messages;

  /* append to end of queue */
  list_add_tail(&nl->buffered, &bufptr->_node);
  nl->out_messages = 0;

  /* get a new outgoing buffer */
  abuf_init(&nl->out);
  abuf_memcpy(&nl->out, &_dummy_buffer, sizeof(_dummy_buffer));
}

/**
 * Add a netlink message to the outgoign queue of a handler
 * @param nl pointer to netlink handler
 * @param nl_hdr pointer to netlink message
 * @return sequence number used for message
 */
int
os_system_linux_netlink_send(struct os_system_netlink *nl,
    struct nlmsghdr *nl_hdr) {
  _seq_used = (_seq_used + 1) & INT32_MAX;
  OONF_DEBUG(nl->used_by->logging, "Prepare to send netlink '%s' message %u (%u bytes)",
      nl->name, _seq_used, nl_hdr->nlmsg_len);

  nl_hdr->nlmsg_seq = _seq_used;
  nl_hdr->nlmsg_flags |= NLM_F_ACK | NLM_F_MULTI;

  if (nl_hdr->nlmsg_len + abuf_getlen(&nl->out) > (size_t)getpagesize()) {
    _enqueue_netlink_buffer(nl);
  }
  abuf_memcpy(&nl->out, nl_hdr, nl_hdr->nlmsg_len);

  OONF_DEBUG_HEX(nl->used_by->logging, nl_hdr, nl_hdr->nlmsg_len,
      "Content of netlink '%s' message:", nl->name);
  
  nl->out_messages++;

  /* trigger write */
  oonf_socket_set_write(&nl->socket, true);
  return _seq_used;
}

/**
 * Join a list of multicast groups for a netlink socket
 * @param nl pointer to netlink handler
 * @param groups pointer to array of multicast groups
 * @param groupcount number of entries in groups array
 * @return -1 if an error happened, 0 otherwise
 */
int
os_system_linux_netlink_add_mc(struct os_system_netlink *nl,
    const uint32_t *groups, size_t groupcount) {
  size_t i;

  for (i=0; i<groupcount; i++) {
    if (setsockopt(os_fd_get_fd(&nl->socket.fd),
        SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
             &groups[i], sizeof(groups[i]))) {
      OONF_WARN(nl->used_by->logging,
          "Could not join netlink '%s' mc group: %x", nl->name, groups[i]);
      return -1;
    }
  }
  return 0;
}

/**
 * Leave a list of multicast groups for a netlink socket
 * @param nl pointer to netlink handler
 * @param groups pointer to array of multicast groups
 * @param groupcount number of entries in groups array
 * @return -1 if an error happened, 0 otherwise
 */
int
os_system_linux_netlink_drop_mc(struct os_system_netlink *nl,
    const int *groups, size_t groupcount) {
  size_t i;

  for (i=0; i<groupcount; i++) {
    if (setsockopt(os_fd_get_fd(&nl->socket.fd),
        SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
             &groups[i], sizeof(groups[i]))) {
      OONF_WARN(nl->used_by->logging,
          "Could not drop netlink '%s' mc group: %x", nl->name, groups[i]);
      return -1;
    }
  }
  return 0;
}

/**
 * Add an attribute to a netlink message
 * @param nl pinter to os netlink handler
 * @param nlmsg pointer to netlink header
 * @param type type of netlink attribute
 * @param data pointer to data of netlink attribute
 * @param len length of data of netlink attribute
 * @return -1 if netlink message got too large, 0 otherwise
 */
int
os_system_linux_netlink_addreq(struct os_system_netlink *nl,
    struct nlmsghdr *nlmsg, int type, const void *data, int len) {
  struct nlattr *nl_attr;
  size_t aligned_msg_len, aligned_attr_len;

  /* calculate aligned length of message and new attribute */
  aligned_msg_len = NLMSG_ALIGN(nlmsg->nlmsg_len);
  aligned_attr_len = NLA_HDRLEN + len;

  if (aligned_msg_len + aligned_attr_len > UIO_MAXIOV) {
    OONF_WARN(LOG_OS_SYSTEM, "Netlink '%s' message got too large!", nl->name);
    return -1;
  }

  nl_attr = (struct nlattr *) ((void*)((char *)nlmsg + aligned_msg_len));
  nl_attr->nla_type = type;
  nl_attr->nla_len = aligned_attr_len;

  /* fix length of netlink message */
  nlmsg->nlmsg_len = aligned_msg_len + aligned_attr_len;

  if (len) {
    memcpy((char *)nl_attr + NLA_HDRLEN, data, len);
  }
  return 0;
}

/**
 * Handle timeout of netlink acks
 * @param ptr timer instance that fired
 */
static void
_cb_handle_netlink_timeout(struct oonf_timer_instance *ptr) {
  struct os_system_netlink *nl;

  nl = container_of(ptr, struct os_system_netlink, timeout);

  if (nl->cb_timeout) {
    nl->cb_timeout();
  }
  nl->msg_in_transit = 0;
}

/**
 * Send all netlink messages in the outgoing queue to the kernel
 * @param nl pointer to netlink handler
 */
static void
_flush_netlink_buffer(struct os_system_netlink *nl) {
  struct os_system_netlink_buffer *buffer;
  ssize_t ret;
  int err;

  if (nl->msg_in_transit > 0) {
    return;
  }

  if (list_is_empty(&nl->buffered)) {
    if (abuf_getlen(&nl->out) > sizeof(struct os_system_netlink_buffer)) {
      _enqueue_netlink_buffer(nl);
    }
    else {
      oonf_socket_set_write(&nl->socket, false);
      return;
    }
  }

  /* get first buffer */
  buffer = list_first_element(&nl->buffered, buffer, _node);

  /* send outgoing message */
  _netlink_send_iov[0].iov_base = (char *)(buffer) + sizeof(*buffer);
  _netlink_send_iov[0].iov_len = buffer->total;

  if ((ret = sendmsg(os_fd_get_fd(&nl->socket.fd),
        &_netlink_send_msg, MSG_DONTWAIT)) <= 0) {
    err = errno;
    if (err != EAGAIN && err != EWOULDBLOCK) {
      OONF_WARN(nl->used_by->logging,
          "Cannot send data (%"PRINTF_SIZE_T_SPECIFIER" bytes)"
          " to netlink socket %s: %s (%d)",
          abuf_getlen(&nl->out), nl->name, strerror(err), err);

      /* remove netlink message from internal queue */
      nl->cb_error(nl->in->nlmsg_seq, err);
      return;
    }
  }
  else {
    nl->msg_in_transit += buffer->messages;

    OONF_DEBUG(nl->used_by->logging,
        "netlink %s: Sent %u bytes (%u messages in transit)",
        nl->name, buffer->total, nl->msg_in_transit);

    list_remove(&buffer->_node);
    free(buffer);
  }

  oonf_socket_set_write(&nl->socket, !list_is_empty(&nl->buffered));

  /* start feedback timer */
  oonf_timer_set(&nl->timeout, OS_SYSTEM_NETLINK_TIMEOUT);
}

/**
 * Cleanup netlink handler because all outstanding jobs
 * are finished
 * @param nl pointer to os_system_netlink handler
 */
static void
_netlink_job_finished(struct os_system_netlink *nl) {
  if (nl->msg_in_transit > 0) {
    nl->msg_in_transit--;
  }
  if (nl->msg_in_transit == 0) {
    oonf_timer_stop(&nl->timeout);

    if (!list_is_empty(&nl->buffered)
        || nl->out_messages > 0) {
      oonf_socket_set_write(&nl->socket, true);
    }
  }
  OONF_DEBUG(nl->used_by->logging, "netlink '%s' finished: %d still in transit",
      nl->name, nl->msg_in_transit);
}

/**
 * Handler for incoming netlink messages
 * @param fd
 * @param data
 * @param event_read
 * @param event_write
 */
static void
_netlink_handler(struct oonf_socket_entry *entry) {
  struct os_system_netlink *nl;
  struct nlmsghdr *nh;
  ssize_t ret;
  size_t len;
  int flags;
  uint32_t current_seq = 0;
  bool trigger_is_done;

  nl = container_of(entry, typeof(*nl), socket);
  if (oonf_socket_is_write(entry)) {
    _flush_netlink_buffer(nl);
  }

  if (!oonf_socket_is_read(entry)) {
    return;
  }

  /* handle incoming messages */
  _netlink_rcv_msg.msg_flags = 0;
  flags = MSG_PEEK;

netlink_rcv_retry:
  _netlink_rcv_iov.iov_base = nl->in;
  _netlink_rcv_iov.iov_len = nl->in_len;

  OONF_DEBUG(nl->used_by->logging, "Read netlink '%s' message with"
      " %"PRINTF_SIZE_T_SPECIFIER" bytes buffer",
      nl->name, nl->in_len);
  if ((ret = recvmsg(entry->fd.fd, &_netlink_rcv_msg, MSG_DONTWAIT | flags)) < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      OONF_WARN(nl->used_by->logging,"netlink '%s' recvmsg error: %s (%d)\n",
          nl->name, strerror(errno), errno);
    }
    else {
      oonf_socket_set_read(&nl->socket, true);
    }
    return;
  }

  /* not enough buffer space ? */
  if (nl->in_len < (size_t)ret || (_netlink_rcv_msg.msg_flags & MSG_TRUNC) != 0) {
    void *ptr;

    ret = ret / getpagesize();
    ret++;
    ret *= getpagesize();

    ptr = realloc(nl->in, ret);
    if (!ptr) {
      OONF_WARN(nl->used_by->logging, "Not enough memory to"
          " increase netlink '%s' input buffer", nl->name);
      return;
    }
    nl->in = ptr;
    nl->in_len = ret;
    goto netlink_rcv_retry;
  }
  if (flags) {
    /* it worked, not remove the message from the queue */
    flags = 0;
    OONF_DEBUG(nl->used_by->logging, "Got estimate of netlink '%s'"
        " message size, retrieve it", nl->name);
    goto netlink_rcv_retry;
  }

  OONF_DEBUG(nl->used_by->logging, "Got netlink '%s' message of %"
      PRINTF_SSIZE_T_SPECIFIER" bytes", nl->name, ret);
  OONF_DEBUG_HEX(nl->used_by->logging, nl->in, ret,
      "Content of netlink '%s' message:", nl->name);
  
  trigger_is_done = false;

  /* loop through netlink headers */
  len = (size_t) ret;
  for (nh = nl->in; NLMSG_OK (nh, len); nh = NLMSG_NEXT (nh, len)) {
    OONF_DEBUG(nl->used_by->logging,
        "Netlink '%s' message received: type %d seq %u\n",
        nl->name, nh->nlmsg_type, nh->nlmsg_seq);

    if (nh == nl->in) {
      current_seq = nh->nlmsg_seq;
    }

    if (current_seq != nh->nlmsg_seq && trigger_is_done) {
      if (nl->cb_done) {
        nl->cb_done(current_seq);
      }
      trigger_is_done = false;
    }

    switch (nh->nlmsg_type) {
      case NLMSG_NOOP:
        break;

      case NLMSG_DONE:
        /* End of a multipart netlink message reached */
        trigger_is_done = true;
        break;

      case NLMSG_ERROR:
        /* Feedback for async netlink message */
        trigger_is_done = false;
        _handle_nl_err(nl, nh);
        break;

      default:
        if (nl->cb_message) {
          nl->cb_message(nh);
        }
        break;
    }
  }

  if (trigger_is_done) {
    oonf_timer_stop(&nl->timeout);
    if (nl->cb_done) {
      nl->cb_done(current_seq);
    }
    _netlink_job_finished(nl);
  }

  /* reset timeout if necessary */
  if (oonf_timer_is_active(&nl->timeout)) {
    oonf_timer_set(&nl->timeout, OS_SYSTEM_NETLINK_TIMEOUT);
  }
}

/**
 * Handle result code in netlink message
 * @param nl pointer to netlink handler
 * @param nh pointer to netlink message
 */
static void
_handle_nl_err(struct os_system_netlink *nl, struct nlmsghdr *nh) {
  struct nlmsgerr *err;

  err = (struct nlmsgerr *) NLMSG_DATA(nh);

  OONF_DEBUG(nl->used_by->logging,
      "Received netlink '%s' seq %u feedback (%u bytes): %s (%d)",
      nl->name, nh->nlmsg_seq, nh->nlmsg_len, strerror(-err->error), -err->error);

  if (err->error) {
    if (nl->cb_error) {
      nl->cb_error(err->msg.nlmsg_seq, -err->error);
    }
  }
  else {
    if (nl->cb_done) {
      nl->cb_done(err->msg.nlmsg_seq);
    }
  }

  _netlink_job_finished(nl);
}
