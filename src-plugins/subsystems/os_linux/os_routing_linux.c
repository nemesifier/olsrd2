
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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/uio.h>

#include "common/common_types.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "core/oonf_subsystem.h"
#include "subsystems/os_system.h"

#include "subsystems/os_routing.h"
#include "subsystems/os_linux/os_routing_linux.h"

/* Definitions */
#define LOG_OS_ROUTING _oonf_os_routing_subsystem.logging

/**
 * Array to translate between OONF route types and internal kernel types
 */
struct route_type_translation {
  /*! OONF route type */
  enum os_route_type oonf;

  /*! linux kernel route type */
  uint8_t os_linux;
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static int _routing_set(struct nlmsghdr *msg, struct os_route *route,
    unsigned char rt_scope);

static void _routing_finished(struct os_route *route, int error);
static void _cb_rtnetlink_message(struct nlmsghdr *);
static void _cb_rtnetlink_event_message(struct nlmsghdr *);
static void _cb_rtnetlink_error(uint32_t seq, int err);
static void _cb_rtnetlink_done(uint32_t seq);
static void _cb_rtnetlink_timeout(void);

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_OS_SYSTEM_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_os_routing_subsystem = {
  .name = OONF_OS_ROUTING_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_os_routing_subsystem);

/* translation table between route types */
static struct route_type_translation _type_translation[] = {
    { OS_ROUTE_UNICAST, RTN_UNICAST },
    { OS_ROUTE_LOCAL, RTN_LOCAL },
    { OS_ROUTE_BROADCAST, RTN_BROADCAST },
    { OS_ROUTE_MULTICAST, RTN_MULTICAST },
    { OS_ROUTE_THROW, RTN_THROW },
    { OS_ROUTE_UNREACHABLE, RTN_UNREACHABLE },
    { OS_ROUTE_PROHIBIT, RTN_PROHIBIT },
    { OS_ROUTE_BLACKHOLE, RTN_BLACKHOLE },
    { OS_ROUTE_NAT, RTN_NAT }
};

/* netlink socket for route set/get commands */
static const uint32_t _rtnetlink_mcast[] = {
  RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_ROUTE
};

static struct os_system_netlink _rtnetlink_socket = {
  .name = "routing",
  .used_by = &_oonf_os_routing_subsystem,
  .cb_message = _cb_rtnetlink_message,
  .cb_error = _cb_rtnetlink_error,
  .cb_done = _cb_rtnetlink_done,
  .cb_timeout = _cb_rtnetlink_timeout,
};

static struct os_system_netlink _rtnetlink_event_socket = {
  .name = "routing listener",
  .used_by = &_oonf_os_routing_subsystem,
  .cb_message = _cb_rtnetlink_event_message,
};

static struct avl_tree _rtnetlink_feedback;
static struct list_entity _rtnetlink_listener;

/* default wildcard route */
static const struct os_route_parameter OS_ROUTE_WILDCARD = {
  .family = AF_UNSPEC,
  .src_ip = { ._type = AF_UNSPEC },
  .gw = { ._type = AF_UNSPEC },
  .type = OS_ROUTE_UNDEFINED,
  .key = {
      .dst = { ._type = AF_UNSPEC },
      .src = { ._type = AF_UNSPEC },
  },
  .table = RT_TABLE_UNSPEC,
  .metric = -1,
  .protocol = RTPROT_UNSPEC,
  .if_index = 0
};

/* kernel version check */
static bool _is_kernel_3_11_0_or_better;

/**
 * Initialize routing subsystem
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  if (os_system_linux_netlink_add(&_rtnetlink_socket, NETLINK_ROUTE)) {
    return -1;
  }

  if (os_system_linux_netlink_add(&_rtnetlink_event_socket, NETLINK_ROUTE)) {
    os_system_linux_netlink_remove(&_rtnetlink_socket);
    return -1;
  }

  if (os_system_linux_netlink_add_mc(&_rtnetlink_event_socket, _rtnetlink_mcast, ARRAYSIZE(_rtnetlink_mcast))) {
    os_system_linux_netlink_remove(&_rtnetlink_socket);
    os_system_linux_netlink_remove(&_rtnetlink_event_socket);
    return -1;
  }
  avl_init(&_rtnetlink_feedback, avl_comp_uint32, false);
  list_init_head(&_rtnetlink_listener);

  _is_kernel_3_11_0_or_better = os_system_linux_is_minimal_kernel(3,11,0);
  return 0;
}

/**
 * Cleanup all resources allocated by the routing subsystem
 */
static void
_cleanup(void) {
  struct os_route *rt, *rt_it;

  avl_for_each_element_safe(&_rtnetlink_feedback, rt, _internal._node, rt_it) {
    _routing_finished(rt, 1);
  }

  os_system_linux_netlink_remove(&_rtnetlink_socket);
  os_system_linux_netlink_remove(&_rtnetlink_event_socket);
}

/**
 * Check if kernel supports source-specific routing
 * @param af_family address family
 * @return true if source-specific routing is supported for
 *   address family
 */
bool
os_routing_linux_supports_source_specific(int af_family) {
  if (af_family == AF_INET) {
    return false;
  }

  /* TODO: better check for source specific routing necessary! */
  return _is_kernel_3_11_0_or_better;
}

/**
 * Update an entry of the kernel routing table. This call will only trigger
 * the change, the real change will be done as soon as the netlink socket is
 * writable.
 * @param route data of route to be set/removed
 * @param set true if route should be set, false if it should be removed
 * @param del_similar true if similar routes that block this one should be
 *   removed.
 * @return -1 if an error happened, 0 otherwise
 */
int
os_routing_linux_set(struct os_route *route, bool set, bool del_similar) {
  uint8_t buffer[UIO_MAXIOV];
  struct nlmsghdr *msg;
  unsigned char scope;
  struct os_route os_rt;
  int seq;
#ifdef OONF_LOG_DEBUG_INFO
  struct os_route_str rbuf;
#endif

  memset(buffer, 0, sizeof(buffer));

  /* copy route settings */
  memcpy(&os_rt, route, sizeof(os_rt));

  /* get pointers for netlink message */
  msg = (void *)&buffer[0];

  msg->nlmsg_flags = NLM_F_REQUEST;

  /* set length of netlink message with rtmsg payload */
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

  /* normally all routing operations are UNIVERSE scope */
  scope = RT_SCOPE_UNIVERSE;

  if (set) {
    msg->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
    msg->nlmsg_type = RTM_NEWROUTE;
  } else {
    msg->nlmsg_type = RTM_DELROUTE;

    os_rt.p.protocol = 0;
    netaddr_invalidate(&os_rt.p.src_ip);

    if (del_similar) {
      /* no interface necessary */
      os_rt.p.if_index = 0;

      /* as wildcard for fuzzy deletion */
      scope = RT_SCOPE_NOWHERE;
    }
  }

  if (netaddr_is_unspec(&os_rt.p.gw)
      && netaddr_get_address_family(&os_rt.p.key.dst) == AF_INET
      && netaddr_get_prefix_length(&os_rt.p.key.dst) == netaddr_get_maxprefix(&os_rt.p.key.dst)) {
    /* use destination as gateway, to 'force' linux kernel to do proper source address selection */
    memcpy(&os_rt.p.gw, &os_rt.p.key.dst, sizeof(os_rt.p.gw));
  }

  OONF_DEBUG(LOG_OS_ROUTING, "%sset route: %s", set ? "" : "re",
      os_routing_to_string(&rbuf, &os_rt.p));

  if (_routing_set(msg, &os_rt, scope)) {
    return -1;
  }

  /* cannot fail */
  seq = os_system_linux_netlink_send(&_rtnetlink_socket, msg);

  if (route->cb_finished) {
    route->_internal.nl_seq = seq;
    route->_internal._node.key = &route->_internal.nl_seq;

    assert (!avl_is_node_added(&route->_internal._node));
    avl_insert(&_rtnetlink_feedback, &route->_internal._node);
  }
  return 0;
}

/**
 * Request all routing data of a certain address family
 * @param route pointer to routing filter
 * @return -1 if an error happened, 0 otherwise
 */
int
os_routing_linux_query(struct os_route *route) {
  uint8_t buffer[UIO_MAXIOV];
  struct nlmsghdr *msg;
  struct rtgenmsg *rt_gen;
  int seq;

  assert (route->cb_finished != NULL && route->cb_get != NULL);
  memset(buffer, 0, sizeof(buffer));

  /* get pointers for netlink message */
  msg = (void *)&buffer[0];
  rt_gen = NLMSG_DATA(msg);

  msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

  /* set length of netlink message with rtmsg payload */
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(*rt_gen));

  msg->nlmsg_type = RTM_GETROUTE;
  rt_gen->rtgen_family = route->p.family;

  seq = os_system_linux_netlink_send(&_rtnetlink_socket, msg);
  if (seq < 0) {
    return -1;
  }

  route->_internal.nl_seq = seq;
  route->_internal._node.key = &route->_internal.nl_seq;
  avl_insert(&_rtnetlink_feedback, &route->_internal._node);
  return 0;
}

/**
 * Stop processing of a routing command
 * @param route pointer to os_route
 */
void
os_routing_linux_interrupt(struct os_route *route) {
  if (os_routing_linux_is_in_progress(route)) {
    _routing_finished(route, -1);
  }
}

/**
 * @param route os route
 * @return true if route is being processed by the kernel,
 *   false otherwise
 */
bool
os_routing_linux_is_in_progress(struct os_route *route) {
  return avl_is_node_added(&route->_internal._node);
}

/**
 * Add routing change listener
 * @param listener routing change listener
 */
void
os_routing_linux_listener_add(struct os_route_listener *listener) {
  list_add_tail(&_rtnetlink_listener, &listener->_internal._node);
}

/**
 * Remove routing change listener
 * @param listener routing change listener
 */
void
os_routing_linux_listener_remove(struct os_route_listener *listener) {
  list_remove(&listener->_internal._node);
}

/**
 * @return wildcard route
 */
const struct os_route_parameter *
os_routing_linux_get_wildcard_route(void) {
  return &OS_ROUTE_WILDCARD;
}

/**
 * Stop processing of a routing command and set error code
 * for callback
 * @param route pointer to os_route
 * @param error error code, 0 if no error
 */
static void
_routing_finished(struct os_route *route, int error) {
  /* remove first to prevent any kind of recursive cleanup */
  avl_remove(&_rtnetlink_feedback, &route->_internal._node);

  if (route->cb_finished) {
    route->cb_finished(route, error);
  }
}

/**
 * Initiatize the an netlink routing message
 * @param msg pointer to netlink message header
 * @param route data to be added to the netlink message
 * @param scope scope of route to be set/removed
 * @return -1 if an error happened, 0 otherwise
 */
static int
_routing_set(struct nlmsghdr *msg, struct os_route *route,
    unsigned char rt_scope) {
  struct rtmsg *rt_msg;
  size_t i;

  /* calculate address af_type */
  if (netaddr_get_address_family(&route->p.key.dst) != AF_UNSPEC) {
    route->p.family = netaddr_get_address_family(&route->p.key.dst);
  }
  if (netaddr_get_address_family(&route->p.gw) != AF_UNSPEC) {
    if (route->p.family  != AF_UNSPEC
        && route->p.family  != netaddr_get_address_family(&route->p.gw)) {
      return -1;
    }
    route->p.family  = netaddr_get_address_family(&route->p.gw);
  }
  if (netaddr_get_address_family(&route->p.src_ip) != AF_UNSPEC) {
    if (route->p.family  != AF_UNSPEC && route->p.family  != netaddr_get_address_family(&route->p.src_ip)) {
      return -1;
    }
    route->p.family  = netaddr_get_address_family(&route->p.src_ip);
  }

  if (route->p.family  == AF_UNSPEC) {
    route->p.family  = AF_INET;
  }

  /* initialize rtmsg payload */
  rt_msg = NLMSG_DATA(msg);

  rt_msg->rtm_family = route->p.family ;
  rt_msg->rtm_scope = rt_scope;
  rt_msg->rtm_protocol = route->p.protocol;
  rt_msg->rtm_table = route->p.table;

  /* set default route type */
  rt_msg->rtm_type = RTN_UNICAST;

  /* set route type */
  for (i=0; i<ARRAYSIZE(_type_translation); i++) {
    if (_type_translation[i].oonf == route->p.type) {
      rt_msg->rtm_type = _type_translation[i].os_linux;
      break;
    }
  }

  /* add attributes */
  if (netaddr_get_address_family(&route->p.src_ip) != AF_UNSPEC) {
    /* add src-ip */
    if (os_system_linux_netlink_addnetaddr(&_rtnetlink_event_socket,
        msg, RTA_PREFSRC, &route->p.src_ip)) {
      return -1;
    }
  }

  if (netaddr_get_address_family(&route->p.gw) != AF_UNSPEC) {
    rt_msg->rtm_flags |= RTNH_F_ONLINK;

    /* add gateway */
    if (os_system_linux_netlink_addnetaddr(&_rtnetlink_event_socket,
        msg, RTA_GATEWAY, &route->p.gw)) {
      return -1;
    }
  }

  if (netaddr_get_address_family(&route->p.key.dst) != AF_UNSPEC) {
    rt_msg->rtm_dst_len = netaddr_get_prefix_length(&route->p.key.dst);

    /* add destination */
    if (os_system_linux_netlink_addnetaddr(&_rtnetlink_event_socket,
        msg, RTA_DST, &route->p.key.dst)) {
      return -1;
    }
  }

  if (netaddr_get_address_family(&route->p.key.src) == AF_INET6
      && netaddr_get_prefix_length(&route->p.key.src) != 0) {
    rt_msg->rtm_src_len = netaddr_get_prefix_length(&route->p.key.src);

    /* add source-specific routing prefix */
    if (os_system_linux_netlink_addnetaddr(&_rtnetlink_event_socket,
        msg, RTA_SRC, &route->p.key.src)) {
      return -1;
    }
  }

  if (route->p.metric != -1) {
    /* add metric */
    if (os_system_linux_netlink_addreq(&_rtnetlink_event_socket,
        msg, RTA_PRIORITY, &route->p.metric, sizeof(route->p.metric))) {
      return -1;
    }
  }

  if (route->p.if_index) {
    /* add interface*/
    if (os_system_linux_netlink_addreq(&_rtnetlink_event_socket,
        msg, RTA_OIF, &route->p.if_index, sizeof(route->p.if_index))) {
      return -1;
    }
  }
  return 0;
}

/**
 * Parse a rtnetlink header into a os_route object
 * @param route pointer to target os_route
 * @param msg pointer to rtnetlink message header
 * @return -1 if address family of rtnetlink is unknown,
 *   1 if the entry should be ignored, 0 otherwise
 */
static int
_routing_parse_nlmsg(struct os_route *route, struct nlmsghdr *msg) {
  struct rtmsg *rt_msg;
  struct rtattr *rt_attr;
  int rt_len;
  size_t i;

  rt_msg = NLMSG_DATA(msg);
  rt_attr = (struct rtattr *) RTM_RTA(rt_msg);
  rt_len = RTM_PAYLOAD(msg);

  if ((rt_msg->rtm_flags & RTM_F_CLONED) != 0) {
    /* ignore cloned route events by returning the wildcard route */
    return 1;
  }

  memcpy(&route->p, &OS_ROUTE_WILDCARD, sizeof(OS_ROUTE_WILDCARD));

  route->p.protocol = rt_msg->rtm_protocol;
  route->p.table = rt_msg->rtm_table;
  route->p.family = rt_msg->rtm_family;

  if (route->p.family != AF_INET && route->p.family != AF_INET6) {
    return -1;
  }

  /* get route type */
  route->p.type = OS_ROUTE_UNDEFINED;
  for (i=0; i<ARRAYSIZE(_type_translation); i++) {
    if (rt_msg->rtm_type == _type_translation[i].os_linux) {
      route->p.type = _type_translation[i].oonf;
      break;
    }
  }
  if (route->p.type == OS_ROUTE_UNDEFINED) {
    OONF_WARN(LOG_OS_ROUTING, "Got route type: %u", rt_msg->rtm_type);
    return -1;
  }

  for(; RTA_OK(rt_attr, rt_len); rt_attr = RTA_NEXT(rt_attr,rt_len)) {
    switch(rt_attr->rta_type) {
      case RTA_PREFSRC:
        netaddr_from_binary(&route->p.src_ip, RTA_DATA(rt_attr), RTA_PAYLOAD(rt_attr),
            rt_msg->rtm_family);
        break;
      case RTA_GATEWAY:
        netaddr_from_binary(&route->p.gw, RTA_DATA(rt_attr), RTA_PAYLOAD(rt_attr), rt_msg->rtm_family);
        break;
      case RTA_DST:
        netaddr_from_binary_prefix(&route->p.key.dst, RTA_DATA(rt_attr), RTA_PAYLOAD(rt_attr),
            rt_msg->rtm_family, rt_msg->rtm_dst_len);
        break;
      case RTA_SRC:
        netaddr_from_binary_prefix(&route->p.key.src, RTA_DATA(rt_attr),
            RTA_PAYLOAD(rt_attr), rt_msg->rtm_family, rt_msg->rtm_src_len);
        break;
      case RTA_PRIORITY:
        memcpy(&route->p.metric, RTA_DATA(rt_attr), sizeof(route->p.metric));
        break;
      case RTA_OIF:
        memcpy(&route->p.if_index, RTA_DATA(rt_attr), sizeof(route->p.if_index));
        break;
      default:
        break;
    }
  }

  if (netaddr_get_address_family(&route->p.key.dst) == AF_UNSPEC) {
    memcpy(&route->p.key.dst, route->p.family == AF_INET ? &NETADDR_IPV4_ANY : &NETADDR_IPV6_ANY,
        sizeof(route->p.key.dst));
    netaddr_set_prefix_length(&route->p.key.dst, rt_msg->rtm_dst_len);
  }
  return 0;
}

/**
 * Checks if a os_route object matches a routing filter
 * @param filter pointer to filter
 * @param route pointer to route object
 * @return true if route matches the filter, false otherwise
 */
static bool
_match_routes(struct os_route *filter, struct os_route *route) {
  if (filter->p.family != AF_UNSPEC && filter->p.family != route->p.family) {
    return false;
  }
  if (netaddr_get_address_family(&filter->p.src_ip) != AF_UNSPEC
      && memcmp(&filter->p.src_ip, &route->p.src_ip, sizeof(filter->p.src_ip)) != 0) {
    return false;
  }
  if (filter->p.type != OS_ROUTE_UNDEFINED && filter->p.type != route->p.type) {
    return false;
  }
  if (netaddr_get_address_family(&filter->p.gw) != AF_UNSPEC
      && memcmp(&filter->p.gw, &route->p.gw, sizeof(filter->p.gw)) != 0) {
    return false;
  }
  if (netaddr_get_address_family(&filter->p.key.dst) != AF_UNSPEC
      && memcmp(&filter->p.key.dst, &route->p.key.dst, sizeof(filter->p.key.dst)) != 0) {
    return false;
  }
  if (netaddr_get_address_family(&filter->p.key.src) != AF_UNSPEC
      && memcmp(&filter->p.key.src, &route->p.key.src, sizeof(filter->p.key.src)) != 0) {
    return false;
  }
  if (filter->p.metric != -1 && filter->p.metric != route->p.metric) {
    return false;
  }
  if (filter->p.table != RT_TABLE_UNSPEC && filter->p.table != route->p.table) {
    return false;
  }
  if (filter->p.protocol != RTPROT_UNSPEC && filter->p.protocol != route->p.protocol) {
    return false;
  }
  return filter->p.if_index == 0 || filter->p.if_index == route->p.if_index;
}

/**
 * Handle incoming rtnetlink messages
 * @param msg
 */
static void
_cb_rtnetlink_message(struct nlmsghdr *msg) {
  struct os_route *filter;
  struct os_route rt;
  int result;

  OONF_DEBUG(LOG_OS_ROUTING, "Got message: %d %d", msg->nlmsg_seq, msg->nlmsg_type);

  if (msg->nlmsg_type != RTM_NEWROUTE && msg->nlmsg_type != RTM_DELROUTE) {
    return;
  }

  if ((result = _routing_parse_nlmsg(&rt, msg))) {
    if (result < 0) {
      OONF_WARN(LOG_OS_ROUTING, "Error while processing route reply");
    }
    return;
  }

  /* check for feedback for ongoing route commands */
  filter = avl_find_element(&_rtnetlink_feedback, &msg->nlmsg_seq, filter, _internal._node);
  if (filter) {
    if (filter->cb_get != NULL && _match_routes(filter, &rt)) {
      filter->cb_get(filter, &rt);
    }
  }
}

/**
 * Handle incoming rtnetlink messages
 * @param msg
 */
static void
_cb_rtnetlink_event_message(struct nlmsghdr *msg) {
  struct os_route_listener *listener;
  struct os_route rt;
  int result;

  OONF_DEBUG(LOG_OS_ROUTING, "Got event message: %d %d", msg->nlmsg_seq, msg->nlmsg_type);

  if (msg->nlmsg_type != RTM_NEWROUTE && msg->nlmsg_type != RTM_DELROUTE) {
    return;
  }

  if ((result = _routing_parse_nlmsg(&rt, msg))) {
    if (result < 0) {
      OONF_WARN(LOG_OS_ROUTING, "Error while processing route reply");
    }
    return;
  }

  /* send route events to listeners */
  list_for_each_element(&_rtnetlink_listener, listener, _internal._node) {
    listener->cb_get(&rt, msg->nlmsg_type == RTM_NEWROUTE);
  }
}

/**
 * Handle feedback from netlink socket
 * @param seq
 * @param error
 */
static void
_cb_rtnetlink_error(uint32_t seq, int err) {
  struct os_route *route;
#ifdef OONF_LOG_DEBUG_INFO
  struct os_route_str rbuf;
#endif

  /* transform into errno number */
  route = avl_find_element(&_rtnetlink_feedback, &seq, route, _internal._node);
  if (route) {
    OONF_DEBUG(LOG_OS_ROUTING, "Route seqno %u failed: %s (%d) %s",
        seq, strerror(err), err,
        os_routing_to_string(&rbuf, &route->p));

    _routing_finished(route, err);
  }
  else {
    OONF_DEBUG(LOG_OS_ROUTING, "Unknown route with seqno %u failed: %s (%d)",
        seq, strerror(err), err);
  }
}

/**
 * Handle ack timeout from netlink socket
 */
static void
_cb_rtnetlink_timeout(void) {
  struct os_route *route, *rt_it;

  OONF_WARN(LOG_OS_ROUTING, "Netlink timeout for routing");

  avl_for_each_element_safe(&_rtnetlink_feedback, route, _internal._node, rt_it) {
    _routing_finished(route, -1);
  }
}

/**
 * Handle done from multipart netlink messages
 * @param seq
 */
static void
_cb_rtnetlink_done(uint32_t seq) {
  struct os_route *route;
#ifdef OONF_LOG_DEBUG_INFO
  struct os_route_str rbuf;
#endif

  OONF_DEBUG(LOG_OS_ROUTING, "Got done: %u", seq);

  route = avl_find_element(&_rtnetlink_feedback, &seq, route, _internal._node);
  if (route) {
    OONF_DEBUG(LOG_OS_ROUTING, "Route %s with seqno %u done",
        os_routing_to_string(&rbuf, &route->p), seq);
    _routing_finished(route, 0);
  }
}
