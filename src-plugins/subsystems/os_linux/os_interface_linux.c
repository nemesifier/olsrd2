
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

/*! activate GUI sources for this file */
#define _GNU_SOURCE

/* must be first because of a problem with linux/rtnetlink.h */
#include <sys/socket.h>

/* and now the rest of the includes */
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#include "common/common_types.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "common/string.h"
#include "core/oonf_cfg.h"
#include "core/oonf_main.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_timer.h"
#include "subsystems/os_system.h"

#include "subsystems/os_interface.h"

/* Definitions */
#define LOG_OS_INTERFACE _oonf_os_interface_subsystem.logging

/*! proc file entry for activating IPv4 forwarding */
#define PROC_IPFORWARD_V4 "/proc/sys/net/ipv4/ip_forward"

/*! proc file entry for activating IPv6 forwarding */
#define PROC_IPFORWARD_V6 "/proc/sys/net/ipv6/conf/all/forwarding"

/*! proc file entry to deactivate interface specific redirect requests */
#define PROC_IF_REDIRECT "/proc/sys/net/ipv4/conf/%s/send_redirects"

/*! proc file entry to deactivate generic redirect requests */
#define PROC_ALL_REDIRECT "/proc/sys/net/ipv4/conf/all/send_redirects"

/*! proc file entry to deactivate interface specific reverse path filter */
#define PROC_IF_SPOOF "/proc/sys/net/ipv4/conf/%s/rp_filter"

/*! proc file entry to deactivate generic reverse path filter */
#define PROC_ALL_SPOOF "/proc/sys/net/ipv4/conf/all/rp_filter"

/*! sysfs entry to get vlan interface base index */
#define SYSFS_BASE_IFINDEX "/sys/class/net/%s/iflink"

/* prototypes */
static int _init(void);
static void _cleanup(void);
static void _early_cfg_init(void);

static int _init_mesh(struct os_interface *os_if);
static void _cleanup_mesh(struct os_interface *os_if);

static void _query_interface_links(void);
static void _query_interface_addresses(void);

static void _cb_rtnetlink_message(struct nlmsghdr *hdr);
static void _cb_rtnetlink_error(uint32_t seq, int error);
static void _cb_rtnetlink_done(uint32_t seq);
static void _cb_rtnetlink_timeout(void);
static void _cb_query_error(uint32_t seq, int error);
static void _cb_query_done(uint32_t seq);
static void _cb_query_timeout(void);
static void _address_finished(
    struct os_interface_ip_change *addr, int error);

static void _activate_if_routing(void);
static void _deactivate_if_routing(void);
static int _os_linux_writeToFile(const char *file, char *old, char value);

static void _cb_interface_changed(struct oonf_timer_instance *);
static int _handle_unused_parameter(const char *arg);

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_OS_SYSTEM_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_os_interface_subsystem = {
  .name = OONF_OS_INTERFACE_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
  .early_cfg_init = _early_cfg_init,
};
DECLARE_OONF_PLUGIN(_oonf_os_interface_subsystem);

/* rtnetlink receiver for interface and address events */
static struct os_system_netlink _rtnetlink_receiver = {
  .name = "interface snooper",
  .used_by = &_oonf_os_interface_subsystem,
  .cb_message = _cb_rtnetlink_message,
  .cb_error = _cb_rtnetlink_error,
  .cb_done = _cb_rtnetlink_done,
  .cb_timeout = _cb_rtnetlink_timeout,
};

static struct list_entity _rtnetlink_feedback;

static const uint32_t _rtnetlink_mcast[] = {
  RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR
};

static struct os_system_netlink _rtnetlink_if_query = {
  .name = "interface query",
  .used_by = &_oonf_os_interface_subsystem,
  .cb_message = _cb_rtnetlink_message,
  .cb_error = _cb_query_error,
  .cb_done = _cb_query_done,
  .cb_timeout = _cb_query_timeout,
};

static bool _link_query_in_progress = false;
static bool _address_query_in_progress = false;
static bool _trigger_link_query = false;
static bool _trigger_address_query = false;

/* global procfile state before initialization */
static char _original_rp_filter;
static char _original_icmp_redirect;
static char _original_ipv4_forward;
static char _original_ipv6_forward;

/* counter of mesh interfaces for ip_forward configuration */
static int _mesh_count = 0;

/* kernel version check */
static bool _is_kernel_2_6_31_or_better;

/* interface data handling */
static struct oonf_class _interface_data_class = {
  .name = "network interface data",
  .size = sizeof(struct os_interface),
};

static struct oonf_class _interface_class = {
  .name = "network interface",
  .size = sizeof(struct os_interface_listener),
};

static struct oonf_class _interface_ip_class = {
  .name = "network interface ip",
  .size = sizeof(struct os_interface_ip),
};

static struct oonf_timer_class _interface_change_timer = {
  .name = "interface change",
  .callback = _cb_interface_changed,
};

static struct avl_tree _interface_data_tree;
static const char _ANY_INTERFACE[] = OS_INTERFACE_ANY;

/**
 * Initialize os-specific subsystem
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  if (os_system_linux_netlink_add(&_rtnetlink_receiver, NETLINK_ROUTE)) {
    return -1;
  }

  if (os_system_linux_netlink_add(&_rtnetlink_if_query, NETLINK_ROUTE)) {
    os_system_linux_netlink_remove(&_rtnetlink_receiver);
    return -1;
  }

  if (os_system_linux_netlink_add_mc(&_rtnetlink_receiver, _rtnetlink_mcast, ARRAYSIZE(_rtnetlink_mcast))) {
    os_system_linux_netlink_remove(&_rtnetlink_receiver);
    os_system_linux_netlink_remove(&_rtnetlink_if_query);
    return -1;
  }

  list_init_head(&_rtnetlink_feedback);
  avl_init(&_interface_data_tree, avl_comp_strcasecmp, false);
  oonf_class_add(&_interface_data_class);
  oonf_class_add(&_interface_ip_class);
  oonf_class_add(&_interface_class);
  oonf_timer_add(&_interface_change_timer);

  _is_kernel_2_6_31_or_better = os_system_linux_is_minimal_kernel(2,6,31);

  return 0;
}

/**
 * Cleanup os-specific subsystem
 */
static void
_cleanup(void) {
  struct os_interface_listener *if_listener, *if_listener_it;
  struct os_interface *os_if, *os_if_it;

  avl_for_each_element_safe(&_interface_data_tree, os_if, _node, os_if_it) {
    list_for_each_element_safe(&os_if->_listeners, if_listener, _node, if_listener_it) {
      os_interface_linux_remove(if_listener);
    }
  }

  oonf_timer_remove(&_interface_change_timer);
  oonf_class_remove(&_interface_ip_class);
  oonf_class_remove(&_interface_data_class);
  oonf_class_remove(&_interface_class);

  os_system_linux_netlink_remove(&_rtnetlink_if_query);
  os_system_linux_netlink_remove(&_rtnetlink_receiver);
}

static
void _early_cfg_init(void) {
  oonf_main_set_parameter_handler(_handle_unused_parameter);
}

/**
 * Add an interface event listener to the operation system
 * @param if_listener network interface listener
 */
struct os_interface *
os_interface_linux_add(struct os_interface_listener *if_listener) {
  struct os_interface *data;

  if (if_listener->data) {
    /* interface is already hooked up to data */
    return if_listener->data;
  }

  if (!if_listener->name || !if_listener->name[0]) {
    if_listener->name = _ANY_INTERFACE;
  }

  data = avl_find_element(&_interface_data_tree, if_listener->name, data, _node);
  if (!data) {
    data = oonf_class_malloc(&_interface_data_class);
    if (!data) {
      return NULL;
    }

    OONF_INFO(LOG_OS_INTERFACE, "Add interface to tracking: %s", if_listener->name);

    /* hook into interface data tree */
    strscpy(data->name, if_listener->name, IF_NAMESIZE);
    data->_node.key = data->name;
    avl_insert(&_interface_data_tree, &data->_node);

    /* initialize list/tree */
    avl_init(&data->addresses, avl_comp_netaddr, false);
    list_init_head(&data->_listeners);

    /* initialize change timer */
    data->_change_timer.class = &_interface_change_timer;

    /* check if this is the unspecified interface "any" */
    if (strcmp(data->name, _ANY_INTERFACE) == 0) {
      data->flags.any = true;
    }

    /* trigger new queries */
    _trigger_link_query = true;
    _trigger_address_query = true;

    _query_interface_links();
  }

  /* hook into interface data */
  if_listener->data = data;
  list_add_tail(&data->_listeners, &if_listener->_node);

  if (if_listener->mesh && if_listener->name != _ANY_INTERFACE) {
    if (!data->_internal.mesh_counter) {
      _init_mesh(data);
    }
    data->_internal.mesh_counter++;
  }

  /* trigger interface change listener if necessary */
  if_listener->_dirty = true;
  oonf_timer_start(&data->_change_timer, 200);

  return data;
}

/**
 * Remove an interface event listener to the operation system
 * @param if_listener network interface listener
 */
void
os_interface_linux_remove(struct os_interface_listener *if_listener) {
  struct os_interface_ip *ip, *ip_iter;
  struct os_interface *data;

  if (!if_listener->data) {
    /* interface not hooked up to data */
    return;
  }

  OONF_INFO(LOG_OS_INTERFACE, "Remove interface from tracking: %s", if_listener->name);

  if (if_listener->mesh) {
    if_listener->data->_internal.mesh_counter--;
    if (!if_listener->data->_internal.mesh_counter) {
      _cleanup_mesh(if_listener->data);
    }
  }

  /* unhook from interface data */
  data = if_listener->data;
  if_listener->data = NULL;
  list_remove(&if_listener->_node);

  if (list_is_empty(&data->_listeners)) {
    /* remove all addresses */
    avl_for_each_element_safe(&data->addresses, ip, _node, ip_iter) {
      avl_remove(&data->addresses, &ip->_node);
      oonf_class_free(&_interface_ip_class, ip);
    }

    /* stop change timer */
    oonf_timer_stop(&data->_change_timer);

    /* remove interface */
    avl_remove(&_interface_data_tree, &data->_node);
    oonf_class_free(&_interface_data_class, data);
  }
}

/**
 * @return tree of os interfaces
 */
struct avl_tree *
os_interface_linux_get_tree(void) {
  return &_interface_data_tree;
}

/**
 * Trigger the event handler of an interface listener
 * @param if_listener network interface listener
 */
void
os_interface_linux_trigger_handler(struct os_interface_listener *if_listener) {
  if_listener->_dirty = true;
  if (!oonf_timer_is_active(&if_listener->data->_change_timer)) {
    oonf_timer_start(&if_listener->data->_change_timer,
        OS_INTERFACE_CHANGE_TRIGGER_INTERVAL);
  }
}
/**
 * Set interface up or down
 * @param os_if network interface
 * @param up true if interface should be up, false if down
 * @return -1 if an error happened, 0 otherwise
 */
int
os_interface_linux_state_set(struct os_interface *os_if, bool up) {
  int oldflags;
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strscpy(ifr.ifr_name, os_if->name, IF_NAMESIZE);

  if (ioctl(os_system_linux_linux_get_ioctl_fd(AF_INET),
      SIOCGIFFLAGS, &ifr) < 0) {
    OONF_WARN(LOG_OS_INTERFACE,
        "ioctl SIOCGIFFLAGS (get flags) error on device %s: %s (%d)\n",
        os_if->name, strerror(errno), errno);
    return -1;
  }

  oldflags = ifr.ifr_flags;
  if (up) {
    ifr.ifr_flags |= IFF_UP;
  }
  else {
    ifr.ifr_flags &= ~IFF_UP;
  }

  if (oldflags == ifr.ifr_flags) {
    /* interface is already up/down */
    return 0;
  }

  if (ioctl(os_system_linux_linux_get_ioctl_fd(AF_INET),
      SIOCSIFFLAGS, &ifr) < 0) {
    OONF_WARN(LOG_OS_INTERFACE,
        "ioctl SIOCSIFFLAGS (set flags %s) error on device %s: %s (%d)\n",
        up ? "up" : "down", os_if->name, strerror(errno), errno);
    return -1;
  }
  return 0;
}

/**
 * Set or remove an IP address from an interface
 * @param addr interface address change request
 * @return -1 if the request could not be sent to the server,
 *   0 otherwise
 */
int
os_interface_linux_address_set(
    struct os_interface_ip_change *addr) {
  uint8_t buffer[UIO_MAXIOV];
  struct nlmsghdr *msg;
  struct ifaddrmsg *ifaddrreq;
  int seq;
#if defined(OONF_LOG_DEBUG_INFO)
  struct netaddr_str nbuf;
#endif

  memset(buffer, 0, sizeof(buffer));

  /* get pointers for netlink message */
  msg = (void *)&buffer[0];

  if (addr->set) {
    msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    msg->nlmsg_type = RTM_NEWADDR;
  }
  else {
    msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsg_type = RTM_DELADDR;
  }

  /* set length of netlink message with ifaddrmsg payload */
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

  OONF_DEBUG(LOG_OS_INTERFACE, "%sset address on if %d: %s",
      addr->set ? "" : "re", addr->if_index,
      netaddr_to_string(&nbuf, &addr->address));

  ifaddrreq = NLMSG_DATA(msg);
  ifaddrreq->ifa_family = netaddr_get_address_family(&addr->address);
  ifaddrreq->ifa_prefixlen = netaddr_get_prefix_length(&addr->address);
  ifaddrreq->ifa_index= addr->if_index;
  ifaddrreq->ifa_scope = addr->scope;

  if (os_system_linux_netlink_addnetaddr(&_rtnetlink_receiver,
      msg, IFA_LOCAL, &addr->address)) {
    return -1;
  }

  /* cannot fail */
  seq = os_system_linux_netlink_send(&_rtnetlink_receiver, msg);

  if (addr->cb_finished) {
    list_add_tail(&_rtnetlink_feedback, &addr->_internal._node);
    addr->_internal.nl_seq = seq;
  }
  return 0;
}

/**
 * Stop processing an interface address change
 * @param addr interface address change request
 */
void
os_interface_linux_address_interrupt(struct os_interface_ip_change *addr) {
  if (list_is_node_added(&addr->_internal._node)) {
    /* remove first to prevent any kind of recursive cleanup */
    list_remove(&addr->_internal._node);

    if (addr->cb_finished) {
      addr->cb_finished(addr, -1);
    }
  }
}

/**
 * Set the mac address of an interface
 * @param os_if network interface
 * @param mac mac address
 * @return -1 if an error happened, 0 otherwise
 */
int
os_interface_linux_mac_set(struct os_interface *os_if, struct netaddr *mac) {
  struct ifreq if_req;
  struct netaddr_str nbuf;

  if (netaddr_get_address_family(mac) != AF_MAC48) {
    OONF_WARN(LOG_OS_INTERFACE, "Interface MAC must mac48, not %s",
        netaddr_to_string(&nbuf, mac));
    return -1;
  }

  memset(&if_req, 0, sizeof(if_req));
  strscpy(if_req.ifr_name, os_if->name, IF_NAMESIZE);

  if_req.ifr_addr.sa_family = ARPHRD_ETHER;
  netaddr_to_binary(&if_req.ifr_addr.sa_data, mac, 6);

  if (ioctl(os_system_linux_linux_get_ioctl_fd(AF_INET), SIOCSIFHWADDR, &if_req) < 0) {
    OONF_WARN(LOG_OS_INTERFACE, "Could not set mac address of '%s': %s (%d)",
        os_if->name, strerror(errno), errno);
    return -1;
  }
  return 0;
}

/**
 * Initialize interface for mesh usage
 * @param os_if network interface data
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init_mesh(struct os_interface *os_if) {
  char procfile[FILENAME_MAX];
  char old_redirect = 0, old_spoof = 0;

  if (os_if->flags.loopback || os_if->flags.any) {
    /* ignore loopback and unspecific interface*/
    return 0;
  }

  /* handle global ip_forward setting */
  _mesh_count++;
  if (_mesh_count == 1) {
    _activate_if_routing();
  }

  /* Generate the procfile name */
  snprintf(procfile, sizeof(procfile), PROC_IF_REDIRECT, os_if->name);

  if (_os_linux_writeToFile(procfile, &old_redirect, '0')) {
    OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not disable ICMP redirects! "
        "You should manually ensure that ICMP redirects are disabled!");
  }

  /* Generate the procfile name */
  snprintf(procfile, sizeof(procfile), PROC_IF_SPOOF, os_if->name);

  if (_os_linux_writeToFile(procfile, &old_spoof, '0')) {
    OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not disable the IP spoof filter! "
        "You should mannually ensure that IP spoof filtering is disabled!");
  }

  os_if->_internal._original_state = (old_redirect << 8) | (old_spoof);
  return 0;
}

/**
 * Query a dump of all interface link data
 */
static void
_query_interface_links(void) {
  uint8_t buffer[UIO_MAXIOV];
  struct nlmsghdr *msg;
  struct ifinfomsg *ifi;
#if defined(OONF_LOG_DEBUG_INFO)
#endif

  if (_link_query_in_progress || _address_query_in_progress) {
    return;
  }

  OONF_DEBUG(LOG_OS_INTERFACE, "Request all interfaces");

  _trigger_link_query = false;

  /* get pointers for netlink message */
  msg = (void *)&buffer[0];

  /* get link level data */
  memset(buffer, 0, sizeof(buffer));
  msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
  msg->nlmsg_type = RTM_GETLINK;

  /* set length of netlink message with ifinfomsg payload */
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(*ifi));

  ifi = NLMSG_DATA(msg);
  ifi->ifi_family = AF_NETLINK;

  /* we don't care for the sequence number */
  os_system_linux_netlink_send(&_rtnetlink_if_query, msg);
}

/**
 * Query a dump of all interface link data
 */
static void
_query_interface_addresses(void) {
  uint8_t buffer[UIO_MAXIOV];
  struct nlmsghdr *msg;
  struct ifaddrmsg *ifa;

  if (_link_query_in_progress || _address_query_in_progress) {
    return;
  }

  _trigger_address_query = false;

  OONF_DEBUG(LOG_OS_INTERFACE, "Request all interfaces");

  /* get pointers for netlink message */
  msg = (void *)&buffer[0];

  /* get IP level data */
  memset(buffer, 0, sizeof(buffer));
  msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
  msg->nlmsg_type = RTM_GETADDR;

  /* set length of netlink message with ifaddrmsg payload */
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(*ifa));

  ifa = NLMSG_DATA(msg);
  ifa->ifa_family = AF_UNSPEC;

  /* we don't care for the sequence number */
  os_system_linux_netlink_send(&_rtnetlink_if_query, msg);
}

/**
 * Cleanup interface after mesh usage
 * @param data network interface data
 */
static void
_cleanup_mesh(struct os_interface *os_if) {
  char restore_redirect, restore_spoof;
  char procfile[FILENAME_MAX];

  if (os_if->flags.loopback || os_if->flags.any) {
    /* ignore loopback and unspecific interface*/
    return;
  }

  restore_redirect = (os_if->_internal._original_state >> 8) & 255;
  restore_spoof = (os_if->_internal._original_state & 255);

  /* Generate the procfile name */
  snprintf(procfile, sizeof(procfile), PROC_IF_REDIRECT, os_if->name);

  if (_os_linux_writeToFile(procfile, NULL, restore_redirect) != 0) {
    OONF_WARN(LOG_OS_INTERFACE, "Could not restore ICMP redirect flag %s to %c",
        procfile, restore_redirect);
  }

  /* Generate the procfile name */
  snprintf(procfile, sizeof(procfile), PROC_IF_SPOOF, os_if->name);

  if (_os_linux_writeToFile(procfile, NULL, restore_spoof) != 0) {
    OONF_WARN(LOG_OS_INTERFACE, "Could not restore IP spoof flag %s to %c",
        procfile, restore_spoof);
  }

  /* handle global ip_forward setting */
  _mesh_count--;
  if (_mesh_count == 0) {
    _deactivate_if_routing();
  }

  os_if->_internal._original_state = 0;
  return;
}

/**
 * Set the required settings to allow multihop mesh routing
 */
static void
_activate_if_routing(void) {
  if (_os_linux_writeToFile(PROC_IPFORWARD_V4, &_original_ipv4_forward, '1')) {
    OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not activate ip_forward for ipv4! "
        "You should manually ensure that ip_forward for ipv4 is activated!");
  }
  if (os_system_is_ipv6_supported()) {
    if(_os_linux_writeToFile(PROC_IPFORWARD_V6, &_original_ipv6_forward, '1')) {
      OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not activate ip_forward for ipv6! "
          "You should manually ensure that ip_forward for ipv6 is activated!");
    }
  }

  if (_os_linux_writeToFile(PROC_ALL_REDIRECT, &_original_icmp_redirect, '0')) {
    OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not disable ICMP redirects! "
        "You should manually ensure that ICMP redirects are disabled!");
  }

  /* check kernel version and disable global rp_filter */
  if (_is_kernel_2_6_31_or_better) {
    if (_os_linux_writeToFile(PROC_ALL_SPOOF, &_original_rp_filter, '0')) {
      OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not disable global rp_filter "
          "(necessary for kernel 2.6.31 and newer)! You should manually "
          "ensure that rp_filter is disabled!");
    }
  }
}

/**
 * Reset the multihop mesh routing settings to default
 */
static void
_deactivate_if_routing(void) {
  if (_os_linux_writeToFile(PROC_ALL_REDIRECT, NULL, _original_icmp_redirect) != 0) {
    OONF_WARN(LOG_OS_INTERFACE,
        "WARNING! Could not restore ICMP redirect flag %s to %c!",
        PROC_ALL_REDIRECT, _original_icmp_redirect);
  }

  if (_os_linux_writeToFile(PROC_ALL_SPOOF, NULL, _original_rp_filter)) {
    OONF_WARN(LOG_OS_INTERFACE,
        "WARNING! Could not restore global rp_filter flag %s to %c!",
        PROC_ALL_SPOOF, _original_rp_filter);
  }

  if (_os_linux_writeToFile(PROC_IPFORWARD_V4, NULL, _original_ipv4_forward)) {
    OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not restore %s to %c!",
        PROC_IPFORWARD_V4, _original_ipv4_forward);
  }
  if (os_system_is_ipv6_supported()) {
    if (_os_linux_writeToFile(PROC_IPFORWARD_V6, NULL, _original_ipv6_forward)) {
      OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not restore %s to %c",
          PROC_IPFORWARD_V6, _original_ipv6_forward);
    }
  }
}


/**
 * Overwrite a numeric entry in the procfile system and keep the old
 * value.
 * @param file pointer to filename (including full path)
 * @param old pointer to memory to store old value
 * @param value new value
 * @return -1 if an error happened, 0 otherwise
 */
static int
_os_linux_writeToFile(const char *file, char *old, char value) {
  int fd;
  char rv;

  if (value == 0) {
    /* ignore */
    return 0;
  }

  if ((fd = open(file, O_RDWR)) < 0) {
    OONF_WARN(LOG_OS_INTERFACE,
      "Error, cannot open proc entry %s: %s (%d)\n",
      file, strerror(errno), errno);
    return -1;
  }

  if (read(fd, &rv, 1) != 1) {
    OONF_WARN(LOG_OS_INTERFACE,
      "Error, cannot read proc entry %s: %s (%d)\n",
      file, strerror(errno), errno);
    close(fd);
    return -1;
  }

  if (rv != value) {
    if (lseek(fd, SEEK_SET, 0) == -1) {
      OONF_WARN(LOG_OS_INTERFACE,
        "Error, cannot rewind to start on proc entry %s: %s (%d)\n",
        file, strerror(errno), errno);
      close(fd);
      return -1;
    }

    if (write(fd, &value, 1) != 1) {
      OONF_WARN(LOG_OS_INTERFACE,
        "Error, cannot write '%c' to proc entry %s: %s (%d)\n",
        value, file, strerror(errno), errno);
    }

    OONF_DEBUG(LOG_OS_INTERFACE, "Writing '%c' (was %c) to %s", value, rv, file);
  }

  close(fd);

  if (old && rv != value) {
    *old = rv;
  }

  return 0;
}

/**
 * Trigger all change listeners of a network interface
 * @param os_if network interface
 */
static void
_trigger_if_change(struct os_interface *os_if) {
  struct os_interface_listener *if_listener;

  if (!oonf_timer_is_active(&os_if->_change_timer)) {
    /* inform listeners the interface changed */
    oonf_timer_start(&os_if->_change_timer, 200);

    list_for_each_element(&os_if->_listeners, if_listener, _node) {
      /* each interface should be informed */
      if_listener->_dirty = true;
    }
  }
}

/**
 * Trigger all change listeners of a network interface.
 * Trigger also all change listeners of the wildcard interface "any"
 * @param os_if network interface
 */
static void
_trigger_if_change_including_any(struct os_interface *os_if) {
  _trigger_if_change(os_if);

  os_if = avl_find_element(
      &_interface_data_tree, OS_INTERFACE_ANY, os_if, _node);
  if (os_if) {
    _trigger_if_change(os_if);
  }
}

/**
 * Parse an incoming LINK information from netlink
 * @param ifname interface name
 * @param msg netlink message
 */
static void
_link_parse_nlmsg(const char *ifname, struct nlmsghdr *msg) {
  struct ifinfomsg *ifi_msg;
  struct rtattr *ifi_attr;
  int ifi_len;
  struct netaddr addr;
  struct os_interface *ifdata;
  int iflink;
#if defined(OONF_LOG_DEBUG_INFO)
  struct netaddr_str nbuf;
#endif

  ifi_msg = NLMSG_DATA(msg);
  ifi_attr = (struct rtattr *) IFLA_RTA(ifi_msg);
  ifi_len = RTM_PAYLOAD(msg);

  ifdata = avl_find_element(&_interface_data_tree, ifname, ifdata, _node);
  if (!ifdata) {
    return;
  }

  ifdata->flags.up = (ifi_msg->ifi_flags & IFF_UP) != 0;
  ifdata->flags.promisc = (ifi_msg->ifi_flags & IFF_PROMISC) != 0;
  ifdata->flags.pointtopoint = (ifi_msg->ifi_flags & IFF_POINTOPOINT) != 0;
  ifdata->flags.loopback = (ifi_msg->ifi_flags & IFF_LOOPBACK) != 0;

  OONF_DEBUG(LOG_OS_INTERFACE, "Parse IFI_LINK %s (%u): %c%c%c%c",
      ifname, ifi_msg->ifi_index,
      ifdata->flags.up ? 'u' : '-',
      ifdata->flags.promisc ? 'p' : '-',
      ifdata->flags.pointtopoint ? 'P' : '-',
      ifdata->flags.loopback ? 'l' : '-');

  ifdata->index = ifi_msg->ifi_index;

  for(; RTA_OK(ifi_attr, ifi_len); ifi_attr = RTA_NEXT(ifi_attr,ifi_len)) {
    switch(ifi_attr->rta_type) {
      case IFLA_ADDRESS:
        netaddr_from_binary(&addr, RTA_DATA(ifi_attr), RTA_PAYLOAD(ifi_attr), AF_MAC48);
        OONF_DEBUG(LOG_OS_INTERFACE, "Link: %s", netaddr_to_string(&nbuf, &addr));

        if (msg->nlmsg_type == RTM_NEWLINK) {
          memcpy(&ifdata->mac, &addr, sizeof(addr));
        }
        break;
      case IFLA_LINK:
        memcpy(&iflink, RTA_DATA(ifi_attr), RTA_PAYLOAD(ifi_attr));

        OONF_INFO(LOG_OS_INTERFACE, "Base interface index for %s (%u): %u",
            ifdata->name, ifdata->index, iflink);
        ifdata->base_index = iflink;
        break;
      default:
        //OONF_DEBUG(LOG_OS_INTERFACE, "ifi_attr_type: %u", ifi_attr->rta_type);
        break;
    }
  }

  _trigger_if_change_including_any(ifdata);
}

/**
 * Update the links for routable/ll addresses of a network interface
 * @param os_if network interface
 */
static void
_update_address_shortcuts(struct os_interface *os_if) {
  struct os_interface_ip *ip;
  bool ipv4_ll, ipv6_ll, ipv4_routable, ipv6_routable;

  /* update address shortcuts */
  os_if->if_v4 = &NETADDR_UNSPEC;
  os_if->if_v6 = &NETADDR_UNSPEC;
  os_if->if_linklocal_v4 = &NETADDR_UNSPEC;
  os_if->if_linklocal_v6 = &NETADDR_UNSPEC;

  avl_for_each_element(&os_if->addresses, ip, _node) {
    ipv4_ll = netaddr_is_in_subnet(&ip->address, &NETADDR_IPV4_LINKLOCAL);
    ipv6_ll = netaddr_is_in_subnet(&ip->address, &NETADDR_IPV6_LINKLOCAL);

    ipv4_routable = !ipv4_ll
        && netaddr_get_address_family(&ip->address) == AF_INET
        && !netaddr_is_in_subnet(&ip->address, &NETADDR_IPV4_LOOPBACK_NET)
        && !netaddr_is_in_subnet(&ip->address, &NETADDR_IPV4_MULTICAST);
    ipv6_routable = !ipv4_ll
        && (netaddr_is_in_subnet(&ip->address, &NETADDR_IPV6_ULA)
            || netaddr_is_in_subnet(&ip->address, &NETADDR_IPV6_GLOBAL));

    if (netaddr_is_unspec(os_if->if_v4) && ipv4_routable) {
      os_if->if_v4 = &ip->address;
    }
    if (netaddr_is_unspec(os_if->if_v6) && ipv6_routable) {
      os_if->if_v6 = &ip->address;
    }
    if (netaddr_is_unspec(os_if->if_linklocal_v4) && ipv4_ll) {
      os_if->if_linklocal_v4 = &ip->address;
    }
    if (netaddr_is_unspec(os_if->if_linklocal_v6) && ipv6_ll) {
      os_if->if_linklocal_v6 = &ip->address;
    }
  }
}

/**
 * Add an IP address/prefix to a network interface
 * @param os_if network interface
 * @param prefixed_addr full IP address with prefix length
 */
static void
_add_address(struct os_interface *os_if, struct netaddr *prefixed_addr) {
  struct os_interface_ip *ip;
#if defined(OONF_LOG_INFO)
  struct netaddr_str nbuf;
#endif

  ip = avl_find_element(&os_if->addresses, prefixed_addr, ip, _node);
  if (!ip) {
    ip = oonf_class_malloc(&_interface_ip_class);
    if (!ip) {
      return;
    }

    /* establish key and add to tree */
    memcpy(&ip->prefixed_addr, prefixed_addr, sizeof(*prefixed_addr));
    ip->_node.key = &ip->prefixed_addr;
    avl_insert(&os_if->addresses, &ip->_node);

    /* add back pointer */
    ip->interf = os_if;
  }

  OONF_INFO(LOG_OS_INTERFACE, "Add address to %s: %s",
      os_if->name, netaddr_to_string(&nbuf, prefixed_addr));

  /* copy sanitized addresses */
  memcpy(&ip->address, prefixed_addr, sizeof(*prefixed_addr));
  netaddr_set_prefix_length(&ip->address, netaddr_get_maxprefix(&ip->address));
  netaddr_truncate(&ip->prefix, prefixed_addr);
}

/**
 * Remove an IP address/prefix from a network interface
 * @param os_if network interface
 * @param prefixed_addr full IP address with prefix length
 */
static void
_remove_address(struct os_interface *os_if, struct netaddr *prefixed_addr) {
  struct os_interface_ip *ip;
#if defined(OONF_LOG_INFO)
  struct netaddr_str nbuf;
#endif

  ip = avl_find_element(&os_if->addresses, prefixed_addr, ip, _node);
  if (!ip) {
    return;
  }

  OONF_INFO(LOG_OS_INTERFACE, "Remove address from %s: %s",
      os_if->name, netaddr_to_string(&nbuf, prefixed_addr));

  avl_remove(&os_if->addresses, &ip->_node);
  oonf_class_free(&_interface_ip_class, ip);
}

/**
 * Parse an incoming IP address information from netlink
 * @param ifname name of interface
 * @param msg netlink message
 */
static void
_address_parse_nlmsg(const char *ifname, struct nlmsghdr *msg) {
  struct ifaddrmsg *ifa_msg;
  struct rtattr *ifa_attr;
  int ifa_len;
  struct os_interface *ifdata;
  struct netaddr addr;
  bool update;

  ifa_msg = NLMSG_DATA(msg);
  ifa_attr = IFA_RTA(ifa_msg);
  ifa_len = RTM_PAYLOAD(msg);

  ifdata = avl_find_element(&_interface_data_tree, ifname, ifdata, _node);
  if (!ifdata) {
    return;
  }

  OONF_DEBUG(LOG_OS_INTERFACE, "Parse IFA_GETADDR %s (%u) (len=%u)",
      ifname, ifa_msg->ifa_index, ifa_len);

  update = false;
  for(; RTA_OK(ifa_attr, ifa_len); ifa_attr = RTA_NEXT(ifa_attr,ifa_len)) {
    switch(ifa_attr->rta_type) {
      case IFA_ADDRESS:
        netaddr_from_binary_prefix(&addr, RTA_DATA(ifa_attr), RTA_PAYLOAD(ifa_attr), 0,
            ifa_msg->ifa_prefixlen);
        if (msg->nlmsg_type == RTM_NEWADDR) {
          _add_address(ifdata, &addr);
        }
        else {
          _remove_address(ifdata, &addr);
        }
        update = true;
        break;
      default:
        OONF_DEBUG(LOG_OS_INTERFACE, "ifa_attr_type: %u", ifa_attr->rta_type);
        break;
    }
  }

  if (update) {
    _update_address_shortcuts(ifdata);
  }

  _trigger_if_change_including_any(ifdata);
}

/**
 * Handle incoming rtnetlink multicast messages for interface listeners
 * @param hdr pointer to netlink message
 */
static void
_cb_rtnetlink_message(struct nlmsghdr *hdr) {
  struct ifinfomsg *ifi;
  struct ifaddrmsg *ifa;
  char ifname[IF_NAMESIZE];

  if (hdr->nlmsg_type == RTM_NEWLINK || hdr->nlmsg_type == RTM_DELLINK) {
    ifi = (struct ifinfomsg *) NLMSG_DATA(hdr);
    if (!if_indextoname(ifi->ifi_index, ifname)) {
      return;
    }

    OONF_DEBUG(LOG_OS_INTERFACE, "Linkstatus of interface (%s) %d changed",
        ifname, ifi->ifi_index);
    _link_parse_nlmsg(ifname, hdr);
  }

  else if (hdr->nlmsg_type == RTM_NEWADDR || hdr->nlmsg_type == RTM_DELADDR) {
    ifa = (struct ifaddrmsg *) NLMSG_DATA(hdr);
    if (!if_indextoname(ifa->ifa_index, ifname)) {
      return;
    }

    OONF_DEBUG(LOG_OS_INTERFACE, "Address of interface %s (%u) changed",
        ifname, ifa->ifa_index);
    _address_parse_nlmsg(ifname, hdr);
  }
  else {
    OONF_DEBUG(LOG_OS_INTERFACE, "Message type: %u", hdr->nlmsg_type);
  }
}

/**
 * Handle feedback from netlink socket
 * @param seq sequence number of netlink message
 * @param error error code
 */
static void
_cb_rtnetlink_error(uint32_t seq, int error) {
  struct os_interface_ip_change *addr;

  OONF_INFO(LOG_OS_INTERFACE, "Netlink socket provided feedback: %d %d", seq, error);

  /* transform into errno number */
  list_for_each_element(&_rtnetlink_feedback, addr, _internal._node) {
    if (seq == addr->_internal.nl_seq) {
      _address_finished(addr, error);
      break;
    }
  }
}

/**
 * Handle ack timeout from netlink socket
 */
static void
_cb_rtnetlink_timeout(void) {
  struct os_interface_ip_change *addr;

  OONF_INFO(LOG_OS_INTERFACE, "Netlink socket timed out");

  list_for_each_element(&_rtnetlink_feedback, addr, _internal._node) {
    _address_finished(addr, -1);
  }
}

/**
 * Handle done from multipart netlink messages
 * @param seq sequence number of netlink message
 */
static void
_cb_rtnetlink_done(uint32_t seq) {
  struct os_interface_ip_change *addr;

  OONF_INFO(LOG_OS_INTERFACE, "Netlink operation finished: %u", seq);

  list_for_each_element(&_rtnetlink_feedback, addr, _internal._node) {
    if (seq == addr->_internal.nl_seq) {
      _address_finished(addr, 0);
      break;
    }
  }
}

/**
 * Stop processing of an ip address command and set error code
 * for callback
 * @param addr pointer to os_system_address
 * @param error error code, 0 if no error
 */
static void
_address_finished(struct os_interface_ip_change *addr, int error) {
  if (list_is_node_added(&addr->_internal._node)) {
    /* remove first to prevent any kind of recursive cleanup */
    list_remove(&addr->_internal._node);

    if (addr->cb_finished) {
      addr->cb_finished(addr, error);
    }
  }
}

/**
 * Handle switching between netlink query for links and addresses
 */
static void
_process_end_of_query(void) {
  if (_link_query_in_progress) {
    _link_query_in_progress = false;

    if (_trigger_address_query) {
      _query_interface_addresses();
    }
    else if (_trigger_link_query) {
      _query_interface_links();
    }
  }
  else {
    _address_query_in_progress = false;

    if (_trigger_link_query) {
      _query_interface_links();
    }
    else if (_trigger_address_query) {
      _query_interface_addresses();
    }
  }
}

/**
 * Handle a netlink query that did not work out
 */
static void
_process_bad_end_of_query(void) {
  /* reactivate query that has failed */
  if (_link_query_in_progress) {
    _trigger_link_query = true;
  }
  if (_address_query_in_progress) {
    _trigger_address_query = true;
  }
  _process_end_of_query();
}

/**
 * Handle an incoming netlink query error
 * @param seq sequence number of netlink message
 * @param error error code
 */
static void
_cb_query_error(uint32_t seq __attribute((unused)),
    int error __attribute((unused))) {
  _process_bad_end_of_query();
}

/**
 * Handle a successful netlink query
 * @param seq sequence number of netlink message
 */
static void
_cb_query_done(uint32_t seq __attribute((unused))) {
  _process_end_of_query();
}

/**
 * Handle a timeout of a netlink query
 */
static void
_cb_query_timeout(void) {
  _process_bad_end_of_query();
}

/**
 * Handle timer that announces interface state/address changes
 * @param timer timer instance
 */
static void
_cb_interface_changed(struct oonf_timer_instance *timer) {
  struct os_interface *data;
  struct os_interface_listener *interf, *interf_it;
  bool error;

  data = container_of(timer, struct os_interface, _change_timer);

  OONF_INFO(LOG_OS_INTERFACE, "Interface %s (%u) changed",
      data->name, data->index);

  error = false;
  list_for_each_element_safe(&data->_listeners, interf, _node, interf_it) {
    if (!interf->_dirty) {
      continue;
    }

    if (interf->if_changed && interf->if_changed(interf)) {
      /* interface change handler had a problem and wants to re-trigger */
      error = true;
    }
    else {
      /* everything fine, job done */
      interf->_dirty = false;
    }
  }

  if (error) {
    /* re-trigger */
    oonf_timer_start(timer, 200);
  }
}

/**
 * Transform remaining parameters into interface sections
 * @param arg command line parameter
 * @return always 0 (ok)
 */
static int
_handle_unused_parameter(const char *arg) {
  cfg_db_add_namedsection(oonf_cfg_get_rawdb(), CFG_INTERFACE_SECTION, arg);
  return 0;
}
