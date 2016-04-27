
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

#include <assert.h>

#include "common/common_types.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "common/container_of.h"
#include "common/netaddr.h"
#include "common/netaddr_acl.h"
#include "core/oonf_cfg.h"
#include "core/oonf_logging.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_rfc5444.h"
#include "subsystems/oonf_timer.h"
#include "subsystems/os_interface.h"

#include "nhdp/nhdp.h"
#include "nhdp/nhdp_db.h"
#include "nhdp/nhdp_interfaces.h"
#include "nhdp/nhdp_internal.h"
#include "nhdp/nhdp_writer.h"

/* Prototypes of local functions */
static void _addr_add(struct nhdp_interface *, struct netaddr *addr);
static void _addr_remove(struct nhdp_interface_addr *addr, uint64_t vtime);
static void _remove_addr(struct nhdp_interface_addr *ptr);
static void _cb_addr_timeout(struct oonf_timer_instance *ptr);

static int avl_comp_ifaddr(const void *k1, const void *k2);

static void _cb_generate_hello(struct oonf_timer_instance *ptr);
static void _cb_interface_event(struct oonf_rfc5444_interface_listener *, bool);

/* global tree of nhdp interfaces, filters and addresses */
static struct avl_tree _interface_tree;
static struct avl_tree _ifaddr_tree;

/* memory and timers for nhdp interface objects */
static struct oonf_class _interface_info = {
  .name = NHDP_CLASS_INTERFACE,
  .size = sizeof(struct nhdp_interface),
};

static struct oonf_timer_class _interface_hello_timer = {
  .name = "NHDP hello timer",
  .periodic = true,
  .callback = _cb_generate_hello,
};

static struct oonf_class _addr_info = {
  .name = NHDP_CLASS_INTERFACE_ADDRESS,
  .size = sizeof(struct nhdp_interface_addr),
};

static struct oonf_timer_class _removed_address_hold_timer = {
  .name = "NHDP interface removed address hold timer",
  .callback = _cb_addr_timeout,
};

/* other global variables */
static struct oonf_rfc5444_protocol *_protocol;

/**
 * Initialize NHDP interface subsystem
 * @param p rfc5444 protocol
 */
void
nhdp_interfaces_init(struct oonf_rfc5444_protocol *p) {
  avl_init(&_interface_tree, avl_comp_strcasecmp, false);
  avl_init(&_ifaddr_tree, avl_comp_ifaddr, true);
  oonf_class_add(&_interface_info);
  oonf_class_add(&_addr_info);
  oonf_timer_add(&_interface_hello_timer);
  oonf_timer_add(&_removed_address_hold_timer);

  /* default protocol should be always available */
  _protocol = p;
}

/**
 * Cleanup all allocated resources for nhdp interfaces
 */
void
nhdp_interfaces_cleanup(void) {
  struct nhdp_interface *interf, *if_it;

  avl_for_each_element_safe(&_interface_tree, interf, _node, if_it) {
    nhdp_interface_remove(interf);
  }

  oonf_timer_remove(&_interface_hello_timer);
  oonf_timer_remove(&_removed_address_hold_timer);
  oonf_class_remove(&_interface_info);
  oonf_class_remove(&_addr_info);
}

/**
 * Recalculates if IPv4 or IPv6 should be used on an interface
 * for flooding messages.
 * @param interf pointer to nhdp interface
 */
void
nhdp_interface_update_status(struct nhdp_interface *interf) {
  struct nhdp_link *lnk;
  int ipv4_only, ipv6_only, dualstack;

  ipv4_only = 0;
  ipv6_only = 0;
  dualstack = 0;

  list_for_each_element(&interf->_links, lnk, _if_node) {
    if (lnk->status != NHDP_LINK_SYMMETRIC) {
      /* link is not symmetric */
      continue;
    }

    if (lnk->dualstack_partner != NULL) {
      if (netaddr_get_address_family(&lnk->neigh->originator) == AF_INET) {
        /* count dualstack only once, not for IPv4 and IPv6 */
        dualstack++;
      }
      continue;
    }

    /* we have a non-dualstack node */
    if (netaddr_get_address_family(&lnk->neigh->originator) == AF_INET) {
      ipv4_only++;
    }
    else if (netaddr_get_address_family(&lnk->neigh->originator) == AF_INET6) {
      ipv6_only++;
    }
  }

  OONF_DEBUG(LOG_NHDP, "Interface %s: ipv4_only=%d ipv6_only=%d dualstack=%d",
      nhdp_interface_get_name(interf), ipv4_only, ipv6_only, dualstack);

  interf->use_ipv4_for_flooding = ipv4_only > 0;
  interf->use_ipv6_for_flooding =
      ipv6_only > 0 || (ipv4_only == 0 && dualstack > 0);

  interf->dualstack_af_type = AF_UNSPEC;
  if (dualstack > 0) {
    /* we have dualstack capable nodes */
    if (ipv4_only == 0) {
      /* use IPv6 for dualstack, we have no ipv4-only neighbors */
      interf->dualstack_af_type = AF_INET6;
    }
    else if (ipv6_only == 0) {
      /* use IPv4 for dualstack, we have no ipv6-only neighbors */
      interf->dualstack_af_type = AF_INET;
    }
  }

  OONF_DEBUG(LOG_NHDP, "Interface %s: floodv4=%d floodv6=%d dualstack=%d",
      nhdp_interface_get_name(interf),
      interf->use_ipv4_for_flooding, interf->use_ipv6_for_flooding,
      interf->dualstack_af_type);
}

/**
 * Add a nhdp interface
 * @param name name of interface
 * @return pointer to nhdp interface, NULL if out of memory
 */
struct nhdp_interface *
nhdp_interface_add(const char *name) {
  struct nhdp_interface *interf;

  interf = avl_find_element(&_interface_tree, name, interf, _node);
  if (interf == NULL) {
    interf = oonf_class_malloc(&_interface_info);
    if (interf == NULL) {
      OONF_WARN(LOG_NHDP, "No memory left for NHDP interface");
      return NULL;
    }

    interf->rfc5444_if.cb_interface_changed = _cb_interface_event;
    if (!oonf_rfc5444_add_interface(_protocol, &interf->rfc5444_if, name)) {
      oonf_class_free(&_interface_info, interf);
      OONF_WARN(LOG_NHDP, "Cannot allocate rfc5444 interface for %s", name);
      return NULL;
    }

    /* allocate core interface */
    interf->os_if_listener.name = interf->rfc5444_if.interface->name;
    os_interface_add(&interf->os_if_listener);

    /* initialize timers */
    interf->_hello_timer.class = &_interface_hello_timer;

    /* hook into global interface tree */
    interf->_node.key = interf->rfc5444_if.interface->name;
    avl_insert(&_interface_tree, &interf->_node);

    /* init address tree */
    avl_init(&interf->_if_addresses, avl_comp_netaddr, false);

    /* init link list */
    list_init_head(&interf->_links);

    /* init link address tree */
    avl_init(&interf->_link_addresses, avl_comp_netaddr, false);

    /*
     * init originator tree
     * (might temporarily have multiple links with the same originator)
     */
    avl_init(&interf->_link_originators, avl_comp_netaddr, true);

    /*
     * init twohop tree
     * (this tree allows duplicates to easily find all links to a
     * twohop link address)
     */
    avl_init(&interf->_if_twohops, avl_comp_netaddr, true);

    /* trigger event */
    oonf_class_event(&_interface_info, interf, OONF_OBJECT_ADDED);
  }

  OONF_INFO(LOG_NHDP, "Add interface to NHDP_interface tree: %s (refcount was %d)",
      name, interf->_refcount);

  /* keep track of users */
  interf->_refcount++;

  return interf;
}

/**
 * Mark a nhdp interface as removed and start cleanup timer
 * @param interf pointer to nhdp interface
 */
void
nhdp_interface_remove(struct nhdp_interface *interf) {
  struct nhdp_interface_addr *addr, *a_it;
  struct nhdp_link *lnk, *l_it;

  OONF_INFO(LOG_NHDP, "Remove interface to NHDP_interface tree: %s (refcount was %d)",
      nhdp_interface_get_name(interf), interf->_refcount);

  if (interf->_refcount > 1) {
    /* there are still users left */
    interf->_refcount--;
    return;
  }

  /* trigger event */
  oonf_class_event(&_interface_info, interf, OONF_OBJECT_REMOVED);

  /* free filter */
  netaddr_acl_remove(&interf->ifaddr_filter);

  /* stop Hellos */
  oonf_timer_stop(&interf->_hello_timer);

  avl_for_each_element_safe(&interf->_if_addresses, addr, _if_node, a_it) {
    _remove_addr(addr);
  }

  list_for_each_element_safe(&interf->_links, lnk, _if_node, l_it) {
    nhdp_db_link_set_unsymmetric(lnk);
  }

  /* remove first from tree because we use the interface name as a key */
  avl_remove(&_interface_tree, &interf->_node);

  /* now clean up the rest */
  os_interface_remove(&interf->os_if_listener);
  oonf_rfc5444_remove_interface(interf->rfc5444_if.interface, &interf->rfc5444_if);
  oonf_class_free(&_interface_info, interf);
}

/**
 * Apply the configuration settings of a NHDP interface
 * @param interf pointer to nhdp interface
 */
void
nhdp_interface_apply_settings(struct nhdp_interface *interf) {
  /* parse ip address list again and apply ACL */
  _cb_interface_event(&interf->rfc5444_if, false);

  /* reset hello generation frequency */
  oonf_timer_set(&interf->_hello_timer, interf->refresh_interval);

  /* just copy hold time for now */
  interf->l_hold_time = interf->h_hold_time;
  interf->n_hold_time = interf->l_hold_time;
  interf->i_hold_time = interf->n_hold_time;
}

/**
 * get tree of NHDP interfaces
 * @return interface tree
 */
struct avl_tree *
nhdp_interface_get_tree(void) {
  return &_interface_tree;
}

/**
 * get tree of NHDP interface addresses
 * @return interface address tree
 */
struct avl_tree *
nhdp_interface_get_address_tree(void) {
  return &_ifaddr_tree;
}


/**
 * Add a nhdp interface address to an interface
 * @param interf pointer to nhdp interface
 * @param if_addr address to add to interface
 */
void
_addr_add(struct nhdp_interface *interf, struct netaddr *addr) {
  struct nhdp_interface_addr *if_addr;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif
  OONF_DEBUG(LOG_NHDP, "Add address %s in NHDP interface %s",
      netaddr_to_string(&buf, addr), nhdp_interface_get_name(interf));

  if_addr = avl_find_element(&interf->_if_addresses, addr, if_addr, _if_node);
  if (if_addr == NULL) {
    if_addr = oonf_class_malloc(&_addr_info);
    if (if_addr == NULL) {
      OONF_WARN(LOG_NHDP, "No memory left for NHDP interface address");
      return;
    }

    memcpy(&if_addr->if_addr, addr, sizeof(*addr));

    if_addr->interf = interf;

    /* hook if-addr into interface and global tree */
    if_addr->_global_node.key = &if_addr->if_addr;
    avl_insert(&_ifaddr_tree, &if_addr->_global_node);

    if_addr->_if_node.key = &if_addr->if_addr;
    avl_insert(&interf->_if_addresses, &if_addr->_if_node);

    /* initialize validity timer for removed addresses */
    if_addr->_vtime.class = &_removed_address_hold_timer;

    /* trigger event */
    oonf_class_event(&_addr_info, if_addr, OONF_OBJECT_ADDED);
  }
  else {
    oonf_timer_stop(&if_addr->_vtime);
    if_addr->_to_be_removed = false;
    if_addr->removed = false;
  }
  return;
}

/**
 * Mark an interface address as removed
 * @param addr nhdp interface address
 * @param vtime time in milliseconds until address should be removed from db
 */
static void
_addr_remove(struct nhdp_interface_addr *addr, uint64_t vtime) {
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  OONF_DEBUG(LOG_NHDP, "Remove %s from NHDP interface %s",
      netaddr_to_string(&buf, &addr->if_addr), nhdp_interface_get_name(addr->interf));

  addr->removed = true;
  oonf_timer_set(&addr->_vtime, vtime);
}

/**
 * remove address from NHDP interface
 * @param ptr pointer to nhdp interface address
 */
static void
_remove_addr(struct nhdp_interface_addr *addr) {
  /* trigger event */
  oonf_class_event(&_addr_info, addr, OONF_OBJECT_REMOVED);

  oonf_timer_stop(&addr->_vtime);
  avl_remove(&_ifaddr_tree, &addr->_global_node);
  avl_remove(&addr->interf->_if_addresses, &addr->_if_node);
  oonf_class_free(&_addr_info, addr);
}

/**
 * Callback when an interface address times out
 * @param ptr timer instance that fired
 */
static void
_cb_addr_timeout(struct oonf_timer_instance *ptr) {
  struct nhdp_interface_addr *addr;

  addr = container_of(ptr, struct nhdp_interface_addr, _vtime);
  _remove_addr(addr);
}

/**
 * AVL tree comparator for netaddr objects.
 * @param k1 pointer to key 1
 * @param k2 pointer to key 2
 * @param ptr not used in this comparator
 * @return +1 if k1>k2, -1 if k1<k2, 0 if k1==k2
 */
static int
avl_comp_ifaddr(const void *k1, const void *k2) {
  const struct netaddr *n1 = k1;
  const struct netaddr *n2 = k2;

  if (netaddr_get_address_family(n1) > netaddr_get_address_family(n2)) {
    return 1;
  }
  if (netaddr_get_address_family(n1) < netaddr_get_address_family(n2)) {
    return -1;
  }

  return memcmp(n1, n2, 16);
}

/**
 * Callback triggered to generate a Hello on an interface
 * @param ptr timer instance that fired
 */
static void
_cb_generate_hello(struct oonf_timer_instance *ptr) {
  struct nhdp_interface *nhdp_if;

  nhdp_if = container_of(ptr, struct nhdp_interface, _hello_timer);
  nhdp_writer_send_hello(nhdp_if);
}

/**
 * Configuration of an interface changed,
 *  fix the nhdp addresses if necessary
 * @param ifl olsr rfc5444 interface listener
 * @param changed true if socket address changed
 */
static void
_cb_interface_event(struct oonf_rfc5444_interface_listener *ifl,
    bool changed __attribute__((unused))) {
  struct nhdp_interface *interf;
  struct nhdp_interface_addr *addr, *addr_it;
  struct os_interface_listener *if_listener;
  struct nhdp_link *nhdp_link, *nhdp_link_it;
  struct os_interface_ip *os_ip;
  bool has_active_addr;
  bool ipv4, ipv6;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  OONF_DEBUG(LOG_NHDP, "NHDP Interface change event: %s", ifl->interface->name);

  interf = container_of(ifl, struct nhdp_interface, rfc5444_if);

  /* mark all old addresses */
  avl_for_each_element_safe(&interf->_if_addresses, addr, _if_node, addr_it) {
    addr->_to_be_removed = true;
  }

  has_active_addr = false;

  if_listener = oonf_rfc5444_get_core_if_listener(ifl->interface);
  if (if_listener != NULL && if_listener->data && if_listener->data->flags.up) {
    ipv4 = oonf_rfc5444_is_target_active(interf->rfc5444_if.interface->multicast4);
    ipv6 = oonf_rfc5444_is_target_active(interf->rfc5444_if.interface->multicast6);

    /* get all socket addresses that are matching the filter */
    avl_for_each_element(&if_listener->data->addresses, os_ip, _node) {
      OONF_DEBUG(LOG_NHDP, "Found interface address %s",
          netaddr_to_string(&nbuf, &os_ip->address));

      if (netaddr_get_address_family(&os_ip->address) == AF_INET && !ipv4) {
        /* ignore IPv4 addresses if ipv4 socket is not up*/
        continue;
      }
      if (netaddr_get_address_family(&os_ip->address) == AF_INET6 && !ipv6) {
        /* ignore IPv6 addresses if ipv6 socket is not up*/
        continue;
      }

      /* check if IP address fits to ACL */
      if (netaddr_acl_check_accept(&interf->ifaddr_filter, &os_ip->address)) {
        _addr_add(interf, &os_ip->address);
        has_active_addr = true;
      }
    }
  }

  /* remove outdated socket addresses */
  avl_for_each_element_safe(&interf->_if_addresses, addr, _if_node, addr_it) {
    if (addr->_to_be_removed && !addr->removed) {
      addr->_to_be_removed = false;
      _addr_remove(addr, interf->i_hold_time);
    }
  }

  /* interface not active anymore, remove its links */
  if (!has_active_addr) {
    list_for_each_element_safe(&interf->_links, nhdp_link, _if_node, nhdp_link_it) {
      nhdp_db_link_set_unsymmetric(nhdp_link);
    }
  }
}
