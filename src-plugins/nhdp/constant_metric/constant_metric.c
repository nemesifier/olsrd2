
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
#include <stdio.h>

#include "common/common_types.h"
#include "common/autobuf.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "config/cfg_schema.h"
#include "config/cfg_validate.h"
#include "core/oonf_cfg.h"
#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_rfc5444.h"
#include "subsystems/oonf_timer.h"
#include "subsystems/os_interface.h"

#include "nhdp/nhdp.h"
#include "nhdp/nhdp_domain.h"
#include "nhdp/nhdp_interfaces.h"

#include "constant_metric/constant_metric.h"

/* constants and definitions */
#define LOG_CONSTANT_METRIC _olsrv2_constant_metric_subsystem.logging

/**
 * Session data for a configured constant metric
 */
struct _linkcost {
  /*! hook into tree of configured metrics */
  struct avl_node _node;

  /*! name of interface */
  char if_name[IF_NAMESIZE];

  /*! neighbor IP the metric is restricted to, NULL if interface generic */
  struct netaddr neighbor;

  /*! configured metric */
  uint32_t cost;
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static void _cb_link_added(void *);
static void _cb_set_linkcost(struct oonf_timer_instance *);

static int _avlcmp_linkcost(const void *, const void *);

static int _cb_validate_link(const struct cfg_schema_entry *entry,
      const char *section_name, const char *value, struct autobuf *out);
static void _cb_cfg_changed(void);

/* plugin declaration */
static struct cfg_schema_entry _constant_entries[] = {
  _CFG_VALIDATE("link", "", "Defines the static cost to the link to a neighbor."
      " Value consists of the originator address (or '-' for all neighbors)"
      " followed by the link cost",
      .cb_validate = _cb_validate_link, .list = true),
};

static struct cfg_schema_section _constant_section = {
  .type = OONF_CONSTANT_METRIC_SUBSYSTEM,
  .mode = CFG_SSMODE_NAMED_WITH_DEFAULT,
  .def_name = OS_INTERFACE_ANY,
  .cb_delta_handler = _cb_cfg_changed,
  .entries = _constant_entries,
  .entry_count = ARRAYSIZE(_constant_entries),
};

static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_OS_INTERFACE_SUBSYSTEM,
  OONF_NHDP_SUBSYSTEM,
};
static struct oonf_subsystem _olsrv2_constant_metric_subsystem = {
  .name = OONF_CONSTANT_METRIC_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OLSRv2 Constant Metric plugin",
  .author = "Henning Rogge",

  .cfg_section = &_constant_section,

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_olsrv2_constant_metric_subsystem);

/* timer for handling new NHDP neighbors */
static struct oonf_timer_class _setup_timer_info = {
  .name = "Delayed update of constant NHDP neighbor linkcosts",
  .callback = _cb_set_linkcost,
  .periodic = false,
};

static struct oonf_timer_instance _setup_timer = {
  .class = &_setup_timer_info,
};

/* nhdp metric handler */
static struct nhdp_domain_metric _constant_metric_handler = {
  .name = OONF_CONSTANT_METRIC_SUBSYSTEM,
};

/* NHDP link listeners */
static struct oonf_class_extension _link_extenstion = {
  .ext_name = "constant linkmetric",
  .class_name = NHDP_CLASS_LINK,

  .cb_add = _cb_link_added,
};

/* storage for settings */
static struct oonf_class _linkcost_class = {
  .name = "Constant linkcost storage",
  .size = sizeof(struct _linkcost),
};

static struct avl_tree _linkcost_tree;

/**
 * Initialize plugin
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  if (nhdp_domain_metric_add(&_constant_metric_handler)) {
    return -1;
  }

  if (oonf_class_extension_add(&_link_extenstion)) {
    nhdp_domain_metric_remove(&_constant_metric_handler);
    return -1;
  }

  oonf_timer_add(&_setup_timer_info);
  oonf_class_add(&_linkcost_class);
  avl_init(&_linkcost_tree, _avlcmp_linkcost, false);
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  struct _linkcost *lk, *lk_it;

  avl_for_each_element_safe(&_linkcost_tree, lk, _node, lk_it) {
    avl_remove(&_linkcost_tree, &lk->_node);
    oonf_class_free(&_linkcost_class, lk);
  }

  oonf_timer_stop(&_setup_timer);
  oonf_timer_remove(&_setup_timer_info);

  oonf_class_remove(&_linkcost_class);

  oonf_class_extension_remove(&_link_extenstion);
  nhdp_domain_metric_remove(&_constant_metric_handler);
}

/**
 * Callback triggered when a new nhdp link is added
 * @param ptr nhdp link
 */
static void
_cb_link_added(void *ptr __attribute__((unused))) {
  oonf_timer_set(&_setup_timer, 1);
}

/**
 * Get the linkcost object for an interface/neighbor combination
 * @param ifname name of the interface
 * @param originator IP of the neighbor
 * @return linkcost object, NULL if not found
 */
static struct _linkcost *
_get_linkcost(const char *ifname, const struct netaddr *originator) {
  struct _linkcost key;
  struct _linkcost *entry;

  strscpy(key.if_name, ifname, IF_NAMESIZE);
  memcpy(&key.neighbor, originator, sizeof(struct netaddr));

  return avl_find_element(&_linkcost_tree, &key, entry, _node);
}

/**
 * Timer callback for delayed setting of new metric values into db
 * @param ptr timer instance that fired
 */
static void
_cb_set_linkcost(struct oonf_timer_instance *ptr __attribute__((unused))) {
  struct nhdp_link *lnk;
  struct _linkcost *entry;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  OONF_DEBUG(LOG_CONSTANT_METRIC, "Start setting constant linkcosts");
  list_for_each_element(nhdp_db_get_link_list(), lnk, _global_node) {
    const char *ifname;

    ifname = nhdp_interface_get_name(lnk->local_if);
    OONF_DEBUG(LOG_CONSTANT_METRIC, "Look for constant metric if=%s originator=%s",
        ifname, netaddr_to_string(&nbuf, &lnk->neigh->originator));

    if (netaddr_get_address_family(&lnk->neigh->originator) == AF_UNSPEC) {
      continue;
    }

    entry = _get_linkcost(ifname, &lnk->neigh->originator);
    if (entry == NULL && nhdp_db_link_is_dualstack(lnk)) {
      entry = _get_linkcost(ifname, &lnk->dualstack_partner->neigh->originator);
    }
    if (entry == NULL) {
      entry = _get_linkcost(OS_INTERFACE_ANY, &lnk->neigh->originator);
    }
    if (entry == NULL && nhdp_db_link_is_dualstack(lnk)) {
      entry = _get_linkcost(OS_INTERFACE_ANY,
          &lnk->dualstack_partner->neigh->originator);
    }
    if (entry == NULL)  {
      entry = _get_linkcost(ifname, &NETADDR_UNSPEC);
    }
    if (entry == NULL) {
      entry = _get_linkcost(OS_INTERFACE_ANY, &NETADDR_UNSPEC);
    }
    if (entry) {
      OONF_DEBUG(LOG_CONSTANT_METRIC, "Found metric value %u", entry->cost);
      nhdp_domain_set_incoming_metric(&_constant_metric_handler, lnk, entry->cost);
      continue;
    }
    else {
      nhdp_domain_set_incoming_metric(&_constant_metric_handler, lnk, RFC7181_METRIC_INFINITE);
    }
  }

  /* update neighbor metrics */
  nhdp_domain_neighborhood_changed();
}

/**
 * compare two linkcosts with each other by comparing
 * interface name and neighbor IP
 * @param ptr1
 * @param ptr2
 * @return
 */
static int
_avlcmp_linkcost(const void *ptr1, const void *ptr2) {
  const struct _linkcost *lk1, *lk2;
  int result;

  lk1 = ptr1;
  lk2 = ptr2;

  result = avl_comp_strcasecmp(&lk1->if_name, &lk2->if_name);
  if (result == 0) {
    result = avl_comp_netaddr(&lk1->neighbor, &lk2->neighbor);
  }
  return result;
}

/**
 * Validate configuration parameter for a constant metric
 * @param entry
 * @param section_name
 * @param value
 * @param out
 * @return
 */
static int
_cb_validate_link(const struct cfg_schema_entry *entry,
      const char *section_name, const char *value, struct autobuf *out) {
  struct isonumber_str sbuf;
  struct netaddr_str nbuf;
  const char *ptr;
  int8_t af[] = { AF_INET, AF_INET6, AF_UNSPEC };

  /* test if first word is a network address readable number */
  ptr = str_cpynextword(nbuf.buf, value, sizeof(nbuf));
  if (cfg_validate_netaddr(out, section_name, entry->key.entry, nbuf.buf,
      false, af, ARRAYSIZE(af))) {
    return -1;
  }

  /* test if second word is a human readable number */
  ptr = str_cpynextword(sbuf.buf, ptr, sizeof(sbuf));
  if (cfg_validate_int(out, section_name, entry->key.entry, sbuf.buf,
      RFC7181_METRIC_MIN, RFC7181_METRIC_MAX, 4, 0, false)) {
    return -1;
  }

  if (ptr) {
    cfg_append_printable_line(out, "Value '%s' for entry '%s'"
        " in section %s should have only an address and a link cost",
        value, entry->key.entry, section_name);
    return -1;
  }
  return 0;
}

/**
 * Callback triggered when configuration changes
 */
static void
_cb_cfg_changed(void) {
  struct _linkcost *lk, *lk_it;
  struct netaddr_str nbuf;
  const char *ptr, *cost_ptr;
  const struct const_strarray *array;
  int64_t cost;

  /* remove old entries for this interface */
  avl_for_each_element_safe(&_linkcost_tree, lk, _node, lk_it) {
    if (strcasecmp(lk->if_name, _constant_section.section_name) == 0) {
      avl_remove(&_linkcost_tree, &lk->_node);
      oonf_class_free(&_linkcost_class, lk);
    }
  }

  array = cfg_db_get_schema_entry_value(
      _constant_section.post, &_constant_entries[0]);
  if (!array) {
    OONF_WARN(LOG_CONSTANT_METRIC, "No link defined for static cost");
    return;
  }

  strarray_for_each_element(array, ptr) {
    lk = oonf_class_malloc(&_linkcost_class);
    if (lk) {
      cost_ptr = str_cpynextword(nbuf.buf, ptr, sizeof(nbuf));

      strscpy(lk->if_name, _constant_section.section_name, IF_NAMESIZE);
      if (netaddr_from_string(&lk->neighbor, nbuf.buf)) {
        oonf_class_free(&_linkcost_class, lk);
        continue;
      }
      if (isonumber_to_s64(&cost, cost_ptr, 0, false)) {
        oonf_class_free(&_linkcost_class, lk);
        continue;
      }

      lk->cost = cost;

      lk->_node.key = lk;
      avl_insert(&_linkcost_tree, &lk->_node);

      OONF_DEBUG(LOG_CONSTANT_METRIC, "Add entry (%s/%s: %s)",
          lk->if_name, nbuf.buf, cost_ptr);
    }
  }

  /* delay updating linkcosts */
  oonf_timer_set(&_setup_timer, 1);
}
