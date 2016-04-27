
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

#include "common/avl.h"
#include "common/common_types.h"
#include "common/list.h"
#include "config/cfg_schema.h"
#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_clock.h"
#include "subsystems/oonf_layer2.h"
#include "subsystems/oonf_rfc5444.h"
#include "subsystems/oonf_timer.h"
#include "subsystems/os_interface.h"

#include "nhdp/nhdp_db.h"
#include "nhdp/nhdp_interfaces.h"

#include "neighbor_probing/neighbor_probing.h"

/* definitions and constants */
#define LOG_PROBING _olsrv2_neighbor_probing_subsystem.logging

/**
 * Configuration of neighbor probing plugin
 */
struct _config {
  /*! Interval between two link probes */
  uint64_t interval;

  /*! size of probe */
  int32_t probe_size;

  /*! true to probe all DLEP interfaces */
  bool probe_dlep;
};

/**
 * NHDP link extension for neighbor probing plugin
 */
struct _probing_link_data {
  /*! absolute timestamp of last check if probing is necessary */
  uint64_t last_probe_check;

  /**
   * number of bytes that had been sent to neighbor during last
   * probe check.
   */
  uint64_t last_tx_traffic;

  /**
   * pointer to RFC5444 target allocated for link neighbor
   */
  struct oonf_rfc5444_target *target;
};

/* prototypes */
static int _init(void);
static void _cleanup(void);
static void _cb_link_removed(void *);
static void _cb_probe_link(struct oonf_timer_instance *);
static int _cb_addMessageHeader(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *msg);
static void _cb_addMessageTLVs(struct rfc5444_writer *);
static void _cb_cfg_changed(void);

/* plugin declaration */
static struct cfg_schema_entry _probing_entries[] = {
  CFG_MAP_CLOCK_MIN(_config, interval, "interval", "0.2",
      "Time interval between link probing", 100),
  CFG_MAP_INT32_MINMAX(_config, probe_size, "size", "512",
      "Number of bytes used for neighbor probe",
      0, false, 1, 1500),
  CFG_MAP_BOOL(_config, probe_dlep, "probe_dlep", "true",
      "Probe DLEP interfaces in addition to wireless interfaces"),
};

static struct cfg_schema_section _probing_section = {
  .type = OONF_NEIGHBOR_PROBING_SUBSYSTEM,
  .cb_delta_handler = _cb_cfg_changed,
  .entries = _probing_entries,
  .entry_count = ARRAYSIZE(_probing_entries),
};

static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_CLOCK_SUBSYSTEM,
  OONF_LAYER2_SUBSYSTEM,
  OONF_RFC5444_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_OS_INTERFACE_SUBSYSTEM,
  OONF_NHDP_SUBSYSTEM,
};
static struct oonf_subsystem _olsrv2_neighbor_probing_subsystem = {
  .name = OONF_NEIGHBOR_PROBING_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OLSRv2 Neighbor Probing plugin",
  .author = "Henning Rogge",

  .cfg_section = &_probing_section,

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_olsrv2_neighbor_probing_subsystem);

static struct _config _probe_config;

/* storage extension and listeners */
static struct oonf_class_extension _link_extenstion = {
  .ext_name = "probing linkmetric",
  .class_name = NHDP_CLASS_LINK,
  .size = sizeof(struct _probing_link_data),
  .cb_remove = _cb_link_removed,
};

/* timer class to measure interval between probes */
static struct oonf_timer_class _probe_info = {
  .name = "Link probing timer",
  .callback = _cb_probe_link,
  .periodic = true,
};

static struct oonf_timer_instance _probe_timer = {
  .class = &_probe_info,
};

/* rfc5444 message handing for probing */
static struct oonf_rfc5444_protocol *_protocol;
static struct rfc5444_writer_message *_probing_message;

static struct rfc5444_writer_content_provider _probing_msg_provider = {
  .msg_type = RFC5444_MSGTYPE_PROBING,
  .addMessageTLVs = _cb_addMessageTLVs,
};

/**
 * Initialize plugin
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  _protocol = oonf_rfc5444_get_default_protocol();

  if (oonf_class_extension_add(&_link_extenstion)) {
    return -1;
  }

  _probing_message = rfc5444_writer_register_message(
      &_protocol->writer, RFC5444_MSGTYPE_PROBING, true);
  if (_probing_message == NULL) {
    oonf_rfc5444_remove_protocol(_protocol);
    oonf_class_extension_remove(&_link_extenstion);
    OONF_WARN(LOG_PROBING, "Could not register Probing message");
    return -1;
  }

  _probing_message->addMessageHeader = _cb_addMessageHeader;

  if (rfc5444_writer_register_msgcontentprovider(
      &_protocol->writer, &_probing_msg_provider, NULL, 0)) {

    OONF_WARN(LOG_PROBING, "Count not register Probing msg contentprovider");
    rfc5444_writer_unregister_message(&_protocol->writer, _probing_message);
    oonf_rfc5444_remove_protocol(_protocol);
    oonf_class_extension_remove(&_link_extenstion);
    return -1;
  }

  oonf_timer_add(&_probe_info);
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  rfc5444_writer_unregister_content_provider(
      &_protocol->writer, &_probing_msg_provider, NULL, 0);
  rfc5444_writer_unregister_message(
      &_protocol->writer, _probing_message);
  _protocol = NULL;
  oonf_timer_remove(&_probe_info);
  oonf_class_extension_remove(&_link_extenstion);
}

static void
_cb_link_removed(void *ptr) {
  struct _probing_link_data *ldata;

  ldata = oonf_class_get_extension(&_link_extenstion, ptr);
  if (ldata->target) {
    oonf_rfc5444_remove_target(ldata->target);
  }
}

static bool
_check_if_type(struct oonf_layer2_net *net) {
  if (net->if_type == OONF_LAYER2_TYPE_WIRELESS) {
    return true;
  }

  if (_probe_config.probe_dlep && net->if_type == OONF_LAYER2_TYPE_DLEP) {
    return true;
  }
  return false;
}

/**
 * Callback for triggering a new neighbor probe
 * @param ptr timer instance that fired
 */
static void
_cb_probe_link(struct oonf_timer_instance *ptr __attribute__((unused))) {
  struct nhdp_link *lnk, *best_lnk;
  struct _probing_link_data *ldata, *best_ldata;
  struct nhdp_interface *nhdp_if;

  struct os_interface_listener *if_listener;
  struct oonf_layer2_net *l2net;
  struct oonf_layer2_neigh *l2neigh;

  uint64_t points, best_points;
  uint64_t last_tx_packets;

#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  best_ldata = NULL;
  best_points = 0;

  OONF_DEBUG(LOG_PROBING, "Start looking for probe candidate");

  l2neigh = NULL;

  avl_for_each_element(nhdp_interface_get_tree(), nhdp_if, _node) {
    if_listener = nhdp_interface_get_if_listener(nhdp_if);

    l2net = oonf_layer2_net_get(if_listener->data->name);
    if (!l2net) {
      continue;
    }

    if(!_check_if_type(l2net)) {
      OONF_DEBUG(LOG_PROBING, "Drop interface %s (not wireless)",
          if_listener->data->name);
      continue;
    }

    OONF_DEBUG(LOG_PROBING, "Start looking for probe candidate in interface '%s'",
        if_listener->data->name);

    list_for_each_element(&nhdp_if->_links, lnk, _if_node) {
      if (lnk->status != NHDP_LINK_SYMMETRIC) {
        /* only probe symmetric neighbors */
        continue;
      }

      /* get layer2 data */
      l2neigh = oonf_layer2_neigh_get(l2net, &lnk->remote_mac);
      if (l2neigh == NULL
          || !oonf_layer2_has_value(&l2neigh->data[OONF_LAYER2_NEIGH_RX_BITRATE])
          || !oonf_layer2_has_value(&l2neigh->data[OONF_LAYER2_NEIGH_TX_FRAMES])) {
        OONF_DEBUG(LOG_PROBING, "Drop link %s (missing l2 data)",
            netaddr_to_string(&nbuf, &lnk->remote_mac));
        continue;
      }

      /* get link extension for probing */
      ldata = oonf_class_get_extension(&_link_extenstion, lnk);

      /* fix tx-packets */
      last_tx_packets = ldata->last_tx_traffic;
      ldata->last_tx_traffic = oonf_layer2_get_value(&l2neigh->data[OONF_LAYER2_NEIGH_TX_FRAMES]);

      /* check if link had traffic since last probe check */
      if (last_tx_packets != ldata->last_tx_traffic) {
        /* advance timestamp */
        ldata->last_probe_check = oonf_clock_getNow();
        OONF_DEBUG(LOG_PROBING, "Drop link %s (already has unicast traffic)",
            netaddr_to_string(&nbuf, &l2neigh->addr));
        continue;
      }

      points = oonf_clock_getNow() - ldata->last_probe_check;

      OONF_DEBUG(LOG_PROBING, "Link %s has %" PRIu64 " points",
          netaddr_to_string(&nbuf, &lnk->if_addr), points);

      if (points > best_points) {
        best_points = points;
        best_lnk = lnk;
        best_ldata = ldata;
      }
    }
  }

  if (best_ldata != NULL) {
    best_ldata->last_probe_check = oonf_clock_getNow();

    if (best_ldata->target == NULL
        && netaddr_get_address_family(&best_lnk->if_addr) != AF_UNSPEC) {
      best_ldata->target = oonf_rfc5444_add_target(
          best_lnk->local_if->rfc5444_if.interface, &best_lnk->if_addr);
    }

    if (best_ldata->target) {
      OONF_DEBUG(LOG_PROBING, "Send probing to %s",
          netaddr_to_string(&nbuf, &best_ldata->target->dst));

      oonf_rfc5444_send_if(best_ldata->target, RFC5444_MSGTYPE_PROBING);
    }
  }
}

static int
_cb_addMessageHeader(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *msg) {
  rfc5444_writer_set_msg_header(writer, msg, false, false, false, false);
  return RFC5444_OKAY;
}

static void
_cb_addMessageTLVs(struct rfc5444_writer *writer) {
  uint8_t data[1500];

  memset(data, 0, _probe_config.probe_size);
  rfc5444_writer_add_messagetlv(writer, RFC5444_MSGTLV_PROBING, 0,
      data, _probe_config.probe_size);
}

/**
 * Callback triggered when configuration changes
 */
static void
_cb_cfg_changed(void) {
  if (cfg_schema_tobin(&_probe_config, _probing_section.post,
      _probing_entries, ARRAYSIZE(_probing_entries))) {
    OONF_WARN(LOG_PROBING, "Cannot convert configuration for "
        OONF_NEIGHBOR_PROBING_SUBSYSTEM);
    return;
  }

  oonf_timer_set(&_probe_timer, _probe_config.interval);
}
