
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

#include "common/common_types.h"
#include "common/avl.h"
#include "common/autobuf.h"
#include "core/oonf_logging.h"

#include "subsystems/oonf_layer2.h"
#include "subsystems/oonf_class.h"

#include "dlep/dlep_iana.h"
#include "dlep/dlep_extension.h"
#include "dlep/dlep_reader.h"
#include "dlep/dlep_session.h"
#include "dlep/dlep_writer.h"
#include "dlep/radio/dlep_radio_interface.h"
#include "dlep/radio/dlep_radio_session.h"

#include "dlep/ext_base_proto/proto.h"
#include "dlep/ext_base_proto/proto_radio.h"

static void _cb_init_radio(struct dlep_session *);
static void _cb_cleanup_radio(struct dlep_session *);

static int _radio_process_peer_discovery(struct dlep_extension *, struct dlep_session *);
static int _radio_process_peer_init(struct dlep_extension *, struct dlep_session *);
static int _radio_process_peer_update(struct dlep_extension *, struct dlep_session *);
static int _radio_process_peer_update_ack(struct dlep_extension *, struct dlep_session *);
static int _radio_process_destination_up(struct dlep_extension *, struct dlep_session *);
static int _radio_process_destination_up_ack(struct dlep_extension *, struct dlep_session *);
static int _radio_process_destination_down(struct dlep_extension *, struct dlep_session *);
static int _radio_process_destination_down_ack(struct dlep_extension *, struct dlep_session *);
static int _radio_process_destination_update(struct dlep_extension *, struct dlep_session *);
static int _radio_process_link_char_request(struct dlep_extension *, struct dlep_session *);

static int _radio_write_peer_offer(struct dlep_extension *,
    struct dlep_session *session, const struct netaddr *);
static int _radio_write_peer_init_ack(struct dlep_extension *,
    struct dlep_session *session, const struct netaddr *);

static void _l2_neigh_added_to_session(struct dlep_session *session,
    struct oonf_layer2_neigh *l2neigh, const struct netaddr *mac);
static void _l2_neigh_added(struct oonf_layer2_neigh *l2neigh,
      struct oonf_layer2_destination *l2dest, const struct netaddr *mac);

static void _cb_l2_neigh_added(void *);
static void _cb_l2_neigh_changed(void *);
static void _cb_l2_neigh_removed(void *);

static void _cb_l2_dst_added(void *);
static void _cb_l2_dst_removed(void *);

static void _cb_destination_timeout(struct dlep_session *,
    struct dlep_local_neighbor *);

static struct dlep_extension_implementation _radio_signals[] = {
    {
        .id = DLEP_PEER_DISCOVERY,
        .process = _radio_process_peer_discovery
    },
    {
        .id = DLEP_PEER_OFFER,
        .add_tlvs = _radio_write_peer_offer,
    },
    {
        .id = DLEP_PEER_INITIALIZATION,
        .process = _radio_process_peer_init,
    },
    {
        .id = DLEP_PEER_INITIALIZATION_ACK,
        .add_tlvs = _radio_write_peer_init_ack,
    },
    {
        .id = DLEP_PEER_UPDATE,
        .process = _radio_process_peer_update,
    },
    {
        .id = DLEP_PEER_UPDATE_ACK,
        .process = _radio_process_peer_update_ack,
    },
    {
        .id = DLEP_PEER_TERMINATION,
        .process = dlep_base_proto_process_peer_termination,
    },
    {
        .id = DLEP_PEER_TERMINATION_ACK,
        .process = dlep_base_proto_process_peer_termination_ack,
    },
    {
        .id = DLEP_DESTINATION_UP,
        .process = _radio_process_destination_up,
        .add_tlvs = dlep_base_proto_write_mac_only,
    },
    {
        .id = DLEP_DESTINATION_UP_ACK,
        .process = _radio_process_destination_up_ack,
        .add_tlvs = dlep_base_proto_write_mac_only,
    },
    {
        .id = DLEP_DESTINATION_DOWN,
        .process = _radio_process_destination_down,
        .add_tlvs = dlep_base_proto_write_mac_only,
    },
    {
        .id = DLEP_DESTINATION_DOWN_ACK,
        .process = _radio_process_destination_down_ack,
        .add_tlvs = dlep_base_proto_write_mac_only,
    },
    {
        .id = DLEP_DESTINATION_UPDATE,
        .process = _radio_process_destination_update,
        .add_tlvs = dlep_base_proto_write_mac_only,
    },
    {
        .id = DLEP_HEARTBEAT,
        .process = dlep_base_proto_process_heartbeat,
    },
    {
        .id = DLEP_LINK_CHARACTERISTICS_REQUEST,
        .process = _radio_process_link_char_request,
    },
};

static struct oonf_class_extension _layer2_neigh_listener = {
  .ext_name = "dlep radio",
  .class_name = LAYER2_CLASS_NEIGHBOR,

  .cb_add = _cb_l2_neigh_added,
  .cb_change = _cb_l2_neigh_changed,
  .cb_remove = _cb_l2_neigh_removed,
};

static struct oonf_class_extension _layer2_dst_listener = {
  .ext_name = "dlep radio",
  .class_name = LAYER2_CLASS_DESTINATION,

  .cb_add = _cb_l2_dst_added,
  .cb_remove = _cb_l2_dst_removed,
};

static struct dlep_extension *_base;

/**
 * Initialize the radios DLEP base protocol extension
 */
void
dlep_base_proto_radio_init(void) {
  _base = dlep_base_proto_init();
  dlep_extension_add_processing(_base, true,
      _radio_signals, ARRAYSIZE(_radio_signals));

  oonf_class_extension_add(&_layer2_neigh_listener);
  oonf_class_extension_add(&_layer2_dst_listener);

  _base->cb_session_init_radio = _cb_init_radio;
  _base->cb_session_cleanup_radio = _cb_cleanup_radio;
}

/**
 * Callback to initialize the radio session
 * @param session dlep session
 */
static void
_cb_init_radio(struct dlep_session *session) {
  if (session->restrict_signal == DLEP_PEER_INITIALIZATION) {
    /*
     * we are waiting for a Peer Init,
     */
    session->remote_heartbeat_interval = session->cfg.heartbeat_interval;
    dlep_base_proto_start_remote_heartbeat(session);
  }

  session->cb_destination_timeout = _cb_destination_timeout;
}

/**
 * Callback to cleanup the radio session
 * @param session dlep session
 */
static void
_cb_cleanup_radio(struct dlep_session *session) {
  dlep_base_proto_stop_timers(session);
}

/**
 * Process the peer discovery signal
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static int
_radio_process_peer_discovery(
    struct dlep_extension *ext __attribute__((unused)),
    struct dlep_session *session) {
  if (session->restrict_signal != DLEP_PEER_DISCOVERY) {
    /* ignore unless we are in discovery mode */
    return 0;
  }
  return dlep_session_generate_signal(session, DLEP_PEER_OFFER, NULL);
}

/**
 * Process the peer initialization message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static int
_radio_process_peer_init(
    struct dlep_extension *ext __attribute__((unused)),
    struct dlep_session *session) {
  struct oonf_layer2_net *l2net;
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_destination *l2dest;
  struct dlep_parser_value *value;
  const uint8_t *ptr;

#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  if (session->restrict_signal != DLEP_PEER_INITIALIZATION) {
    /* ignore unless we are in initialization mode */
    return 0;
  }

  /* mandatory heartbeat tlv */
  if (dlep_reader_heartbeat_tlv(
      &session->remote_heartbeat_interval, session, NULL)) {
    OONF_INFO(session->log_source, "no heartbeat tlv");
    return -1;
  }

  OONF_DEBUG(session->log_source, "Remote heartbeat interval %"PRIu64,
      session->remote_heartbeat_interval);

  dlep_base_proto_start_local_heartbeat(session);
  dlep_base_proto_start_remote_heartbeat(session);

  /* optional peer type tlv */
  dlep_base_proto_print_peer_type(session);

  /* optional extension supported tlv */
  value = dlep_session_get_tlv_value(session, DLEP_EXTENSIONS_SUPPORTED_TLV);
  if (value) {
    ptr = dlep_session_get_tlv_binary(session, value);
    if (dlep_session_update_extensions(session, ptr, value->length/2)) {
      return -1;
    }
  }
  else if (dlep_session_update_extensions(session, NULL, 0)) {
    return -1;
  }

  if (dlep_session_generate_signal(
      session, DLEP_PEER_INITIALIZATION_ACK, NULL)) {
    return -1;
  }

  /* trigger DESTINATION UP for all existing elements in l2 db */
  l2net = oonf_layer2_net_get(session->l2_listener.name);
  if (l2net) {
    avl_for_each_element(&l2net->neighbors, l2neigh, _node) {
      if (session->cfg.send_neighbors) {
        OONF_DEBUG(session->log_source, "Add local neighbor: %s",
            netaddr_to_string(&nbuf, &l2neigh->addr));
        _l2_neigh_added_to_session(session, l2neigh, &l2neigh->addr);
      }

      if (session->cfg.send_proxied) {
        avl_for_each_element(&l2neigh->destinations, l2dest, _node) {
          OONF_DEBUG(session->log_source, "Add proxied neighbor: %s",
              netaddr_to_string(&nbuf, &l2dest->destination));
          _l2_neigh_added_to_session(
              session, l2neigh, &l2dest->destination);
        }
      }
    }
  }
  session->next_restrict_signal = DLEP_ALL_SIGNALS;

  return 0;
}

/**
 * Process the peer update message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static int
_radio_process_peer_update(
    struct dlep_extension *ext __attribute__((unused)),
    struct dlep_session *session) {
  /* we don't support IP address exchange with the router at the moment */
  return dlep_session_generate_signal(session, DLEP_PEER_UPDATE_ACK, NULL);
}

/**
 * Process the peer update ack message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return always 0
 */
static int
_radio_process_peer_update_ack(
    struct dlep_extension *ext __attribute__((unused)),
    struct dlep_session *session) {
  dlep_base_proto_print_status(session);
  return 0;
}

/**
 * Process the destination up message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static int
_radio_process_destination_up(
    struct dlep_extension *ext __attribute__((unused)),
    struct dlep_session *session) {
  struct netaddr mac;
  if (dlep_reader_mac_tlv(&mac, session, NULL)) {
    OONF_INFO(session->log_source, "No mac TLV found");
    return -1;
  }

  /* we don't support IP address exchange with the router at the moment */
  return dlep_session_generate_signal(
      session, DLEP_DESTINATION_UP_ACK, &mac);
}

/**
 * Process the destination up ack message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static int
_radio_process_destination_up_ack(
    struct dlep_extension *ext __attribute__((unused)),
    struct dlep_session *session) {
  struct dlep_local_neighbor *local;
  struct netaddr mac;
  if (dlep_reader_mac_tlv(&mac, session, NULL)) {
    return -1;
  }

  if (dlep_base_proto_print_status(session) == DLEP_STATUS_OKAY) {
    local = dlep_session_get_local_neighbor(session, &mac);
    if (local->state == DLEP_NEIGHBOR_UP_SENT) {
      local->state = DLEP_NEIGHBOR_UP_ACKED;
      oonf_timer_stop(&local->_ack_timeout);

      if (local->changed) {
        dlep_session_generate_signal(session,
            DLEP_DESTINATION_UPDATE, &mac);
        local->changed = false;
      }
    }
  }
  return 0;
}

/**
 * Process the destination down message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static int
_radio_process_destination_down(
    struct dlep_extension *ext __attribute__((unused)),
    struct dlep_session *session) {
  struct netaddr mac;
  if (dlep_reader_mac_tlv(&mac, session, NULL)) {
    return -1;
  }

  /* we don't support IP address exchange with the router at the moment */
  return dlep_session_generate_signal(
      session, DLEP_DESTINATION_DOWN_ACK, &mac);
}

/**
 * Process the destination down ack message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static int
_radio_process_destination_down_ack(
    struct dlep_extension *ext __attribute__((unused)),
    struct dlep_session *session) {
  struct dlep_local_neighbor *local;
  struct netaddr mac;
  if (dlep_reader_mac_tlv(&mac, session, NULL)) {
    OONF_INFO(session->log_source, "Could not read MAC tlv");
    return -1;
  }

  if (dlep_base_proto_print_status(session) == DLEP_STATUS_OKAY) {
    local = dlep_session_get_local_neighbor(session, &mac);
    if (local->state == DLEP_NEIGHBOR_DOWN_SENT) {
      dlep_session_remove_local_neighbor(session, local);
    }
  }
  return 0;
}

/**
 * Process the destination update message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return always 0
 */
static int
_radio_process_destination_update(
    struct dlep_extension *ext __attribute__((unused)),
    struct dlep_session *session __attribute__((unused))) {
  /* TODO: IP address change processing ? */
  return 0;
}

/**
 * Process the link characteristic message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static int
_radio_process_link_char_request(
    struct dlep_extension *ext __attribute__((unused)),
    struct dlep_session *session __attribute__((unused))) {
  /* TODO: Link characteristic processing ? */
  return 0;
}

/**
 * Generate a peer offer signal
 * @param ext (this) dlep extension
 * @param session dlep session
 * @param addr mac address the message should refer to
 * @return -1 if an error happened, 0 otherwise
 */
static int
_radio_write_peer_offer(
    struct dlep_extension *ext __attribute__((unused)),
    struct dlep_session *session,
    const struct netaddr *addr __attribute__((unused))) {
  struct dlep_radio_if *radio_if;
  struct netaddr local_addr;

  radio_if = dlep_radio_get_by_layer2_if(
      session->l2_listener.data->name);
  if (!radio_if || &radio_if->interf.session != session) {
    /* unknown type of session, ignore */
    return 0;
  }

  netaddr_from_socket(&local_addr, &radio_if->tcp.socket_v4.local_socket);
  if (netaddr_get_address_family(&local_addr) == AF_INET) {
    /* no support for TLS at the moment */
    dlep_writer_add_ipv4_conpoint_tlv(&session->writer,
        &local_addr, radio_if->tcp_config.port, false);
  }

  netaddr_from_socket(&local_addr, &radio_if->tcp.socket_v6.local_socket);
  if (netaddr_get_address_family(&local_addr) == AF_INET6) {
    /* no support for TLS at the moment */
    dlep_writer_add_ipv6_conpoint_tlv(&session->writer,
        &local_addr, radio_if->tcp_config.port, false);
  }
  return 0;
}

/**
 * Generate a peer init ack signal
 * @param ext (this) dlep extension
 * @param session dlep session
 * @param addr mac address the message should refer to
 * @return -1 if an error happened, 0 otherwise
 */
static int
_radio_write_peer_init_ack(
    struct dlep_extension *ext __attribute__((unused)),
    struct dlep_session *session,
    const struct netaddr *addr __attribute__((unused))) {
  const uint16_t *ext_ids;
  uint16_t ext_count;

  /* write heartbeat interval */
  dlep_writer_add_heartbeat_tlv(&session->writer,
      session->remote_heartbeat_interval);

  /* write supported extensions */
  ext_ids = dlep_extension_get_ids(&ext_count);
  if (ext_count) {
    dlep_writer_add_supported_extensions(
        &session->writer, ext_ids, ext_count);
  }

  if (session->cfg.peer_type) {
    dlep_writer_add_peer_type_tlv(
        &session->writer, session->cfg.peer_type);
  }

  return 0;
}

/**
 * Helper function to add a layer2 neighbor to a dlep session
 * @param session dlep session
 * @param l2neigh layer2 neighbor
 * @param mac MAC address of other endpoint
 */
static void
_l2_neigh_added_to_session(struct dlep_session *session,
    struct oonf_layer2_neigh *l2neigh, const struct netaddr *mac) {
  struct dlep_local_neighbor *local;

  local = dlep_session_add_local_neighbor(session, mac);

  if (local) {
    memcpy(&local->neigh_addr, &l2neigh->addr, sizeof(local->neigh_addr));

    dlep_session_generate_signal(session, DLEP_DESTINATION_UP, mac);
    local->state = DLEP_NEIGHBOR_UP_SENT;
    oonf_timer_set(&local->_ack_timeout,
        session->cfg.heartbeat_interval * 2);
  }
}

/**
 * Helper function triggered for a new layer2 neighbor
 * @param l2neigh layer2 neighbor
 * @param l2dest layer2 destination (might be NULL)
 * @param mac MAC address of other endpoint
 */
static void
_l2_neigh_added(struct oonf_layer2_neigh *l2neigh,
    struct oonf_layer2_destination *l2dest, const struct netaddr *mac) {
  struct dlep_radio_if *radio_if;
  struct dlep_radio_session *radio_session;

  radio_if = dlep_radio_get_by_layer2_if(l2neigh->network->name);
  if (!radio_if) {
    return;
  }

  avl_for_each_element(&radio_if->interf.session_tree, radio_session, _node) {
    if (l2dest && !radio_session->session.cfg.send_proxied) {
      continue;
    }
    if (!l2dest && !radio_session->session.cfg.send_neighbors) {
      continue;
    }
    _l2_neigh_added_to_session(&radio_if->interf.session, l2neigh, mac);
  }
}

/**
 * Helper function triggered when a layer2 neighbor changed
 * @param l2neigh layer2 neighbor
 * @param l2dest layer2 destination (might be NULL)
 * @param mac MAC address of other endpoint
 */
static void
_l2_neigh_changed(struct oonf_layer2_neigh *l2neigh,
    struct oonf_layer2_destination *l2dest, const struct netaddr *mac) {
  struct dlep_radio_if *radio_if;
  struct dlep_radio_session *radio_session;
  struct dlep_local_neighbor *local;

  radio_if = dlep_radio_get_by_layer2_if(l2neigh->network->name);
  if (!radio_if) {
    return;
  }

  avl_for_each_element(&radio_if->interf.session_tree, radio_session, _node) {
    if (l2dest && !radio_session->session.cfg.send_proxied) {
      continue;
    }
    if (!l2dest && !radio_session->session.cfg.send_neighbors) {
      continue;
    }

    local = dlep_session_add_local_neighbor(
        &radio_session->session, mac);

    if (local) {
      memcpy(&local->neigh_addr, &l2neigh->addr, sizeof(local->neigh_addr));

      switch (local->state) {
        case DLEP_NEIGHBOR_UP_SENT:
          local->changed = true;
          break;
        case DLEP_NEIGHBOR_UP_ACKED:
          dlep_session_generate_signal(&radio_session->session,
              DLEP_DESTINATION_UPDATE, mac);
          local->changed = false;
          break;
        case DLEP_NEIGHBOR_IDLE:
        case DLEP_NEIGHBOR_DOWN_SENT:
        case DLEP_NEIGHBOR_DOWN_ACKED:
          dlep_session_generate_signal(&radio_session->session,
              DLEP_DESTINATION_UP, mac);
          local->state = DLEP_NEIGHBOR_UP_SENT;
          local->changed = false;
          oonf_timer_set(&local->_ack_timeout,
              radio_session->session.cfg.heartbeat_interval * 2);
          break;
        default:
          break;
      }
    }
  }
}

/**
 * Helper function triggered when a layer2 neighbor is removed
 * @param l2neigh layer2 neighbor
 * @param l2dest layer2 destination (might be NULL)
 * @param mac MAC address of other endpoint
 */
static void
_l2_neigh_removed(struct oonf_layer2_neigh *l2neigh,
    struct oonf_layer2_destination *l2dest, const struct netaddr *mac) {
  struct dlep_radio_if *radio_if;
  struct dlep_radio_session *radio_session;
  struct dlep_local_neighbor *local;

  radio_if = dlep_radio_get_by_layer2_if(l2neigh->network->name);
  if (!radio_if) {
    return;
  }

  avl_for_each_element(&radio_if->interf.session_tree, radio_session, _node) {
    if (l2dest && !radio_session->session.cfg.send_proxied) {
      continue;
    }
    if (!l2dest && !radio_session->session.cfg.send_neighbors) {
      continue;
    }

    local = dlep_session_get_local_neighbor(
        &radio_session->session, mac);
    if (!local) {
      continue;
    }

    if ((l2dest && netaddr_cmp(&l2neigh->addr, &local->neigh_addr) == 0)
        || (!l2dest && netaddr_is_unspec(&local->neigh_addr))) {
      dlep_session_generate_signal(&radio_session->session,
          DLEP_DESTINATION_DOWN, mac);
      local->state = DLEP_NEIGHBOR_DOWN_SENT;
      oonf_timer_set(&local->_ack_timeout,
          radio_session->session.cfg.heartbeat_interval * 2);
    }
  }

}

/**
 * Callback triggered when a layer2 neighbor object has been added
 * @param ptr layer2 neighbor
 */
static void
_cb_l2_neigh_added(void *ptr) {
  struct oonf_layer2_neigh *l2neigh = ptr;

  _l2_neigh_added(l2neigh, NULL, &l2neigh->addr);
}

/**
 * Callback triggered when a layer2 neighbor object has been changed
 * @param ptr layer2 neighbor
 */
static void
_cb_l2_neigh_changed(void *ptr) {
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_destination *l2dst;

  l2neigh = ptr;
  _l2_neigh_changed(l2neigh, NULL, &l2neigh->addr);

  avl_for_each_element(&l2neigh->destinations, l2dst, _node) {
    _l2_neigh_changed(l2neigh, l2dst, &l2dst->destination);
  }
}

/**
 * Callback triggered when a layer2 neighbor object has been removed
 * @param ptr layer2 neighbor
 */
static void
_cb_l2_neigh_removed(void *ptr) {
  struct oonf_layer2_neigh *l2neigh = ptr;

  _l2_neigh_removed(l2neigh, NULL, &l2neigh->addr);
}

/**
 * Callback triggered when a layer2 destination object has been added
 * @param ptr layer2 destination
 */
static void
_cb_l2_dst_added(void *ptr) {
  struct oonf_layer2_destination *l2dst = ptr;

  _l2_neigh_added(l2dst->neighbor, NULL, &l2dst->destination);
}

/**
 * Callback triggered when a layer2 destination object has been removed
 * @param ptr layer2 destination
 */
static void
_cb_l2_dst_removed(void *ptr) {
  struct oonf_layer2_destination *l2dst = ptr;

  _l2_neigh_removed(l2dst->neighbor, NULL, &l2dst->destination);
}

/**
 * Callback triggered when a destination up/down ack times out
 * @param session dlep session
 * @param local local DLEP neighbor
 */
static void
_cb_destination_timeout(struct dlep_session *session,
    struct dlep_local_neighbor *local) {
  dlep_session_remove_local_neighbor(session, local);
}
