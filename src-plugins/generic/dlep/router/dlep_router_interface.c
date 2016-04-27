
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
#include <unistd.h>

#include "common/common_types.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "common/netaddr.h"

#include "subsystems/oonf_class.h"
#include "subsystems/oonf_layer2.h"
#include "subsystems/oonf_packet_socket.h"
#include "subsystems/oonf_timer.h"

#include "dlep/dlep_extension.h"
#include "dlep/dlep_iana.h"
#include "dlep/dlep_interface.h"
#include "dlep/dlep_session.h"
#include "dlep/dlep_writer.h"

#include "dlep/router/dlep_router.h"
#include "dlep/router/dlep_router_interface.h"

#include "dlep/ext_base_proto/proto_router.h"
#include "dlep/ext_base_metric/metric.h"
#include "dlep/ext_l1_statistics/l1_statistics.h"
#include "dlep/ext_l2_statistics/l2_statistics.h"
#include "dlep/router/dlep_router_internal.h"
#include "dlep/router/dlep_router_session.h"

static void _cleanup_interface(struct dlep_router_if *interface);

static struct avl_tree _interface_tree;

static struct oonf_class _router_if_class = {
  .name = "DLEP router interface",
  .size = sizeof(struct dlep_router_if),
};

static bool _shutting_down;
static uint32_t _l2_origin;

/**
 * Initialize dlep router interface framework. This will also
 * initialize the dlep router session framework.
 */
void
dlep_router_interface_init(void) {
  oonf_class_add(&_router_if_class);
  avl_init(&_interface_tree, avl_comp_strcasecmp, false);

  dlep_extension_init();
  dlep_session_init();
  dlep_router_session_init();
  dlep_base_proto_router_init();
  dlep_base_metric_init();
  dlep_l1_statistics_init();
  dlep_l2_statistics_init();

  _shutting_down = false;

  _l2_origin = oonf_layer2_register_origin();
}

/**
 * Cleanup dlep router interface framework. This will also cleanup
 * all dlep router sessions.
 */
void
dlep_router_interface_cleanup(void) {
  struct dlep_router_if *interf, *it;

  avl_for_each_element_safe(&_interface_tree, interf, interf._node, it) {
    dlep_router_remove_interface(interf);
  }

  oonf_class_remove(&_router_if_class);

  dlep_router_session_cleanup();
}

/**
 * Get a dlep router interface by layer2 interface name
 * @param l2_ifname interface name
 * @return dlep router interface, NULL if not found
 */
struct dlep_router_if *
dlep_router_get_by_layer2_if(const char *l2_ifname) {
  struct dlep_router_if *interf;

  return avl_find_element(&_interface_tree, l2_ifname, interf, interf._node);
}

/**
 * Get a dlep router interface by dlep datapath name
 * @param ifname interface name
 * @return dlep router interface, NULL if not found
 */
struct dlep_router_if *
dlep_router_get_by_datapath_if(const char *ifname) {
  struct dlep_router_if *interf;

  avl_for_each_element(&_interface_tree, interf, interf._node) {
    if (strcmp(interf->interf.udp_config.interface, ifname) == 0) {
      return interf;
    }
  }
  return NULL;
}

/**
 * Add a new dlep interface or get existing one with same name.
 * @param ifname interface name
 * @return dlep router interface, NULL if allocation failed
 */
struct dlep_router_if *
dlep_router_add_interface(const char *ifname) {
  struct dlep_router_if *interface;

  interface = dlep_router_get_by_layer2_if(ifname);
  if (interface) {
    OONF_DEBUG(LOG_DLEP_ROUTER, "use existing instance for %s", ifname);
    return interface;
  }

  interface = oonf_class_malloc(&_router_if_class);
  if (!interface) {
    return NULL;
  }

  if (dlep_if_add(&interface->interf, ifname,
      _l2_origin, LOG_DLEP_ROUTER, false)) {
    oonf_class_free(&_router_if_class, interface);
    return NULL;
  }

  /* add to global tree of sessions */
  avl_insert(&_interface_tree, &interface->interf._node);

  OONF_DEBUG(LOG_DLEP_ROUTER, "Add session %s", ifname);
  return interface;
}

/**
 * Remove dlep router interface
 * @param interface dlep router interface
 */
void
dlep_router_remove_interface(struct dlep_router_if *interface) {
  /* close all sessions */
  _cleanup_interface(interface);

  /* cleanup generic interface */
  dlep_if_remove(&interface->interf);

  /* remove session */
  avl_remove(&_interface_tree, &interface->interf._node);
  oonf_class_free(&_router_if_class, interface);
}

/**
 * Apply new settings to dlep router interface. This will close all
 * existing dlep sessions.
 * @param interf dlep router interface
 */
void
dlep_router_apply_interface_settings(struct dlep_router_if *interf) {
  struct dlep_extension *ext;
  struct os_interface *os_if;
  const struct netaddr *result;
  union netaddr_socket local, remote;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  oonf_packet_apply_managed(&interf->interf.udp, &interf->interf.udp_config);

  _cleanup_interface(interf);

  if (!netaddr_is_unspec(&interf->connect_to_addr)) {
    os_if = interf->interf.session.l2_listener.data;

    OONF_DEBUG(LOG_DLEP_ROUTER, "Connect directly to [%s]:%d",
        netaddr_to_string(&nbuf, &interf->connect_to_addr),
        interf->connect_to_port);

    result = os_interface_get_prefix_from_dst(&interf->connect_to_addr, os_if);
    if (result) {
      /* initialize local and remote socket */
      netaddr_socket_init(&local, result, 0, os_if->index);
      netaddr_socket_init(&remote,
          &interf->connect_to_addr, interf->connect_to_port, os_if->index);

      dlep_router_add_session(interf, &local, &remote);
    }
  }

  avl_for_each_element(dlep_extension_get_tree(), ext, _node) {
    if (ext->cb_session_apply_router) {
      ext->cb_session_apply_router(&interf->interf.session);
    }
  }
}

/**
 * Send all active sessions a Peer Terminate signal
 */
void
dlep_router_terminate_all_sessions(void) {
  struct dlep_router_if *interf;
  struct dlep_router_session *router_session;

  _shutting_down = true;

  avl_for_each_element(&_interface_tree, interf, interf._node) {
    avl_for_each_element(&interf->interf.session_tree, router_session, _node) {
      dlep_session_terminate(&router_session->session);
    }
  }
}

/**
 * Close all existing dlep sessions of a dlep interface
 * @param interface dlep router interface
 */
static void
_cleanup_interface(struct dlep_router_if *interface) {
  struct dlep_router_session *stream, *it;

  /* close TCP connection and socket */
  avl_for_each_element_safe(&interface->interf.session_tree, stream, _node, it) {
    dlep_router_remove_session(stream);
  }
}
