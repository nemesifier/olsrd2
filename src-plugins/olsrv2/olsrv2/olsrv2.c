
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

#include "common/avl.h"
#include "common/common_types.h"
#include "common/list.h"
#include "common/netaddr.h"
#include "common/netaddr_acl.h"
#include "config/cfg_schema.h"
#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"
#include "core/os_core.h"
#include "subsystems/oonf_rfc5444.h"
#include "subsystems/oonf_telnet.h"
#include "subsystems/oonf_timer.h"
#include "subsystems/os_interface.h"

#include "nhdp/nhdp_interfaces.h"

#include "olsrv2/olsrv2.h"
#include "olsrv2/olsrv2_lan.h"
#include "olsrv2/olsrv2_originator.h"
#include "olsrv2/olsrv2_reader.h"
#include "olsrv2/olsrv2_tc.h"
#include "olsrv2/olsrv2_writer.h"

/* definitions */

/*! configuration option for locally attached networks */
#define _LOCAL_ATTACHED_NETWORK_KEY "lan"

/**
 * Default values for locally attached network parameters
 */
enum _lan_option_defaults {
  LAN_DEFAULT_DOMAIN    = 0,//!< LAN_DEFAULT_DOMAIN
  LAN_DEFAULT_METRIC    = 1,//!< LAN_DEFAULT_METRIC
  LAN_DEFAULT_DISTANCE  = 2,//!< LAN_DEFAULT_DISTANCE
};

/*! locally attached network option for source-specific prefix */
#define LAN_OPTION_SRC    "src="

/*! locally attached network option for outgoing metric */
#define LAN_OPTION_METRIC "metric="

/*! locally attached network option for domain */
#define LAN_OPTION_DOMAIN "domain="

/*! locally attached network option for hopcount distance */
#define LAN_OPTION_DIST   "dist="

/**
 * olsrv2 plugin config
 */
struct _config {
  /*! topology control interval */
  uint64_t tc_interval;

  /*! topology control validity */
  uint64_t tc_validity;

  /*! olsrv2 f_hold_time */
  uint64_t f_hold_time;

  /*! olsrv2 p_hold_time */
  uint64_t p_hold_time;

  /*! IP filter for routable addresses */
  struct netaddr_acl routable;

  /*! IP filter for valid originator */
  struct netaddr_acl originator_acl;
};

/**
 * Additional parameters of a single locally attached network
 */
struct _lan_data {
  /*! domain of LAN */
  struct nhdp_domain *domain;

  /*! source prefix */
  struct netaddr source_prefix;

  /*! olsrv2 metric */
  uint32_t metric;

  /*! routing metric (distance) */
  uint32_t dist;
};

/* prototypes */
static void _early_cfg_init(void);
static int _init(void);
static void _initiate_shutdown(void);
static void _cleanup(void);

static const char *_parse_lan_parameters(struct os_route_key *prefix,
		struct _lan_data *dst, const char *src);
static void _parse_lan_array(struct cfg_named_section *section, bool add);
static void _cb_generate_tc(struct oonf_timer_instance *);

static void _update_originator(int af_family);
static int _cb_if_event(struct os_interface_listener *);

static void _cb_cfg_olsrv2_changed(void);
static void _cb_cfg_domain_changed(void);

/* subsystem definition */
static struct cfg_schema_entry _rt_domain_entries[] = {
  CFG_MAP_BOOL(olsrv2_routing_domain, use_srcip_in_routes, "srcip_routes", "true",
      "Set the source IP of IPv4-routes to a fixed value."),
  CFG_MAP_INT32_MINMAX(olsrv2_routing_domain, protocol, "protocol", "100",
      "Protocol number to be used in routing table", 0, false, 1, 254),
  CFG_MAP_INT32_MINMAX(olsrv2_routing_domain, table, "table", "254",
      "Routing table number for routes", 0, false, 1, 254),
  CFG_MAP_INT32_MINMAX(olsrv2_routing_domain, distance, "distance", "2",
      "Metric Distance to be used in routing table", 0, false, 1, 255),
  CFG_MAP_BOOL(olsrv2_routing_domain, source_specific, "source_specific", "true",
      "This domain uses IPv6 source specific routing"),
};

static struct cfg_schema_section _rt_domain_section = {
  .type = CFG_NHDP_DOMAIN_SECTION,
  .mode = CFG_SSMODE_NAMED_WITH_DEFAULT,
  .def_name = CFG_NHDP_DEFAULT_DOMAIN,
  .cb_delta_handler = _cb_cfg_domain_changed,
  .entries = _rt_domain_entries,
  .entry_count = ARRAYSIZE(_rt_domain_entries),
};

static struct cfg_schema_entry _olsrv2_entries[] = {
  CFG_MAP_CLOCK_MIN(_config, tc_interval, "tc_interval", "5.0",
    "Time between two TC messages", 100),
  CFG_MAP_CLOCK_MIN(_config, tc_validity, "tc_validity", "300.0",
    "Validity time of a TC messages", 100),
  CFG_MAP_CLOCK_MIN(_config, f_hold_time, "forward_hold_time", "300.0",
    "Holdtime for forwarding set information", 100),
  CFG_MAP_CLOCK_MIN(_config, p_hold_time, "processing_hold_time", "300.0",
    "Holdtime for processing set information", 100),
  CFG_MAP_ACL_V46(_config, routable, "routable",
      OLSRV2_ROUTABLE_IPV4 OLSRV2_ROUTABLE_IPV6 ACL_DEFAULT_ACCEPT,
    "Filter to decide which addresses are considered routable"),

  CFG_VALIDATE_LAN(_LOCAL_ATTACHED_NETWORK_KEY, "",
    "locally attached network, a combination of an"
    " ip address or prefix followed by an up to four optional parameters"
    " which define link metric cost, hopcount distance and domain of the prefix"
    " ( <"LAN_OPTION_METRIC"...> <"LAN_OPTION_DIST"...>"
    " <"LAN_OPTION_DOMAIN"<num>/all> <"LAN_OPTION_SRC"...> ).",
    .list = true),

  CFG_MAP_ACL_V46(_config, originator_acl, "originator",
    OLSRV2_ORIGINATOR_IPV4 OLSRV2_ORIGINATOR_IPV6 ACL_DEFAULT_ACCEPT,
    "Filter for router originator addresses (ipv4 and ipv6)"
    " from the interface addresses. Olsrv2 will prefer routable addresses"
    " over linklocal addresses."),
};

static struct cfg_schema_section _olsrv2_section = {
  .type = CFG_OLSRV2_SECTION,
  .cb_delta_handler = _cb_cfg_olsrv2_changed,
  .entries = _olsrv2_entries,
  .entry_count = ARRAYSIZE(_olsrv2_entries),
  .next_section = &_rt_domain_section,
};

static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_RFC5444_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_OS_INTERFACE_SUBSYSTEM,
  OONF_NHDP_SUBSYSTEM,
};
static struct oonf_subsystem _olsrv2_subsystem = {
  .name = OONF_OLSRV2_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .early_cfg_init = _early_cfg_init,
  .init = _init,
  .cleanup = _cleanup,
  .initiate_shutdown = _initiate_shutdown,
  .cfg_section = &_olsrv2_section,
};
DECLARE_OONF_PLUGIN(_olsrv2_subsystem);

static struct _config _olsrv2_config;

/* timer for TC generation */
static struct oonf_timer_class _tc_timer_class = {
  .name = "TC generation",
  .periodic = true,
  .callback = _cb_generate_tc,
};

static struct oonf_timer_instance _tc_timer = {
  .class = &_tc_timer_class,
};

/* global interface listener */
static struct os_interface_listener _if_listener = {
  .if_changed = _cb_if_event,
};

/* global variables */
static struct oonf_rfc5444_protocol *_protocol;

static uint16_t _ansn;

/* Additional logging sources */
enum oonf_log_source LOG_OLSRV2;
enum oonf_log_source LOG_OLSRV2_R;
enum oonf_log_source LOG_OLSRV2_ROUTING;
enum oonf_log_source LOG_OLSRV2_W;

/**
 * Initialize additional logging sources for NHDP
 */
static void
_early_cfg_init(void) {
  LOG_OLSRV2 = _olsrv2_subsystem.logging;
  LOG_OLSRV2_R = oonf_log_register_source(OONF_OLSRV2_SUBSYSTEM "_r");
  LOG_OLSRV2_W = oonf_log_register_source(OONF_OLSRV2_SUBSYSTEM "_w");
  LOG_OLSRV2_ROUTING = oonf_log_register_source(OONF_OLSRV2_SUBSYSTEM "_routing");
}

/**
 * Initialize OLSRV2 subsystem
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  if (os_core_get_random(&_ansn, sizeof(_ansn))) {
    return -1;
  }

  _protocol = oonf_rfc5444_get_default_protocol();
  if (olsrv2_writer_init(_protocol)) {
    return -1;
  }

  /* activate interface listener */
  os_interface_add(&_if_listener);

  /* activate the rest of the olsrv2 protocol */
  olsrv2_lan_init();
  olsrv2_originator_init();
  olsrv2_reader_init(_protocol);
  olsrv2_tc_init();
  olsrv2_routing_init();

  /* initialize timer */
  oonf_timer_add(&_tc_timer_class);

  return 0;
}

/**
 * Begin shutdown by deactivating reader and writer. Also flush all routes
 */
static void
_initiate_shutdown(void) {
  olsrv2_writer_cleanup();
  olsrv2_reader_cleanup();
  olsrv2_routing_initiate_shutdown();
}

/**
 * Cleanup OLSRV2 subsystem
 */
static void
_cleanup(void) {
  /* remove interface listener */
  os_interface_remove(&_if_listener);

  /* cleanup configuration */
  netaddr_acl_remove(&_olsrv2_config.routable);
  netaddr_acl_remove(&_olsrv2_config.originator_acl);

  /* cleanup all parts of olsrv2 */
  olsrv2_routing_cleanup();
  olsrv2_originator_cleanup();
  olsrv2_tc_cleanup();
  olsrv2_lan_cleanup();

  /* free protocol instance */
  _protocol = NULL;
}

/**
 * @return interval between two tcs
 */
uint64_t
olsrv2_get_tc_interval(void) {
  return _olsrv2_config.tc_interval;
}

/**
 * @return validity of the local TCs
 */
uint64_t
olsrv2_get_tc_validity(void) {
  return _olsrv2_config.tc_validity;
}

/**
 * @return acl for checking if an address is routable
 */
const struct netaddr_acl *
olsrv2_get_routable(void) {
    return &_olsrv2_config.routable;
}


/**
 * default implementation for rfc5444 processing handling according
 * to MPR settings.
 * @param context
 * @param vtime
 * @return
 */
bool
olsrv2_mpr_shall_process(
    struct rfc5444_reader_tlvblock_context *context, uint64_t vtime) {
  enum oonf_duplicate_result dup_result;
  bool process;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  /* check if message has originator and sequence number */
  if (!context->has_origaddr || !context->has_seqno) {
    OONF_DEBUG(LOG_OLSRV2, "Do not process message type %u,"
        " originator or sequence number is missing!",
        context->msg_type);
    return false;
  }

  /* check forwarding set */
  dup_result = oonf_duplicate_entry_add(&_protocol->processed_set,
      context->msg_type, &context->orig_addr,
      context->seqno, vtime + _olsrv2_config.f_hold_time);
  process = oonf_duplicate_is_new(dup_result);

  OONF_DEBUG(LOG_OLSRV2, "Do %sprocess message type %u from %s"
      " with seqno %u (dupset result: %u)",
      process ? "" : "not ",
      context->msg_type,
      netaddr_to_string(&buf, &context->orig_addr),
      context->seqno, dup_result);
  return process;
}

/**
 * default implementation for rfc5444 forwarding handling according
 * to MPR settings.
 * @param context RFC5444 reader context
 * @param source_address source address of RFC5444 message
 * @param vtime validity time of message information
 * @return true if message was forwarded, false otherwise
 */
bool
olsrv2_mpr_shall_forwarding(struct rfc5444_reader_tlvblock_context *context,
    struct netaddr *source_address, uint64_t vtime) {
  struct nhdp_interface *interf;
  struct nhdp_laddr *laddr;
  struct nhdp_neighbor *neigh;
  enum oonf_duplicate_result dup_result;
  bool forward;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  /* check if message has originator and sequence number */
  if (!context->has_origaddr || !context->has_seqno) {
    OONF_DEBUG(LOG_OLSRV2, "Do not forward message type %u,"
        " originator or sequence number is missing!",
        context->msg_type);
    return false;
  }

  /* check input interface */
  if (_protocol->input_interface == NULL) {
    OONF_DEBUG(LOG_OLSRV2, "Do not forward because input interface is not set");
    return false;
  }

  /* checp input source address */
  if (!source_address) {
    OONF_DEBUG(LOG_OLSRV2, "Do not forward because input source is not set");
    return false;
  }

  /* check if this is coming from the unicast receiver */
  if (strcmp(_protocol->input_interface->name, RFC5444_UNICAST_INTERFACE) == 0) {
    return false;
  }

  /* check forwarding set */
  dup_result = oonf_duplicate_entry_add(&_protocol->forwarded_set,
      context->msg_type, &context->orig_addr,
      context->seqno, vtime + _olsrv2_config.f_hold_time);
  if (!oonf_duplicate_is_new(dup_result)) {
    OONF_DEBUG(LOG_OLSRV2, "Do not forward message type %u from %s"
        " with seqno %u (dupset result: %u)",
        context->msg_type,
        netaddr_to_string(&buf, &context->orig_addr),
        context->seqno, dup_result);
    return false;
  }

  /* get NHDP interface */
  interf = nhdp_interface_get(_protocol->input_interface->name);
  if (interf == NULL) {
    OONF_DEBUG(LOG_OLSRV2, "Do not forward because NHDP does not handle"
        " interface '%s'", _protocol->input_interface->name);
    return false;
  }

  /* get NHDP link address corresponding to source */
  laddr = nhdp_interface_get_link_addr(interf, source_address);
  if (laddr == NULL) {
    OONF_DEBUG(LOG_OLSRV2, "Do not forward because source IP %s is"
        " not a direct neighbor",
        netaddr_to_string(&buf, source_address));
    return false;
  }

  if (netaddr_get_address_family(&context->orig_addr)
      == netaddr_get_address_family(source_address)) {
    /* get NHDP neighbor */
    neigh = laddr->link->neigh;
  }
  else if (laddr->link->dualstack_partner) {
    /* get dualstack NHDP neighbor */
    neigh = laddr->link->dualstack_partner->neigh;
  }
  else {
    OONF_DEBUG(LOG_OLSRV2, "Do not forward because this is a dualstack"
        " message, but the link source %s is not dualstack capable",
        netaddr_to_string(&buf, source_address));
    return false;
  }

  /* forward if this neighbor has selected us as a flooding MPR */
  forward = neigh->local_is_flooding_mpr && neigh->symmetric > 0;
  OONF_DEBUG(LOG_OLSRV2, "Do %sforward message type %u from %s"
      " with seqno %u (%s/%u)",
      forward ? "" : "not ",
      context->msg_type,
      netaddr_to_string(&buf, &context->orig_addr),
      context->seqno,
      neigh->local_is_flooding_mpr ? "true" : "false", neigh->symmetric);
  return forward;
}

/**
 * @return current answer set number for local topology database
 */
uint16_t
olsrv2_get_ansn(void) {
  return _ansn;
}

/**
 * Update answer set number if metric of a neighbor changed since last update.
 * @return new answer set number, might be the same if no metric changed.
 */
uint16_t
olsrv2_update_ansn(void) {
  struct nhdp_domain *domain;
  bool changed;

  changed = false;
  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    if (domain->neighbor_metric_changed) {
      changed = true;
      domain->neighbor_metric_changed = false;
    }
  }

  if (changed) {
    _ansn++;
  }
  return _ansn;
}

/**
 * Schema entry validator for an attached network.
 * See CFG_VALIDATE_ACL_*() macros.
 * @param entry pointer to schema entry
 * @param section_name name of section type and name
 * @param value value of schema entry
 * @param out pointer to autobuffer for validator output
 * @return 0 if validation found no problems, -1 otherwise
 */
int
olsrv2_validate_lan(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out) {
  struct netaddr_str buf;
  struct _lan_data data;
  const char *ptr, *result;
  struct os_route_key prefix;

  if (value == NULL) {
    cfg_schema_help_netaddr(entry, out);
    cfg_append_printable_line(out,
        "    This value is followed by a list of four optional parameters.");
    cfg_append_printable_line(out,
        "    - '"LAN_OPTION_SRC"<prefix>' the source specific prefix of this attached network."
        " The default is 2.");
    cfg_append_printable_line(out,
        "    - '"LAN_OPTION_METRIC"<m>' the link metric of the LAN (between %u and %u)."
        " The default is 0.", RFC7181_METRIC_MIN, RFC7181_METRIC_MAX);
    cfg_append_printable_line(out,
        "    - '"LAN_OPTION_DOMAIN"<d>' the domain of the LAN (between 0 and 255) or 'all'."
        " The default is all.");
    cfg_append_printable_line(out,
        "    - '"LAN_OPTION_DIST"<d>' the hopcount distance of the LAN (between 0 and 255)."
        " The default is 2.");
    return 0;
  }

  ptr = str_cpynextword(buf.buf, value, sizeof(buf));
  if (cfg_schema_validate_netaddr(entry, section_name, buf.buf, out)) {
    /* check prefix first */
    return -1;
  }

  if (netaddr_from_string(&prefix.dst, buf.buf)) {
    return -1;
  }

  result = _parse_lan_parameters(&prefix, &data, ptr);
  if (result) {
    cfg_append_printable_line(out, "Value '%s' for entry '%s'"
        " in section %s has %s",
        value, entry->key.entry, section_name, result);
    return -1;
  }

  if (data.metric < RFC7181_METRIC_MIN || data.metric > RFC7181_METRIC_MAX) {
    cfg_append_printable_line(out, "Metric %u for prefix %s must be between %u and %u",
        data.metric, buf.buf, RFC7181_METRIC_MIN, RFC7181_METRIC_MAX);
    return -1;
  }
  if (data.dist > 255) {
    cfg_append_printable_line(out,
        "Distance %u for prefix %s must be between 0 and 255", data.dist, buf.buf);
    return -1;
  }

  return 0;
}

/**
 * Parse parameters of lan prefix string
 * @param prefix source specific prefix (to store source prefix)
 * @param dst pointer to data structure to store results.
 * @param src source string
 * @return NULL if parser worked without an error, a pointer
 *   to the suffix of the error message otherwise.
 */
static const char *
_parse_lan_parameters(struct os_route_key *prefix,
		struct _lan_data *dst, const char *src) {
  char buffer[64];
  const char *ptr, *next;
  unsigned ext;

  ptr = src;
  dst->domain = NULL;
  dst->metric = LAN_DEFAULT_METRIC;
  dst->dist   = LAN_DEFAULT_DISTANCE;

  while (ptr != NULL) {
    next = str_cpynextword(buffer, ptr, sizeof(buffer));

    if (strncasecmp(buffer, LAN_OPTION_METRIC, 7) == 0) {
      dst->metric = strtoul(&buffer[7], NULL, 0);
      if (dst->metric == 0 && errno != 0) {
        return "an illegal metric parameter";
      }
    }
    else if (strncasecmp(buffer, LAN_OPTION_DOMAIN, 7) == 0) {
      fprintf(stderr, "domain='%s'\n", &buffer[7]);
      if (strcasecmp(&buffer[7], "all") == 0) {
        dst->domain = NULL;
      }
      else {
        ext = strtoul(&buffer[7], NULL, 10);
        if ((ext == 0 && errno != 0) || ext > 255) {
          return "an illegal domain parameter";
        }
        dst->domain = nhdp_domain_get_by_ext(ext);
        if (dst->domain == NULL) {
          return "an unknown domain extension number";
        }
      }
    }
    else if (strncasecmp(buffer, LAN_OPTION_DIST, 5) == 0) {
      dst->dist = strtoul(&buffer[5], NULL, 10);
      if (dst->dist == 0 && errno != 0) {
        return "an illegal distance parameter";
      }
    }
    else if (strncasecmp(buffer, LAN_OPTION_SRC, 4) == 0) {
      if (netaddr_from_string(&prefix->src, &buffer[4])) {
        return "an illegal source prefix";
      }
      if (netaddr_get_address_family(&prefix->dst)
            != netaddr_get_address_family(&prefix->src)) {
    	  return "an illegal source prefix address type";
      }
      if (!os_routing_supports_source_specific(
          netaddr_get_address_family(&prefix->dst))) {
        return "an unsupported sourc specific prefix";
      }
    }
    else {
      return "an unknown parameter";
    }
    ptr = next;
  }
  return NULL;
}

/**
 * Takes a named configuration section, extracts the attached network
 * array and apply it
 * @param section pointer to configuration section.
 * @param add true if new lan entries should be created, false if
 *   existing entries should be removed.
 */
static void
_parse_lan_array(struct cfg_named_section *section, bool add) {
  struct netaddr_str addr_buf;
  struct netaddr addr;
  struct os_route_key prefix;
  struct _lan_data data;

  const char *value, *ptr;
  struct cfg_entry *entry;

  if (section == NULL) {
    return;
  }

  entry = cfg_db_get_entry(section, _LOCAL_ATTACHED_NETWORK_KEY);
  if (entry == NULL) {
    return;
  }

  strarray_for_each_element(&entry->val, value) {
    /* extract data */
    ptr = str_cpynextword(addr_buf.buf, value, sizeof(addr_buf));
    if (netaddr_from_string(&addr, addr_buf.buf)) {
      continue;
    }

    os_routing_init_sourcespec_prefix(&prefix, &addr);

    /* truncate address */
    netaddr_truncate(&prefix.dst, &prefix.dst);

    if (_parse_lan_parameters(&prefix, &data, ptr)) {
      continue;
    }

    if (data.domain == NULL) {
      list_for_each_element(nhdp_domain_get_list(), data.domain, _node) {
        if (add) {
          olsrv2_lan_add(data.domain, &prefix, data.metric, data.dist);
        }
        else {
          olsrv2_lan_remove(data.domain, &prefix);
        }
      }
    }
    else {
      if (add) {
        olsrv2_lan_add(data.domain, &prefix, data.metric, data.dist);
      }
      else {
        olsrv2_lan_remove(data.domain, &prefix);
      }
    }
  }
}

/**
 * Callback to trigger normal tc generation with timer
 * @param ptr timer instance that fired
 */
static void
_cb_generate_tc(struct oonf_timer_instance *ptr __attribute__((unused))) {
  if (nhdp_domain_node_is_mpr() || !avl_is_empty(olsrv2_lan_get_tree())) {
    olsrv2_writer_send_tc();
  }
}

static int
_get_addr_priority(const struct netaddr *addr) {
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  if (!netaddr_acl_check_accept(&_olsrv2_config.originator_acl, addr)) {
    /* does not match the acl */
    OONF_DEBUG(LOG_OLSRV2, "check priority for %s: 0 (not in ACL)",
        netaddr_to_string(&nbuf, addr));
    return 0;
  }


  if (netaddr_get_address_family(addr) == AF_INET) {
    if (netaddr_is_in_subnet(&NETADDR_IPV4_LINKLOCAL, addr)) {
      /* linklocal */
      OONF_DEBUG(LOG_OLSRV2, "check priority for %s: 2 (linklocal)",
          netaddr_to_string(&nbuf, addr));
      return 2;
    }

    /* routable */
    OONF_DEBUG(LOG_OLSRV2, "check priority for %s: 4 (routable)",
        netaddr_to_string(&nbuf, addr));
    return 4;
  }

  if (netaddr_get_address_family(addr) == AF_INET6) {
    if (netaddr_is_in_subnet(&NETADDR_IPV6_LINKLOCAL, addr)) {
      /* linklocal */
      OONF_DEBUG(LOG_OLSRV2, "check priority for %s: 2 (linklocal)",
          netaddr_to_string(&nbuf, addr));
      return 2;
    }

    /* routable */
    OONF_DEBUG(LOG_OLSRV2, "check priority for %s: 4 (routable)",
        netaddr_to_string(&nbuf, addr));
    return 4;
  }

  /* unknown */
  OONF_DEBUG(LOG_OLSRV2, "check priority for %s: 0 (unknown)",
      netaddr_to_string(&nbuf, addr));

  return 0;
}

/**
 * Check if current originators are still valid and
 * lookup new one if necessary.
 */
static void
_update_originator(int af_family) {
  const struct netaddr *originator;
  struct nhdp_interface *nhdp_if;
  struct os_interface_listener *if_listener;
  struct netaddr new_originator;
  struct os_interface_ip *ip;
  int new_priority;
  int old_priority;
  int priority;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  OONF_DEBUG(LOG_OLSRV2, "Updating OLSRV2 %s originator",
      af_family == AF_INET ? "ipv4" : "ipv6");

  originator = olsrv2_originator_get(af_family);

  old_priority = 0;
  new_priority = 0;

  netaddr_invalidate(&new_originator);

  avl_for_each_element(nhdp_interface_get_tree(), nhdp_if, _node) {
    if_listener = nhdp_interface_get_if_listener(nhdp_if);

    /* check if originator is still valid */
    avl_for_each_element(&if_listener->data->addresses, ip, _node) {
      if (netaddr_get_address_family(&ip->address) == af_family) {
        priority = _get_addr_priority(&ip->address);
        if (priority == 0) {
          /* not useful */
          continue;
        }

        if (netaddr_cmp(originator, &ip->address) == 0) {
          old_priority = priority + 1;
        }

        if (priority > old_priority && priority > new_priority) {
          memcpy(&new_originator, &ip->address, sizeof(new_originator));
          new_priority = priority;
        }
      }
    }
  }

  if (new_priority > old_priority) {
    OONF_DEBUG(LOG_OLSRV2, "Set originator to %s",
        netaddr_to_string(&buf, &new_originator));
    olsrv2_originator_set(&new_originator);
  }
}

/**
 * Callback for interface events
 * @param listener pointer to interface listener
 * @return always 0
 */
static int
_cb_if_event(struct os_interface_listener *if_listener __attribute__((unused))) {
  _update_originator(AF_INET);
  _update_originator(AF_INET6);
  return 0;
}

/**
 * Callback fired when olsrv2 section changed
 */
static void
_cb_cfg_olsrv2_changed(void) {
  if (cfg_schema_tobin(&_olsrv2_config, _olsrv2_section.post,
      _olsrv2_entries, ARRAYSIZE(_olsrv2_entries))) {
    OONF_WARN(LOG_OLSRV2, "Cannot convert OLSRV2 configuration.");
    return;
  }

  /* set tc timer interval */
  oonf_timer_set(&_tc_timer, _olsrv2_config.tc_interval);

  /* check if we have to change the originators */
  _update_originator(AF_INET);
  _update_originator(AF_INET6);

  /* run through all pre-update LAN entries and remove them */
  _parse_lan_array(_olsrv2_section.pre, false);

  /* run through all post-update LAN entries and add them */
  _parse_lan_array(_olsrv2_section.post, true);
}

/**
 * Callback fired when domain section changed
 */
static void
_cb_cfg_domain_changed(void) {
  struct olsrv2_routing_domain rtdomain;
  struct nhdp_domain *domain;
  char *error = NULL;
  int ext;

  ext = strtol(_rt_domain_section.section_name, &error, 10);
  if (error != NULL && *error != 0) {
    /* illegal domain name */
    return;
  }

  if (ext < 0 || ext > 255) {
    /* name out of range */
    return;
  }

  domain = nhdp_domain_add(ext);
  if (domain == NULL) {
    return;
  }

  memset(&rtdomain, 0, sizeof(rtdomain));
  if (cfg_schema_tobin(&rtdomain, _rt_domain_section.post,
      _rt_domain_entries, ARRAYSIZE(_rt_domain_entries))) {
    OONF_WARN(LOG_OLSRV2, "Cannot convert OLSRV2 routing domain parameters.");
    return;
  }

  olsrv2_routing_set_domain_parameter(domain, &rtdomain);
}
