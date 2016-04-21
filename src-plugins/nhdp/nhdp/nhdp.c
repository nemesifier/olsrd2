
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
#include "config/cfg_schema.h"
#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_interface.h"
#include "subsystems/oonf_rfc5444.h"
#include "nhdp/nhdp_hysteresis.h"
#include "nhdp/nhdp_interfaces.h"
#include "nhdp/nhdp_domain.h"
#include "nhdp/nhdp_reader.h"
#include "nhdp/nhdp_writer.h"
#include "nhdp/nhdp.h"

/* definitions */

/**
 * Parameters of a NHDP domain
 */
struct _domain_parameters {
  /*! name of metric algorithm */
  char metric_name[NHDP_DOMAIN_METRIC_MAXLEN];

  /*! name of mpr algorithm for routing */
  char mpr_name[NHDP_DOMAIN_MPR_MAXLEN];

  /*! routing willingness */
  int32_t mpr_willingness;
};

/**
 * generic paramters for all domains
 */
struct _generic_parameters {
  /*! name of MPR algorithm for flooding */
  char flooding_mpr_name[NHDP_DOMAIN_MPR_MAXLEN];

  /*! routing willingness */
  int32_t mpr_willingness;
};

/* prototypes */
static void _early_cfg_init(void);
static int _init(void);
static void _initiate_shutdown(void);
static void _cleanup(void);

static bool _forwarding_selector(struct rfc5444_writer_target *rfc5444_target);

static void _cb_cfg_domain_changed(void);
static void _cb_cfg_interface_changed(void);
static void _cb_cfg_nhdp_changed(void);
static int _cb_validate_domain_section(const char *section_name,
    struct cfg_named_section *, struct autobuf *);

/* subsystem definition */
static struct cfg_schema_entry _nhdp_entries[] = {
  CFG_MAP_STRING_ARRAY(_generic_parameters, flooding_mpr_name, "mpr", "*",
      "ID of the mpr algorithm used for this domain. '"CFG_DOMAIN_NO_METRIC_MPR"'"
      " means no mpr algorithm (everyone is MPR), '"CFG_DOMAIN_ANY_METRIC_MPR"' means"
      " any metric that is loaded (with fallback on '"CFG_DOMAIN_NO_METRIC_MPR"').",
      NHDP_DOMAIN_MPR_MAXLEN),
  CFG_MAP_INT32_MINMAX(_generic_parameters, mpr_willingness, "willingness",
      RFC7181_WILLINGNESS_DEFAULT_STRING,
      "Flooding willingness for MPR calculation", 0, false,
      RFC7181_WILLINGNESS_MIN, RFC7181_WILLINGNESS_MAX),
};

static struct cfg_schema_section _nhdp_section = {
  .type = OONF_NHDP_SUBSYSTEM,
  .cb_delta_handler = _cb_cfg_nhdp_changed,
  .entries = _nhdp_entries,
  .entry_count = ARRAYSIZE(_nhdp_entries),
};

static struct cfg_schema_entry _interface_entries[] = {
  CFG_MAP_ACL_V46(nhdp_interface, ifaddr_filter, "ifaddr_filter",
      "-127.0.0.0/8\0-::1\0" ACL_DEFAULT_ACCEPT,
      "Filter for ip interface addresses that should be included in HELLO messages"),
  CFG_MAP_CLOCK_MIN(nhdp_interface, h_hold_time, "hello_validity", "20.0",
    "Validity time for NHDP Hello Messages", 100),
  CFG_MAP_CLOCK_MIN(nhdp_interface, refresh_interval, "hello_interval", "2.0",
    "Time interval between two NHDP Hello Messages", 100),
};

static struct cfg_schema_section _interface_section = {
  .type = CFG_INTERFACE_SECTION,
  .mode = CFG_INTERFACE_SECTION_MODE,
  .cb_delta_handler = _cb_cfg_interface_changed,
  .entries = _interface_entries,
  .entry_count = ARRAYSIZE(_interface_entries),
  .next_section = &_nhdp_section,
};

static struct cfg_schema_entry _domain_entries[] = {
  CFG_MAP_STRING_ARRAY(_domain_parameters, metric_name, "metric", CFG_DOMAIN_ANY_METRIC_MPR,
      "ID of the routing metric used for this domain. '"CFG_DOMAIN_NO_METRIC_MPR"'"
      " means no metric (hopcount!), '"CFG_DOMAIN_ANY_METRIC_MPR"' means any metric"
      " that is loaded (with fallback on '"CFG_DOMAIN_NO_METRIC_MPR"').",
      NHDP_DOMAIN_METRIC_MAXLEN),
  CFG_MAP_STRING_ARRAY(_domain_parameters, mpr_name,  "mpr", CFG_DOMAIN_ANY_METRIC_MPR,
      "ID of the mpr algorithm used for this domain. '"CFG_DOMAIN_NO_METRIC_MPR"'"
      " means no mpr algorithm (everyone is MPR), '"CFG_DOMAIN_ANY_METRIC_MPR"' means"
      " any metric that is loaded (with fallback on '"CFG_DOMAIN_NO_METRIC_MPR"').",
      NHDP_DOMAIN_MPR_MAXLEN),
  CFG_MAP_INT32_MINMAX(_domain_parameters, mpr_willingness, "willingness",
      RFC7181_WILLINGNESS_DEFAULT_STRING, "Routing willingness used for MPR calculation",
      0, false, RFC7181_WILLINGNESS_MIN, RFC7181_WILLINGNESS_MAX),
};

static struct cfg_schema_section _domain_section = {
  .type = CFG_NHDP_DOMAIN_SECTION,
  .mode = CFG_SSMODE_NAMED_WITH_DEFAULT,
  .def_name = CFG_NHDP_DEFAULT_DOMAIN,

  .cb_delta_handler = _cb_cfg_domain_changed,
  .cb_validate = _cb_validate_domain_section,

  .entries = _domain_entries,
  .entry_count = ARRAYSIZE(_domain_entries),
  .next_section = &_interface_section,
};

static const char *_dependencies[] = {
  OONF_CLOCK_SUBSYSTEM,
  OONF_CLASS_SUBSYSTEM,
  OONF_INTERFACE_SUBSYSTEM,
  OONF_RFC5444_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
};
static struct oonf_subsystem nhdp_subsystem = {
  .name = OONF_NHDP_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .early_cfg_init = _early_cfg_init,
  .init = _init,
  .cleanup = _cleanup,
  .initiate_shutdown = _initiate_shutdown,
  .cfg_section = &_domain_section,
};
DECLARE_OONF_PLUGIN(nhdp_subsystem);

/* other global variables */
static struct oonf_rfc5444_protocol *_protocol;

/* NHDP originator address, might be undefined */
static struct netaddr _originator_v4, _originator_v6;

/* logging sources for NHDP subsystem */
enum oonf_log_source LOG_NHDP;
enum oonf_log_source LOG_NHDP_R;
enum oonf_log_source LOG_NHDP_W;

/**
 * Initialize additional logging sources for NHDP
 */
static void
_early_cfg_init(void) {
  LOG_NHDP = nhdp_subsystem.logging;
  LOG_NHDP_R = oonf_log_register_source(OONF_NHDP_SUBSYSTEM "_r");
  LOG_NHDP_W = oonf_log_register_source(OONF_NHDP_SUBSYSTEM "_w");
}

/**
 * Initialize NHDP subsystem
 * @return 0 if initialized, -1 if an error happened
 */
static int
_init(void) {
  _protocol = oonf_rfc5444_get_default_protocol();
  if (nhdp_writer_init(_protocol)) {
    return -1;
  }

  nhdp_db_init();
  nhdp_reader_init(_protocol);
  nhdp_interfaces_init(_protocol);
  nhdp_domain_init(_protocol);

  return 0;
}

/**
 * Begin shutdown by deactivating reader and writer
 */
static void
_initiate_shutdown(void) {
  nhdp_writer_cleanup();
  nhdp_reader_cleanup();
}

/**
 * Cleanup NHDP subsystem
 */
static void
_cleanup(void) {
  nhdp_db_cleanup();
  nhdp_interfaces_cleanup();
  nhdp_domain_cleanup();
}

/**
 * Sets the originator address used by NHDP to a new value.
 * @param addr NHDP originator.
 */
void
nhdp_set_originator(const struct netaddr *addr) {
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  OONF_DEBUG(LOG_NHDP, "Set originator to %s", netaddr_to_string(&buf, addr));
  if (netaddr_get_address_family(addr) == AF_INET) {
    memcpy(&_originator_v4, addr, sizeof(*addr));
  }
  else if (netaddr_get_address_family(addr) == AF_INET6) {
    memcpy(&_originator_v6, addr, sizeof(*addr));
  }
}

/**
 * Remove the originator currently set
 * @param af_type address family type of the originator
 *   (AF_INET or AF_INET6)
 */
void
nhdp_reset_originator(int af_type) {
  if (af_type == AF_INET) {
    netaddr_invalidate(&_originator_v4);
  }
  else if (af_type == AF_INET6) {
    netaddr_invalidate(&_originator_v6);
  }
}

/**
 * @param af_type address family type of the originator
 *   (AF_INET or AF_INET6)
 * @return current NHDP originator
 */
const struct netaddr *
nhdp_get_originator(int af_type) {
  if (af_type == AF_INET) {
    return &_originator_v4;
  }
  else if (af_type == AF_INET6) {
    return &_originator_v6;
  }
  return NULL;
}

/**
 * default implementation for rfc5444 flooding target selection to
 * handle dualstack correctly.
 * @param writer rfc5444 protocol to flood messages
 * @param rfc5444_target rfc5444 target to flood message
 * @param ptr custom pointer for message flooding callback
 * @return true if message should be flooded
 */
bool
nhdp_flooding_selector(struct rfc5444_writer *writer __attribute__((unused)),
    struct rfc5444_writer_target *rfc5444_target, void *ptr __attribute__((unused))) {
  return _forwarding_selector(rfc5444_target);
}

/**
 * default implementation for rfc5444 forwarding selector to
 * hangle dualstack correctly
 * @param rfc5444_target rfc5444 target to flood message to
 * @param context reader context of the message to be forwarded
 * @param msg pointer to message buffer
 * @param len length of message buffer
 * @return true if target corresponds to selection
 */
bool
nhdp_forwarding_selector(struct rfc5444_writer_target *rfc5444_target,
    struct rfc5444_reader_tlvblock_context *context __attribute__((unused)),
    const uint8_t *msg __attribute__((unused)), size_t len __attribute__((unused))) {
  return _forwarding_selector(rfc5444_target);
}

/**
 * default implementation for rfc5444 forwarding selector to
 * hangle dualstack correctly
 * @param writer rfc5444 writer
 * @param target rfc5444 target
 * @param ptr custom pointer, contains rfc5444 target
 * @return true if target corresponds to selection
 */
static bool
_forwarding_selector(struct rfc5444_writer_target *rfc5444_target) {
  struct oonf_rfc5444_target *target;
  struct nhdp_interface *interf;
  bool is_ipv4, flood;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif
  target = container_of(rfc5444_target, struct oonf_rfc5444_target, rfc5444_target);

  /* test if this is the ipv4 multicast target */
  is_ipv4 = target == target->interface->multicast4;

  /* only forward to multicast targets */
  if (!is_ipv4 && target != target->interface->multicast6) {
    return false;
  }

  /* get NHDP interface for target */
  interf = nhdp_interface_get(target->interface->name);
  if (interf == NULL) {
    OONF_DEBUG(LOG_NHDP, "Do not flood message type"
        " to interface %s: its unknown to NHDP",
        target->interface->name);
    return NULL;
  }

  /* lookup flooding cache in NHDP interface */
  if (is_ipv4) {
    flood = interf->use_ipv4_for_flooding
        || interf->dualstack_af_type == AF_INET;
  }
  else {
    flood =  interf->use_ipv6_for_flooding
        || interf->dualstack_af_type == AF_INET6;
  }

  OONF_DEBUG(LOG_NHDP, "Flooding to target %s: %s",
      netaddr_to_string(&buf, &target->dst), flood ? "yes" : "no");

  return flood;
}

/**
 * Configuration of a NHDP domain changed
 */
static void
_cb_cfg_domain_changed(void) {
  struct _domain_parameters param;
  int ext;

  OONF_INFO(LOG_NHDP, "Received domain cfg change for name '%s': %s %s",
      _domain_section.section_name,
      _domain_section.pre != NULL ? "pre" : "-",
      _domain_section.post != NULL ? "post" : "-");

  ext = strtol(_domain_section.section_name, NULL, 10);

  if (cfg_schema_tobin(&param, _domain_section.post,
      _domain_entries, ARRAYSIZE(_domain_entries))) {
    OONF_WARN(LOG_NHDP, "Cannot convert NHDP domain configuration.");
    return;
  }

  nhdp_domain_configure(ext, param.metric_name,
      param.mpr_name, param.mpr_willingness);
}

/**
 * Configuration has changed, handle the changes
 */
static void
_cb_cfg_interface_changed(void) {
  struct nhdp_interface *interf;

  OONF_DEBUG(LOG_NHDP, "Configuration of NHDP interface %s changed",
      _interface_section.section_name);

  /* get interface */
  interf = nhdp_interface_get(_interface_section.section_name);

  if (_interface_section.post == NULL) {
    /* section was removed */
    if (interf != NULL) {
      nhdp_interface_remove(interf);
    }
    return;
  }

  if (interf == NULL) {
    interf = nhdp_interface_add(_interface_section.section_name);
  }

  if (cfg_schema_tobin(interf, _interface_section.post,
      _interface_entries, ARRAYSIZE(_interface_entries))) {
    OONF_WARN(LOG_NHDP, "Cannot convert NHDP configuration for interface.");
    return;
  }

  /* apply new settings to interface */
  nhdp_interface_apply_settings(interf);
}

static void
_cb_cfg_nhdp_changed(void) {
  struct _generic_parameters param;
  if (cfg_schema_tobin(&param, _nhdp_section.post,
      _nhdp_entries, ARRAYSIZE(_nhdp_entries))) {
    OONF_WARN(LOG_NHDP, "Cannot convert NHDP configuration.");
    return;
  }

  nhdp_domain_set_flooding_mpr(param.flooding_mpr_name, param.mpr_willingness);
}

/**
 * Validate that the name of the domain section is valid
 * @param section_name name of section including type
 * @param named cfg named section
 * @param out output buffer for errors
 * @return -1 if invalid, 0 otherwise
 */
static int
_cb_validate_domain_section(const char *section_name,
    struct cfg_named_section *named, struct autobuf *out) {
  char *error = NULL;
  int ext;

  if (!named->name) {
    /* default name should be okay */
    return 0;
  }

  ext = strtol(named->name, &error, 10);
  if (error != NULL && *error != 0) {
    /* illegal domain name */
    abuf_appendf(out, "name of section '%s' must be a number between 0 and 255",
        section_name);
    return -1;
  }

  if (ext < 0 || ext > 255) {
    /* name out of range */
    abuf_appendf(out, "name of section '%s' must be a number between 0 and 255",
        section_name);
    return -1;
  }
  return 0;
}
