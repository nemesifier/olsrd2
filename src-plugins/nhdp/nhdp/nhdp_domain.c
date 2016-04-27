
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

#include <stdio.h>

#include "common/avl.h"
#include "common/avl_comp.h"
#include "common/common_types.h"
#include "common/list.h"
#include "common/netaddr.h"
#include "core/oonf_cfg.h"
#include "core/oonf_logging.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_rfc5444.h"

#include "nhdp/nhdp.h"
#include "nhdp/nhdp_db.h"
#include "nhdp/nhdp_domain.h"
#include "nhdp/nhdp_interfaces.h"
#include "nhdp/nhdp_internal.h"

static void _apply_metric(struct nhdp_domain *domain, const char *metric_name);
static void _remove_metric(struct nhdp_domain *);
static void _apply_mpr(struct nhdp_domain *domain,
    const char *mpr_name, uint8_t willingness);
static void _remove_mpr(struct nhdp_domain *);

static void _cb_update_everyone_mpr(void);

static void _recalculate_neighbor_metric(struct nhdp_domain *domain,
        struct nhdp_neighbor *neigh);
static const char *_link_to_string(struct nhdp_metric_str *, uint32_t);
static const char *_path_to_string(struct nhdp_metric_str *, uint32_t, uint8_t);
static const char *_int_to_string(struct nhdp_metric_str *, struct nhdp_link *);

/* domain class */
static struct oonf_class _domain_class = {
  .name = NHDP_CLASS_DOMAIN,
  .size = sizeof(struct nhdp_domain),
};

/* default metric handler (hopcount) */
static struct nhdp_domain_metric _no_metric = {
  .name = "Hopcount metric",

  .incoming_link_start = RFC7181_METRIC_MAX,
  .outgoing_link_start = RFC7181_METRIC_MAX,
  .incoming_2hop_start = RFC7181_METRIC_MAX,
  .outgoing_2hop_start = RFC7181_METRIC_MAX,

  .link_to_string = _link_to_string,
  .path_to_string = _path_to_string,
  .internal_link_to_string = _int_to_string,

  .no_default_handling = true,
};

/* default MPR handler (no MPR handling) */
static struct nhdp_domain_mpr _everyone_mprs = {
  .name = "Everyone MPR",

  .mpr_start = true,
  .mprs_start = true,

  .update_mpr = _cb_update_everyone_mpr,
};

/* non-default routing domains registered to NHDP */
static struct list_entity _domain_list;
static struct list_entity _domain_listener_list;

static size_t _domain_counter = 0;

/* tree of known routing metrics/mpr-algorithms */
static struct avl_tree _domain_metrics;
static struct avl_tree _domain_mprs;

/* flooding domain */
static struct nhdp_domain _flooding_domain;

/* NHDP RFC5444 protocol */
static struct oonf_rfc5444_protocol *_protocol;

/* remember if node is MPR or not */
static bool _node_is_selected_as_mpr = false;

/**
 * Initialize nhdp metric core
 * @param p pointer to rfc5444 protocol
 */
void
nhdp_domain_init(struct oonf_rfc5444_protocol *p) {
  _protocol = p;

  oonf_class_add(&_domain_class);
  list_init_head(&_domain_list);
  list_init_head(&_domain_listener_list);

  avl_init(&_domain_metrics, avl_comp_strcasecmp, false);
  avl_init(&_domain_mprs, avl_comp_strcasecmp, false);

  /* initialize flooding domain */
  _flooding_domain.metric = &_no_metric;
  _flooding_domain.mpr = &_everyone_mprs;

  _flooding_domain.mpr->_refcount++;
  _flooding_domain.metric->_refcount++;
}

/**
 * cleanup allocated resources for nhdp metric core
 */
void
nhdp_domain_cleanup(void) {
  struct nhdp_domain *domain, *d_it;
  struct nhdp_domain_listener *listener, *l_it;
  int i;

  list_for_each_element_safe(&_domain_list, domain, _node, d_it) {
    /* free allocated TLVs */
    for (i=0; i<4; i++) {
      rfc5444_writer_unregister_addrtlvtype(
          &_protocol->writer, &domain->_metric_addrtlvs[i]);
    }

    /* remove domain */
    list_remove(&domain->_node);
    oonf_class_free(&_domain_class, domain);
  }

  list_for_each_element_safe(&_domain_listener_list, listener, _node, l_it) {
    nhdp_domain_listener_remove(listener);
  }
  oonf_class_remove(&_domain_class);
}

/**
 * @return number of registered nhdp domains
 */
size_t
nhdp_domain_get_count(void) {
  return _domain_counter;
}

/**
 * Add a new metric handler to nhdp
 * @param metric pointer to NHDP link metric
 * @return 0 if successful, -1 if metric was already registered
 */
int
nhdp_domain_metric_add(struct nhdp_domain_metric *metric) {
  /* initialize key */
  metric->_node.key = metric->name;

  /* insert default values if not set */
  if (metric->incoming_link_start == 0) {
    metric->incoming_link_start = RFC7181_METRIC_MAX;
  }
  if (metric->outgoing_link_start == 0) {
    metric->outgoing_link_start = RFC7181_METRIC_INFINITE;
  }
  if (metric->incoming_2hop_start == 0) {
    metric->incoming_2hop_start = RFC7181_METRIC_INFINITE;
  }
  if (metric->outgoing_2hop_start == 0) {
    metric->outgoing_2hop_start = RFC7181_METRIC_INFINITE;
  }

  /* initialize to_string method if empty */
  if (metric->link_to_string == NULL) {
    metric->link_to_string = _link_to_string;
  }
  if (metric->path_to_string == NULL) {
    metric->path_to_string = _path_to_string;
  }

  if (metric->internal_link_to_string == NULL) {
    metric->internal_link_to_string = _int_to_string;
  }

  /* hook into tree */
  return avl_insert(&_domain_metrics, &metric->_node);
}

/**
 * Remove a metric handler from the nhdp metric core
 * @param metric pointer to metric handler
 */
void
nhdp_domain_metric_remove(struct nhdp_domain_metric *metric) {
  struct nhdp_domain *domain;

  list_for_each_element(&_domain_list, domain, _node) {
    if (domain->metric == metric) {
      _remove_metric(domain);
      break;
    }
  }

  avl_remove(&_domain_metrics, &metric->_node);
}

/**
 * Add a new mpr handler to nhdp
 * @param mpr pointer to mpr handler
 * @return 0 if successful, -1 if metric is already registered
 */
int
nhdp_domain_mpr_add(struct nhdp_domain_mpr *mpr) {
  struct nhdp_domain *domain;

  /* initialize key */
  mpr->_node.key = mpr->name;

  if (avl_insert(&_domain_mprs, &mpr->_node)) {
    return -1;
  }

  list_for_each_element(&_domain_list, domain, _node) {
    if (domain->mpr == &_everyone_mprs) {
      _apply_mpr(domain, domain->mpr_name, domain->local_willingness);
    }
  }
  if (_flooding_domain.mpr == &_everyone_mprs) {
    _apply_mpr(&_flooding_domain,
        _flooding_domain.mpr_name, _flooding_domain.local_willingness);
  }
  return 0;
}

/**
 * Remove a metric handler from the nhdp metric core
 * @param mpr pointer to mpr handler
 */
void
nhdp_domain_mpr_remove(struct nhdp_domain_mpr *mpr) {
  struct nhdp_domain *domain;

  list_for_each_element(&_domain_list, domain, _node) {
    if (domain->mpr == mpr) {
      _remove_mpr(domain);
      break;
    }
  }

  avl_remove(&_domain_mprs, &mpr->_node);
}

/**
 * Adds a listener to the NHDP domain system
 * @param listener pointer to NHDP domain listener
 */
void
nhdp_domain_listener_add(struct nhdp_domain_listener *listener) {
  list_add_tail(&_domain_listener_list, &listener->_node);
}

/**
 * Removes a listener from the NHDP domain system
 * @param listener pointer to NHDP domain listener
 */
void
nhdp_domain_listener_remove(struct nhdp_domain_listener *listener) {
  if (list_is_node_added(&listener->_node)) {
    list_remove(&listener->_node);
  }
}

/**
 * @param ext TLV extension value of MPR/Linkmetrics
 * @return NHDP domain registered to this extension, NULL if not found
 */
struct nhdp_domain *
nhdp_domain_get_by_ext(uint8_t ext) {
  struct nhdp_domain *d;

  list_for_each_element(&_domain_list, d, _node) {
    if (d->ext == ext) {
      return d;
    }
  }
  return NULL;
}

/**
 * Initialize the domain data of a new NHDP link
 * @param lnk NHDP link
 */
void
nhdp_domain_init_link(struct nhdp_link *lnk) {
  struct nhdp_domain *domain;
  struct nhdp_link_domaindata *data;
  int i;

  /* initialize metrics */
  for (i=0; i<NHDP_MAXIMUM_DOMAINS; i++) {
    lnk->_domaindata[i].metric.in = RFC7181_METRIC_MAX;
    lnk->_domaindata[i].metric.out = RFC7181_METRIC_MAX;
  }
  list_for_each_element(&_domain_list, domain, _node) {
    data = nhdp_domain_get_linkdata(domain, lnk);

    data->metric.in = domain->metric->incoming_link_start;
    data->metric.out = domain->metric->outgoing_link_start;
  }
}

/**
 * Initialize the domain data of a new NHDP twohop neighbor
 * @param l2hop NHDP twohop neighbor
 */
void
nhdp_domain_init_l2hop(struct nhdp_l2hop *l2hop) {
  struct nhdp_domain *domain;
  struct nhdp_l2hop_domaindata *data;
  int i;

  /* initialize metrics */
  for (i=0; i<NHDP_MAXIMUM_DOMAINS; i++) {
    l2hop->_domaindata[i].metric.in = RFC7181_METRIC_MAX;
    l2hop->_domaindata[i].metric.out = RFC7181_METRIC_MAX;
  }

  list_for_each_element(&_domain_list, domain, _node) {
    data = nhdp_domain_get_l2hopdata(domain, l2hop);

    data->metric.in = domain->metric->incoming_2hop_start;
    data->metric.out = domain->metric->outgoing_2hop_start;
  }
}

/**
 * Initialize the domain data of a new NHDP neighbor
 * @param neigh NHDP neighbor
 */
void
nhdp_domain_init_neighbor(struct nhdp_neighbor *neigh) {
  struct nhdp_domain *domain;
  struct nhdp_neighbor_domaindata *data;
  int i;

  /* initialize flooding MPR settings */
  neigh->flooding_willingness = RFC7181_WILLINGNESS_NEVER;
  neigh->local_is_flooding_mpr = _flooding_domain.mpr->mprs_start;
  neigh->neigh_is_flooding_mpr = _flooding_domain.mpr->mpr_start;

  for (i=0; i<NHDP_MAXIMUM_DOMAINS; i++) {
    neigh->_domaindata[i].metric.in = RFC7181_METRIC_MAX;
    neigh->_domaindata[i].metric.out = RFC7181_METRIC_MAX;
  }

  /* initialize metrics and mprs */
  list_for_each_element(&_domain_list, domain, _node) {
    data = nhdp_domain_get_neighbordata(domain, neigh);

    data->metric.in = domain->metric->incoming_link_start;
    data->metric.out = domain->metric->outgoing_link_start;

    data->best_link = NULL;

    data->willingness = RFC7181_WILLINGNESS_NEVER;
    data->local_is_mpr = domain->mpr->mprs_start;
    data->neigh_is_mpr = domain->mpr->mpr_start;
  }
}

/**
 * Process an in linkmetric tlv for a nhdp link
 * @param domain pointer to NHDP domain
 * @param lnk pointer to nhdp link
 * @param value pointer to value of metric tlv,
 *   must have a length of at least 2
 */
void
nhdp_domain_process_metric_linktlv(struct nhdp_domain *domain,
    struct nhdp_link *lnk, uint8_t *value) {
  struct rfc7181_metric_field metric_field;
  uint32_t metric;

  memcpy(&metric_field, value, sizeof(metric_field));
  metric = rfc7181_metric_decode(&metric_field);

  if (rfc7181_metric_has_flag(&metric_field, RFC7181_LINKMETRIC_INCOMING_LINK)) {
    nhdp_domain_get_linkdata(domain, lnk)->metric.out = metric;
  }
  if (rfc7181_metric_has_flag(&metric_field, RFC7181_LINKMETRIC_INCOMING_NEIGH)) {
    nhdp_domain_get_neighbordata(domain, lnk->neigh)->metric.out = metric;
  }
}

/**
 * Process an in linkmetric tlv for a nhdp twohop neighbor
 * @param domain pointer to NHDP domain
 * @param l2hop pointer to nhdp twohop neighbor
 * @param value value of metric tlv
 */
void
nhdp_domain_process_metric_2hoptlv(struct nhdp_domain *domain,
    struct nhdp_l2hop *l2hop, uint8_t *value) {
  struct rfc7181_metric_field metric_field;
  struct nhdp_l2hop_domaindata *data;
  uint32_t metric;

  memcpy(&metric_field, value, sizeof(metric_field));
  metric = rfc7181_metric_decode(&metric_field);

  data = nhdp_domain_get_l2hopdata(domain, l2hop);
  if (rfc7181_metric_has_flag(&metric_field, RFC7181_LINKMETRIC_INCOMING_NEIGH)) {
    data->metric.in = metric;
  }
  if (rfc7181_metric_has_flag(&metric_field, RFC7181_LINKMETRIC_OUTGOING_NEIGH)) {
    data->metric.out = metric;
  }
}

/**
 * Neighborhood changed in terms of metrics or connectivity.
 * This will trigger a MPR set recalculation.
 */
void
nhdp_domain_neighborhood_changed(void) {
  struct nhdp_domain_listener *listener;
  struct nhdp_domain *domain;
  struct nhdp_neighbor *neigh;
  
  list_for_each_element(&_domain_list, domain, _node) {
    list_for_each_element(nhdp_db_get_neigh_list(), neigh, _global_node) {
      _recalculate_neighbor_metric(domain, neigh);
    }

    if (domain->mpr->update_mpr != NULL) {
      domain->mpr->update_mpr();
    }
  }

  // TODO: flooding mpr ?
  // (Why do we need to consider flooding MPRs here?)

  list_for_each_element(&_domain_listener_list, listener, _node) {
    if (listener->update) {
      listener->update(NULL);
    }
  }

  /* check if we still have routing MPR selectors */
  OONF_DEBUG(LOG_NHDP, "Checking if we still have routing MPR selectors");
  _node_is_selected_as_mpr = false;

  list_for_each_element(&_domain_list, domain, _node) {
    list_for_each_element(nhdp_db_get_neigh_list(), neigh, _global_node) {
      if (nhdp_domain_get_neighbordata(domain, neigh)->local_is_mpr) {
        _node_is_selected_as_mpr = true;
        return;
      }
    }
  }
}

/**
 * One neighbor changed in terms of metrics or connectivity.
 * This will trigger a MPR set recalculation.
 * @param neigh neighbor where the changed happened
 */
void
nhdp_domain_neighbor_changed(struct nhdp_neighbor *neigh) {
  struct nhdp_domain_listener *listener;
  struct nhdp_domain *domain;
  

  list_for_each_element(&_domain_list, domain, _node) {
    _recalculate_neighbor_metric(domain, neigh);

    if (domain->mpr->update_mpr != NULL) {
      domain->mpr->update_mpr();
    }
  }

  // TODO: flooding mpr ?
  // (Why do we need to consider flooding MPRs here?)

  list_for_each_element(&_domain_listener_list, listener, _node) {
    if (listener->update) {
      listener->update(neigh);
    }
  }

  /* check if we still have routing MPR selectors */
  OONF_DEBUG(LOG_NHDP, "Checking if we still have routing MPR selectors");
  _node_is_selected_as_mpr = false;

  list_for_each_element(&_domain_list, domain, _node) {
    list_for_each_element(nhdp_db_get_neigh_list(), neigh, _global_node) {
      if (nhdp_domain_get_neighbordata(domain, neigh)->local_is_mpr) {
        _node_is_selected_as_mpr = true;
        return;
      }
    }
  }
}

/**
 * @return true if this node is selected as a MPR by any other node
 */
bool
nhdp_domain_node_is_mpr(void) {
  return _node_is_selected_as_mpr;
}

/**
 *
 * @param mprtypes destination buffer for mpr types
 * @param mprtypes_size size of destination buffer
 * @param tlv pointer to mprtypes TLV, might be NULL
 * @return number of bytes written into destination buffer
 */
size_t
nhdp_domain_process_mprtypes_tlv(
    uint8_t *mprtypes, size_t mprtypes_size,
    struct rfc5444_reader_tlvblock_entry *tlv) {
  struct nhdp_domain *domain;
  size_t count;

  if (!tlv) {
    domain = list_first_element(&_domain_list, domain, _node);
    mprtypes[0] = domain->ext;

    return 1;
  }

  memset(mprtypes, 255, mprtypes_size);

  count = 0;
  list_for_each_element(&_domain_list, domain, _node) {
    mprtypes[count++] = domain->ext;
    if (count >= mprtypes_size) {
      break;
    }
  }
  return count;
}

/**
 * Process an in MPR tlv for a NHDP link
 * @param mprtypes list of extenstions for MPR
 * @param mprtypes_size length of mprtypes array
 * @param neigh NHDP neighbor
 * @param tlv MPR tlv context
 */
void
nhdp_domain_process_mpr_tlv(uint8_t *mprtypes, size_t mprtypes_size,
    struct nhdp_neighbor *neigh, struct rfc5444_reader_tlvblock_entry *tlv) {
  struct nhdp_domain *domain;
  size_t bit_idx, byte_idx;
  size_t i;

  neigh->local_is_flooding_mpr = false;
  list_for_each_element(&_domain_list, domain, _node) {
    nhdp_domain_get_neighbordata(domain, neigh)->local_is_mpr = false;
  }

  if (!tlv) {
    return;
  }

  /* set flooding MPR flag */
  neigh->local_is_flooding_mpr =
      (tlv->single_value[0] & RFC7181_MPR_FLOODING) != 0;
  OONF_DEBUG(LOG_NHDP_R, "Flooding MPR for neighbor: %s",
      neigh->local_is_flooding_mpr ? "true" : "false");

  /* set routing MPR flags */
  for (i=0; i<mprtypes_size; i++) {
    domain = nhdp_domain_get_by_ext(mprtypes[i]);
    if (domain == NULL) {
      continue;
    }
    bit_idx = (i + 1) & 7;
    byte_idx = (i + 1) >> 3;

    if (byte_idx >= tlv->length) {
      continue;
    }

    nhdp_domain_get_neighbordata(domain, neigh)->local_is_mpr =
        (tlv->single_value[byte_idx] & (1 << bit_idx)) != 0;

    OONF_DEBUG(LOG_NHDP_R, "Routing MPR for neighbor in domain %u: %s",
        domain->ext, nhdp_domain_get_neighbordata(domain, neigh)->local_is_mpr ? "true" : "false");
  }
}

/**
 * Process an in Willingness tlv and put values into
 * temporary storage in MPR handler object. Call
 * nhdp_domain_store_willingness to permanently store them later.
 * @param mprtypes list of extenstions for MPR
 * @param mprtypes_size length of mprtypes array
 * @param tlv Willingness tlv context
 */
void
nhdp_domain_process_willingness_tlv(
    uint8_t *mprtypes, size_t mprtypes_size,
    struct rfc5444_reader_tlvblock_entry *tlv) {
  struct nhdp_domain *domain;
  size_t idx, i;
  uint8_t value;

  _flooding_domain._tmp_willingness = RFC7181_WILLINGNESS_NEVER;
  list_for_each_element(&_domain_list, domain, _node) {
    domain->_tmp_willingness= RFC7181_WILLINGNESS_NEVER;
  }

  if (!tlv) {
    return;
  }

  /* copy flooding willingness */
  _flooding_domain._tmp_willingness
    = tlv->single_value[0] & RFC7181_WILLINGNESS_MASK;
  OONF_DEBUG(LOG_NHDP_R, "Received flooding willingness: %u",
      _flooding_domain._tmp_willingness);

  for (i=0; i<mprtypes_size; i++) {
    domain = nhdp_domain_get_by_ext(mprtypes[i]);
    if (domain == NULL) {
      continue;
    }

    idx = (i + 1) / 2;
    if (idx >= tlv->length) {
      continue;
    }

    value = tlv->single_value[idx];
    if ((domain->index & 1) == 0) {
      value >>= RFC7181_WILLINGNESS_SHIFT;
    }
    else {
      value &= RFC7181_WILLINGNESS_MASK;
    }

    domain->_tmp_willingness = value;

    OONF_DEBUG(LOG_NHDP_R, "Received routing willingness for domain %u: %u",
        domain->ext, domain->_tmp_willingness);
  }
}

/**
 * Stores the willingness data processed by
 * nhdp_domain_process_willingness_tlv() into a neighbor object
 * @param neigh NHDP neighbor
 */
void
nhdp_domain_store_willingness(struct nhdp_neighbor *neigh) {
  struct nhdp_neighbor_domaindata *neighdata;
  struct nhdp_domain *domain;

  neigh->flooding_willingness = _flooding_domain._tmp_willingness;
  OONF_DEBUG(LOG_NHDP_R, "Set flooding willingness: %u",
      neigh->flooding_willingness);

  list_for_each_element(&_domain_list, domain, _node) {
    neighdata = nhdp_domain_get_neighbordata(domain, neigh);
    neighdata->willingness = domain->_tmp_willingness;
    OONF_DEBUG(LOG_NHDP_R, "Set routing willingness for domain %u: %u",
        domain->ext, neighdata->willingness);
  }
}

/**
 * Generate MPRTYPES tlv value
 * @param mprtypes pointer to destination buffer for value
 * @param mprtypes_size length of destination buffer
 * @return number of bytes written into buffer
 */
size_t
nhdp_domain_encode_mprtypes_tlvvalue(
    uint8_t *mprtypes, size_t mprtypes_size) {
  struct nhdp_domain *domain;
  size_t count;

  count = 0;
  list_for_each_element(&_domain_list, domain, _node) {
    mprtypes[count++] = domain->ext;

    if (count >= mprtypes_size) {
      break;
    }
  }

  return count;
}

/**
 * Calculates the tlvvalue of a MPR tlv
 *
 * @param tlvvalue destination for value of MPR tlv
 * @param tlvsize length of tlv value
 * @param neigh pointer to NHDP neighbor for MPR tlv
 * @return length of tlvvalue, 0 if an error happened
 */
size_t
nhdp_domain_encode_mpr_tlvvalue(
    uint8_t *tlvvalue, size_t tlvsize, struct nhdp_neighbor *neigh) {
  struct nhdp_domain *domain;
  size_t bit_idx, byte_idx, len;

  memset(tlvvalue, 0, tlvsize);
  len = 0;
  /* set flooding MPR flag */
  if (neigh->neigh_is_flooding_mpr) {
    tlvvalue[0] |= RFC7181_MPR_FLOODING;
  }

  OONF_DEBUG(LOG_NHDP_W, "Set flooding MPR: %s",
      neigh->neigh_is_flooding_mpr ? "true" : "false");

  list_for_each_element(&_domain_list, domain, _node) {
    bit_idx = (domain->index + 1) & 7;
    byte_idx = (domain->index + 1) >> 3;

    if (byte_idx >= tlvsize) {
      return 0;
    }
    if (byte_idx+1 > len) {
      len = byte_idx + 1;
    }

    if (nhdp_domain_get_neighbordata(domain, neigh)->neigh_is_mpr) {
      tlvvalue[byte_idx] |= (1 << bit_idx);
    }

    OONF_DEBUG(LOG_NHDP_W, "Set routing MPR for domain %u: %s",
        domain->ext, nhdp_domain_get_neighbordata(domain, neigh)->neigh_is_mpr ? "true" : "false");
  }
  return len;
}

/**
 * Calculates the tlvvalue of a Willingness tlv
 * @param tlvvalue destination array
 * @param tlvsize length of destination array
 * @return length of tlvvalue, 0 if an error happened
 */
size_t
nhdp_domain_encode_willingness_tlvvalue(uint8_t *tlvvalue, size_t tlvsize) {
  struct nhdp_domain *domain;
  uint8_t value;
  size_t idx, len;

  memset(tlvvalue, 0, tlvsize);
  len = 0;

  /* set flooding willingness */
  tlvvalue[0] = _flooding_domain.local_willingness;
  OONF_DEBUG(LOG_NHDP_W, "Set flooding willingness: %u",
      _flooding_domain.local_willingness);

  /* set routing willingness */
  list_for_each_element(&_domain_list, domain, _node) {
    idx = (domain->index + 1) / 2;
    if (idx >= tlvsize) {
      return -1;
    }
    if (idx+1 > len) {
      len = idx + 1;
    }

    value = domain->local_willingness & RFC7181_WILLINGNESS_MASK;

    if ((domain->index & 1) == 0) {
      value <<= RFC7181_WILLINGNESS_SHIFT;
    }

    OONF_DEBUG(LOG_NHDP_W, "Set routing willingness for domain %u: %x"
        " (%"PRINTF_SIZE_T_SPECIFIER")",
        domain->ext, value, idx);

    tlvvalue[idx] |= value;
  }

  return len;
}

/**
 * Sets a new flodding MPR algorithm
 * @param mpr_name name of MPR algorithm
 * @param willingness of MPR algorithm
 */
void
nhdp_domain_set_flooding_mpr(const char *mpr_name, uint8_t willingness) {
  _apply_mpr(&_flooding_domain, mpr_name, willingness);
}

/**
 * Sets the incoming metric of a link. This is the only function external
 * code should use to commit the calculated metric values to the nhdp db.
 * @param metric NHDP domain metric
 * @param lnk NHDP link
 * @param metric_in incoming metric value for NHDP link
 * @return true if metric changed, false otherwise
 */
bool
nhdp_domain_set_incoming_metric(struct nhdp_domain_metric *metric,
    struct nhdp_link *lnk, uint32_t metric_in) {
  struct nhdp_link_domaindata *linkdata;
  struct nhdp_domain *domain;
  bool changed;

  changed = false;
  list_for_each_element(&_domain_list, domain, _node) {
    if (domain->metric == metric) {
      linkdata = nhdp_domain_get_linkdata(domain, lnk);
      changed |= (linkdata->metric.in != metric_in);
      linkdata->metric.in = metric_in;
    }
  }
  return changed;
}

/**
 * get list of nhdp domains
 * @return domain list
 */
struct list_entity *
nhdp_domain_get_list(void) {
  return &_domain_list;
}

/**
 * get list of nhdp domain listeners for metric/mpr changes
 * @return listener list
 */
struct list_entity *
nhdp_domain_get_listener_list(void) {
  return &_domain_listener_list;
}

/**
 * get current NHDP flooding domain
 * @return flooding domain
 */
const struct nhdp_domain *
nhdp_domain_get_flooding(void) {
  return &_flooding_domain;
}

/**
 * Recalculate the 'best link/metric' values of a neighbor
 * @param domain NHDP domain
 * @param neigh NHDP neighbor
 */
static void
_recalculate_neighbor_metric(
    struct nhdp_domain *domain,
    struct nhdp_neighbor *neigh) {
  struct nhdp_link *lnk;
  struct nhdp_link_domaindata *linkdata;
  struct nhdp_neighbor_domaindata *neighdata;
  struct nhdp_metric oldmetric;

  neighdata = nhdp_domain_get_neighbordata(domain, neigh);

  /* copy old metric value */
  memcpy(&oldmetric, &neighdata->metric, sizeof(oldmetric));

  /* reset metric */
  neighdata->metric.in = RFC7181_METRIC_INFINITE;
  neighdata->metric.out = RFC7181_METRIC_INFINITE;

  /* reset best link */
  neighdata->best_link = NULL;

  /* get best metric */
  list_for_each_element(&neigh->_links, lnk, _neigh_node) {
    linkdata = nhdp_domain_get_linkdata(domain, lnk);

    if (linkdata->metric.out < neighdata->metric.out) {
      neighdata->metric.out = linkdata->metric.out;
      neighdata->best_link = lnk;
    }
    if (linkdata->metric.in < neighdata->metric.in) {
      neighdata->metric.in = linkdata->metric.in;
    }
  }

  if (neighdata->best_link != NULL) {
    neighdata->best_link_ifindex =
        nhdp_interface_get_if_listener(neighdata->best_link->local_if)->data->index;
  }

  if (memcmp(&oldmetric, &neighdata->metric, sizeof(oldmetric)) != 0) {
    /* mark metric as updated */
    domain->neighbor_metric_changed = true;
  }
}

/**
 * Add a new domain to the NHDP system
 * @param ext TLV extension type used for new domain
 * @return pointer to new domain, NULL, if out of memory or
 *   maximum number of domains has been reached.
 */
struct nhdp_domain *
nhdp_domain_add(uint8_t ext) {
  struct nhdp_domain *domain;
  int i;

  domain = nhdp_domain_get_by_ext(ext);
  if (domain) {
    return domain;
  }

  if (_domain_counter == NHDP_MAXIMUM_DOMAINS) {
    OONF_WARN(LOG_NHDP, "Maximum number of NHDP domains reached: %d",
        NHDP_MAXIMUM_DOMAINS);
    return NULL;
  }

  /* initialize new domain */
  domain = oonf_class_malloc(&_domain_class);
  if (domain == NULL) {
    return NULL;
  }

  domain->ext = ext;
  domain->index = _domain_counter++;
  domain->metric = &_no_metric;
  domain->mpr = &_everyone_mprs;

  domain->mpr->_refcount++;
  domain->metric->_refcount++;

  /* initialize metric TLVs */
  for (i=0; i<4; i++) {
    domain->_metric_addrtlvs[i].type = RFC7181_ADDRTLV_LINK_METRIC;
    domain->_metric_addrtlvs[i].exttype = domain->ext;

    rfc5444_writer_register_addrtlvtype(&_protocol->writer,
        &domain->_metric_addrtlvs[i], -1);
  }

  /* add to domain list */
  list_add_tail(&_domain_list, &domain->_node);

  oonf_class_event(&_domain_class, domain,OONF_OBJECT_ADDED);
  return domain;
}

/**
 * Configure a NHDP domain to a metric and a MPR algorithm
 * @param ext TLV extension type used for new domain
 * @param metric_name name of the metric algorithm to be used,
 *   might be CFG_DOMAIN_NO_METRIC (for hopcount metric)
 *   or CFG_DOMAIN_ANY_METRIC (for a metric the NHDP core should
 *   choose).
 * @param mpr_name name of the MPR algorithm to be used,
 *   might be CFG_DOMAIN_NO_MPR (every node is MPR)
 *   or CFG_DOMAIN_ANY_MPR (for a MPR the NHDP core should
 *   choose).
 * @param willingness routing willingness for domain
 * @return pointer to configured domain, NULL, if out of memory or
 *   maximum number of domains has been reached.
 */
struct nhdp_domain *
nhdp_domain_configure(uint8_t ext, const char *metric_name,
    const char *mpr_name, uint8_t willingness) {
  struct nhdp_domain *domain;

  domain = nhdp_domain_add(ext);
  if (domain == NULL) {
    return NULL;
  }

  OONF_DEBUG(LOG_NHDP, "Configure domain %u to metric=%s",
      domain->index, metric_name);
  _apply_metric(domain, metric_name);

  OONF_DEBUG(LOG_NHDP, "Configure domain %u to mpr=%s, willingness=%u",
      domain->index, mpr_name, willingness);
  _apply_mpr(domain, mpr_name, willingness);

  oonf_class_event(&_domain_class, domain, OONF_OBJECT_CHANGED);

  return domain;
}

/**
 * Apply a new metric algorithm to a NHDP domain
 * @param domain pointer to NHDP domain
 * @param metric_name name of the metric algorithm to be used,
 *   might be CFG_DOMAIN_NO_METRIC (for hopcount metric)
 *   or CFG_DOMAIN_ANY_METRIC (for a metric the NHDP core should
 *   choose).
 */
static void
_apply_metric(struct nhdp_domain *domain, const char *metric_name) {
  struct nhdp_domain_metric *metric;

  /* check if we have to remove the old metric first */
  if (strcasecmp(domain->metric_name, metric_name) == 0) {
    /* nothing to do, we already have the right metric */
    return;
  }

  if (domain->metric != &_no_metric) {
    _remove_metric(domain);
  }

  /* Handle wildcard metric name first */
  if (strcasecmp(metric_name, CFG_DOMAIN_ANY_METRIC_MPR) == 0
      && !avl_is_empty(&_domain_metrics)) {
    metric_name = avl_first_element(&_domain_metrics, metric, _node)->name;
  }

  /* look for metric implementation */
  metric = avl_find_element(&_domain_metrics, metric_name, metric, _node);
  if (metric == NULL) {
    metric = &_no_metric;
  }

  /* copy new metric name */
  strscpy(domain->metric_name, metric->name, sizeof(domain->metric_name));

  /* link domain and metric */
  domain->metric->_refcount--;
  domain->metric = metric;

  /* activate metric */
  if (metric->_refcount == 0 && metric->enable) {
    metric->enable();
  }
  metric->_refcount++;
}

/**
 * Reset the metric of a NHDP domain to hopcount
 * @param domain pointer to NHDP domain
 */
static void
_remove_metric(struct nhdp_domain *domain) {
  domain->metric->_refcount--;
  if (!domain->metric->_refcount && domain->metric->disable) {
    domain->metric->disable();
  }
  strscpy(domain->metric_name, CFG_DOMAIN_NO_METRIC_MPR, sizeof(domain->metric_name));
  domain->metric = &_no_metric;
  domain->metric->_refcount++;
}

/**
 * Apply a new MPR algorithm to a NHDP domain
 * @param domain pointer to NHDP domain
 * @param mpr_name name of the MPR algorithm to be used,
 *   might be CFG_DOMAIN_NO_MPR (every node is MPR)
 *   or CFG_DOMAIN_ANY_MPR (for a MPR the NHDP core should
 *   choose).
 * @param willingness routing willingness for domain
 */
static void
_apply_mpr(struct nhdp_domain *domain, const char *mpr_name, uint8_t willingness) {
  struct nhdp_domain_mpr *mpr;

  domain->local_willingness = willingness;

  /* check if we have to remove the old mpr first */
  if (strcasecmp(domain->mpr_name, mpr_name) == 0) {
    /* nothing else to do, we already have the right MPR */
    return;
  }
  if (domain->mpr != &_everyone_mprs) {
    /* replace old MPR algorithm with "everyone MPR" */
    _remove_mpr(domain);
  }

  /* Handle wildcard mpr name first */
  if (strcasecmp(mpr_name, CFG_DOMAIN_ANY_METRIC_MPR) == 0
      && !avl_is_empty(&_domain_mprs)) {
    mpr_name = avl_first_element(&_domain_mprs, mpr, _node)->name;
  }

  /* look for mpr implementation */
  mpr = avl_find_element(&_domain_mprs, mpr_name, mpr, _node);
  if (mpr == NULL) {
    mpr = &_everyone_mprs;
  }

  /* copy new metric name */
  strscpy(domain->mpr_name, mpr->name, sizeof(domain->mpr_name));

  /* link domain and mpr */
  domain->mpr->_refcount--;
  domain->mpr = mpr;

  /* activate mpr */
  if (mpr->_refcount == 0 && mpr->enable) {
    mpr->enable();
  }
  mpr->_refcount++;
}

/**
 * Reset the MPR of a NHDP domain to 'everyone is MPR'
 * @param domain pointer to NHDP domain
 */
static void
_remove_mpr(struct nhdp_domain *domain) {
  domain->mpr->_refcount--;
  if (!domain->mpr->_refcount && domain->mpr->disable) {
    domain->mpr->disable();
  }
  strscpy(domain->mpr_name, CFG_DOMAIN_NO_METRIC_MPR, sizeof(domain->mpr_name));
  domain->mpr = &_everyone_mprs;
  domain->mpr->_refcount++;
}

static void
_cb_update_everyone_mpr(void) {
  struct nhdp_neighbor *neigh;
  struct nhdp_domain *domain;
  struct nhdp_neighbor_domaindata *domaindata;

  list_for_each_element(nhdp_db_get_neigh_list(), neigh, _global_node) {
    if (_flooding_domain.mpr == &_everyone_mprs) {
      neigh->neigh_is_flooding_mpr =
          neigh->flooding_willingness > RFC7181_WILLINGNESS_NEVER;
    }

    list_for_each_element(nhdp_domain_get_list(), domain, _node) {
      if (domain->mpr == &_everyone_mprs) {
        domaindata = nhdp_domain_get_neighbordata(domain, neigh);
        domaindata->neigh_is_mpr =
            domaindata->willingness > RFC7181_WILLINGNESS_NEVER;
      }
    }
  }
}

/**
 * Default implementation to convert a link metric value into text
 * @param buf pointer to metric output buffer
 * @param metric link metric value
 * @return pointer to string representation of linkmetric value
 */
static const char *
_link_to_string(struct nhdp_metric_str *buf, uint32_t metric) {
  snprintf(buf->buf, sizeof(*buf), "0x%x", metric);

  return buf->buf;
}

/**
 * Default implementation to convert a path metric value into text
 * @param buf pointer to metric output buffer
 * @param metric path metric value
 * @param hopcount hopcount of path
 * @return pointer to string representation of path metric value
 */
static const char *
_path_to_string(struct nhdp_metric_str *buf, uint32_t metric,
    uint8_t hopcount __attribute((unused))) {
  snprintf(buf->buf, sizeof(*buf), "0x%x", metric);

  return buf->buf;
}

static const char *
_int_to_string(struct nhdp_metric_str *buf,
    struct nhdp_link *lnk __attribute__((unused))) {
  strscpy(buf->buf, "-", sizeof(*buf));
  return buf->buf;
}
