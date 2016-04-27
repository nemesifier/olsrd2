
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
#include "common/autobuf.h"
#include "common/json.h"

#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_clock.h"
#include "subsystems/oonf_telnet.h"

#include "nhdp/nhdp.h"
#include "nhdp/nhdp_db.h"
#include "nhdp/nhdp_domain.h"
#include "nhdp/nhdp_interfaces.h"
#include "olsrv2/olsrv2.h"
#include "olsrv2/olsrv2_lan.h"
#include "olsrv2/olsrv2_originator.h"
#include "olsrv2/olsrv2_routing.h"
#include "olsrv2/olsrv2_tc.h"

#include "netjsoninfo/netjsoninfo.h"

/* definitions */
#define LOG_NETJSONINFO olsrv2_netjsoninfo.logging

/*! name of filter command */
#define JSON_NAME_FILTER "filter"

/*! name of graph command/json-object */
#define JSON_NAME_GRAPH  "graph"

/*! name of route command/json-object */
#define JSON_NAME_ROUTE  "route"

/*! name of domain command/json-object */
#define JSON_NAME_DOMAIN "domain"

struct domain_id_str {
  char buf[16];
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static void _print_graph_node(
    struct json_session *session, const struct netaddr *id);
static void _print_graph_edge(struct json_session *session,
    struct nhdp_domain *domain,
    const struct netaddr *src, const struct netaddr *dst,
    uint32_t out, uint32_t in, bool outgoing_tree);
static void _print_graph_end(struct json_session *session,
    struct nhdp_domain *domain,
    const struct netaddr *src, const struct os_route_key *prefix,
    uint32_t out, uint8_t hopcount);
static void _print_graph(struct json_session *session,
    struct nhdp_domain *domain, int af_type);
static void _create_graph_json(
    struct json_session *session, const char *filter);
static void _print_routing_tree(struct json_session *session,
    struct nhdp_domain *domain, int af_type);
static void _create_route_json(
    struct json_session *session, const char *filter);
static void _create_domain_json(
    struct json_session *session);
static void _create_error_json(struct json_session *session,
    const char *message, const char *parameter);
static enum oonf_telnet_result _cb_netjsoninfo(
    struct oonf_telnet_data *con);
static void _print_json_string(
    struct json_session *session, const char *key, const char *value);
static void _print_json_number(
    struct json_session *session, const char *key, uint64_t value);
static void _print_json_netaddr(struct json_session *session,
    const char *key, const struct netaddr *addr);

/* telnet command of this plugin */
static struct oonf_telnet_command _telnet_commands[] = {
    TELNET_CMD(OONF_NETJSONINFO_SUBSYSTEM, _cb_netjsoninfo,
        "The command has three main commands (route, graph, domain) and a"
        " 'filter' prefix for route/graph. You can use any combination of the"
        " three main commands (space separated) to generate a NetworkCollection"
        " with the information of the main commands for all known domains.\n"
        "> route graph\n"
        "The filter prefix use an id (which can be queried by 'domain') to output"
        " a single domain of route/graph without the NetworkCollection object"
        " around it. The domain_id's are ipv4_<domain_number> and ipv6_<domain_number>.\n"
        "> filter route ipv4_0\n"),
};

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_NHDP_SUBSYSTEM,
  OONF_OLSRV2_SUBSYSTEM,
  OONF_TELNET_SUBSYSTEM,
};
static struct oonf_subsystem olsrv2_netjsoninfo = {
  .name = OONF_NETJSONINFO_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OLSRv2 JSON for networks generator plugin",
  .author = "Henning Rogge",
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(olsrv2_netjsoninfo);

/**
 * Initialize plugin
 * @return always returns 0
 */
static int
_init(void) {
  oonf_telnet_add(&_telnet_commands[0]);
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  oonf_telnet_remove(&_telnet_commands[0]);
}

static const char *
_create_domain_id(struct domain_id_str *buf,
    struct nhdp_domain *domain, int af_type) {
  snprintf(buf->buf, sizeof(*buf), "%s_%u",
      af_type == AF_INET ? "ipv4" : "ipv6", domain->ext);
  return buf->buf;
}

/**
 * Print the JSON output for a graph node
 * @param session json session
 * @param id node address
 */
static void
_print_graph_node(struct json_session *session, const struct netaddr *id) {
  json_start_object(session, NULL);
  _print_json_netaddr(session, "id", id);
  json_end_object(session);
}

/**
 * Print the JSON output for a graph edge
 * @param session json session
 * @param domain nhdp domain
 * @param src src address
 * @param dst dst address
 * @param out outgoing metric
 * @param in incoming metric
 * @param outgoing_tree true if part of outgoing routing tree,
 *   false otherwise
 */
static void
_print_graph_edge(struct json_session *session,
    struct nhdp_domain *domain,
    const struct netaddr *src, const struct netaddr *dst,
    uint32_t out, uint32_t in, bool outgoing_tree) {
  struct nhdp_metric_str mbuf;

  if (out >= RFC7181_METRIC_INFINITE) {
    return;
  }

  json_start_object(session, NULL);
  _print_json_netaddr(session, "source", src);
  _print_json_netaddr(session, "target", dst);

  _print_json_number(session, "cost", out);
  _print_json_string(session, "cost_text",
      nhdp_domain_get_link_metric_value(&mbuf, domain, out));
  if (in) {
    json_start_object(session, "properties");
    if (in < RFC7181_METRIC_INFINITE) {
      _print_json_number(session, "in", in);
      _print_json_string(session, "in_text",
          nhdp_domain_get_link_metric_value(&mbuf, domain, in));
    }
    _print_json_string(session, "outgoing_tree",
        json_getbool(outgoing_tree));
    json_end_object(session);
  }
  json_end_object(session);
}

/**
 * Print the JSON OUTPUT of graph endpoints
 * @param session json session
 * @param domain NHDP domain
 * @param src src address
 * @param prefix attached prefix
 * @param out outgoing metric
 * @param hopcount hopcount cost of prefix
 */
static void
_print_graph_end(struct json_session *session,
    struct nhdp_domain *domain,
    const struct netaddr *src, const struct os_route_key *prefix,
    uint32_t out, uint8_t hopcount) {
  struct nhdp_metric_str mbuf;

  if (out >= RFC7181_METRIC_INFINITE) {
    return;
  }

  json_start_object(session, NULL);
  _print_json_netaddr(session, "source", src);
  _print_json_netaddr(session, "target", &prefix->dst);
  _print_json_number(session, "cost", out);
  _print_json_string(session, "cost_text",
      nhdp_domain_get_link_metric_value(&mbuf, domain, out));

  json_start_object(session, "properties");
  if (netaddr_get_prefix_length(&prefix->src)) {
	  _print_json_netaddr(session, "source", &prefix->src);
  }
  if (hopcount) {
    _print_json_number(session, "hopcount", hopcount);
  }
  json_end_object(session);
  json_end_object(session);
}

/**
 * Print the JSON graph object
 * @param session json session
 * @param domain NHDP domain
 * @param af_type address family type
 */
static void
_print_graph(struct json_session *session,
    struct nhdp_domain *domain, int af_type) {
  const struct netaddr *originator;
  struct nhdp_neighbor *neigh;
  struct olsrv2_tc_node *node;
  struct olsrv2_tc_edge *edge;
  struct olsrv2_tc_attachment *attached;
  struct olsrv2_lan_entry *lan;
  struct avl_tree *rt_tree;
  struct olsrv2_routing_entry *rt_entry;
  struct domain_id_str dbuf;

  bool outgoing;

  originator = olsrv2_originator_get(af_type);
  if (netaddr_get_address_family(originator) != af_type) {
    return;
  }
  json_start_object(session, NULL);

  _print_json_string(session, "type", "NetworkGraph");
  _print_json_string(session, "protocol", "olsrv2");
  _print_json_string(session, "version", oonf_log_get_libdata()->version);
  _print_json_string(session, "revision", oonf_log_get_libdata()->git_commit);
  _print_json_netaddr(session, "router_id", originator);
  _print_json_string(session, "metric", domain->metric->name);
  _print_json_string(session, "topology_id",
      _create_domain_id(&dbuf, domain, af_type));

  json_start_array(session, "nodes");
  avl_for_each_element(olsrv2_tc_get_tree(), node, _originator_node) {
    if (netaddr_get_address_family(&node->target.prefix.dst) == af_type) {
      _print_graph_node(session, &node->target.prefix.dst);
    }
  }
  json_end_array(session);

  json_start_array(session, "links");

  rt_tree = olsrv2_routing_get_tree(domain);

  /* print local links to neighbors */
  avl_for_each_element(nhdp_db_get_neigh_originator_tree(), neigh, _originator_node) {
    if (netaddr_get_address_family(&neigh->originator) == af_type
        && neigh->symmetric > 0) {
      rt_entry = avl_find_element(rt_tree, &neigh->originator, rt_entry, _node);
      outgoing = rt_entry != NULL
          && netaddr_cmp(&rt_entry->last_originator, originator) == 0;

      _print_graph_edge(session, domain,
          originator, &neigh->originator,
          nhdp_domain_get_neighbordata(domain, neigh)->metric.out,
          nhdp_domain_get_neighbordata(domain, neigh)->metric.in,
          outgoing);

      _print_graph_edge(session, domain,
          &neigh->originator, originator,
          nhdp_domain_get_neighbordata(domain, neigh)->metric.in,
          nhdp_domain_get_neighbordata(domain, neigh)->metric.out,
          false);
    }
  }

  /* print remote node links to neighbors and prefixes */
  avl_for_each_element(olsrv2_tc_get_tree(), node, _originator_node) {
    if (netaddr_get_address_family(&node->target.prefix.dst) == af_type) {
      avl_for_each_element(&node->_edges, edge, _node) {
        if (!edge->virtual) {
          if (netaddr_cmp(&edge->dst->target.prefix.dst, originator) == 0) {
            /* we already have this information from NHDP */
            continue;
          }

          rt_entry = avl_find_element(rt_tree, &edge->dst->target.prefix.dst, rt_entry, _node);
          outgoing = rt_entry != NULL
              && netaddr_cmp(&rt_entry->last_originator, &node->target.prefix.dst) == 0;

          _print_graph_edge(session, domain,
              &node->target.prefix.dst, &edge->dst->target.prefix.dst,
              edge->cost[domain->index],
              edge->inverse->cost[domain->index],
              outgoing);
        }
      }
    }
  }
  json_end_array(session);

  json_start_array(session, "endpoints");

  /* print local endpoints */
  avl_for_each_element(olsrv2_lan_get_tree(), lan, _node) {
    if (netaddr_get_address_family(&lan->prefix.dst) == af_type
        && olsrv2_lan_get_domaindata(domain, lan)->active) {
      _print_graph_end(session, domain,
          originator, &lan->prefix,
          olsrv2_lan_get_domaindata(domain, lan)->outgoing_metric,
          olsrv2_lan_get_domaindata(domain, lan)->distance);
    }
  }

  /* print remote nodes neighbors */
  avl_for_each_element(olsrv2_tc_get_tree(), node, _originator_node) {
    if (netaddr_get_address_family(&node->target.prefix.dst) == af_type) {
      avl_for_each_element(&node->_attached_networks, attached, _src_node) {
        _print_graph_end(session, domain,
            &node->target.prefix.dst, &attached->dst->target.prefix,
            attached->cost[domain->index],
            attached->distance[domain->index]);
      }
    }
  }
  json_end_array(session);

  json_end_object(session);
}

/**
 * Print all JSON graph objects
 * @param session json session
 */
static void
_create_graph_json(struct json_session *session,
    const char *filter __attribute__((unused))) {
  struct nhdp_domain *domain;
  struct domain_id_str dbuf;

  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    if (filter == NULL
        || strcmp(_create_domain_id(&dbuf, domain, AF_INET), filter) == 0) {
      _print_graph(session, domain, AF_INET);
    }
    if (filter == NULL
        || strcmp(_create_domain_id(&dbuf, domain, AF_INET6), filter) == 0) {
      _print_graph(session, domain, AF_INET6);
    }
  }
}

/**
 * Print the JSON routing tree
 * @param session json session
 * @param domain NHDP domain
 * @param af_type address family
 */
static void
_print_routing_tree(struct json_session *session,
    struct nhdp_domain *domain, int af_type) {
  struct olsrv2_routing_entry *rtentry;
  const struct netaddr *originator;
  char ibuf[IF_NAMESIZE];
  struct nhdp_metric_str mbuf;
  struct domain_id_str dbuf;

  originator = olsrv2_originator_get(af_type);
  if (netaddr_get_address_family(originator) != af_type) {
    return;
  }

  json_start_object(session, NULL);

  _print_json_string(session, "type", "NetworkRoutes");
  _print_json_string(session, "protocol", "olsrv2");
  _print_json_string(session, "version", oonf_log_get_libdata()->version);
  _print_json_string(session, "revision", oonf_log_get_libdata()->git_commit);
  _print_json_netaddr(session, "router_id", originator);
  _print_json_string(session, "metric", domain->metric->name);
  _print_json_string(session, "topology_id",
      _create_domain_id(&dbuf, domain, af_type));

  json_start_array(session, JSON_NAME_ROUTE);

  avl_for_each_element(olsrv2_routing_get_tree(domain), rtentry, _node) {
    if (rtentry->route.p.family == af_type) {
      json_start_object(session, NULL);
      _print_json_netaddr(session, "destination", &rtentry->route.p.key.dst);
      if (netaddr_get_prefix_length(&rtentry->route.p.key.src) > 0) {
        _print_json_netaddr(session, "source", &rtentry->route.p.key.src);
      }
      _print_json_netaddr(session, "next", &rtentry->route.p.gw);
      _print_json_netaddr(session, "next_id", &rtentry->next_originator);

      _print_json_string(session, "device", if_indextoname(rtentry->route.p.if_index, ibuf));
      _print_json_number(session, "cost", rtentry->path_cost);
      _print_json_string(session, "cost_text",
          nhdp_domain_get_path_metric_value(
              &mbuf, domain, rtentry->path_cost, rtentry->path_hops));

      json_start_object(session, "properties");
      _print_json_number(session, "hops", rtentry->path_hops);
      _print_json_netaddr(session, "last_id", &rtentry->last_originator);
      json_end_object(session);

      json_end_object(session);
    }
  }

  json_end_array(session);
  json_end_object(session);
}

/**
 * Print all JSON routes
 * @param session
 */
static void
_create_route_json(struct json_session *session, const char *filter) {
  struct nhdp_domain *domain;
  struct domain_id_str dbuf;

  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    if (filter == NULL
        || strcmp(_create_domain_id(&dbuf, domain, AF_INET), filter) == 0) {
      _print_routing_tree(session, domain, AF_INET);
    }
    if (filter == NULL
        || strcmp(_create_domain_id(&dbuf, domain, AF_INET6), filter) == 0) {
      _print_routing_tree(session, domain, AF_INET6);
    }
  }
}

static void
_create_domain_json(struct json_session *session) {
  const struct netaddr *originator_v4, *originator_v6;
  struct nhdp_domain *domain;
  struct domain_id_str dbuf;

  originator_v4 = olsrv2_originator_get(AF_INET);
  originator_v6 = olsrv2_originator_get(AF_INET6);

  json_start_object(session, NULL);

  _print_json_string(session, "type", "NetworkDomain");
  _print_json_string(session, "protocol", "olsrv2");
  _print_json_string(session, "version", oonf_log_get_libdata()->version);
  _print_json_string(session, "revision", oonf_log_get_libdata()->git_commit);

  json_start_array(session, JSON_NAME_DOMAIN);

  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    if (!netaddr_is_unspec(originator_v4)) {
      json_start_object(session, NULL);

      _print_json_string(session, "id",
          _create_domain_id(&dbuf, domain, AF_INET));
      _print_json_number(session, "number", domain->ext);
      _print_json_netaddr(session, "router_id", originator_v4);
      _print_json_string(session, "metric", domain->metric->name);
      _print_json_string(session, "mpr", domain->mpr->name);

      json_end_object(session);
    }

    if (!netaddr_is_unspec(originator_v6)) {
      json_start_object(session, NULL);

      _print_json_string(session, "id",
          _create_domain_id(&dbuf, domain, AF_INET6));
      _print_json_number(session, "number", domain->ext);
      _print_json_netaddr(session, "router_id", originator_v6);
      _print_json_string(session, "metric", domain->metric->name);
      _print_json_string(session, "mpr", domain->mpr->name);

      json_end_object(session);
    }
  }

  json_end_array(session);
  json_end_object(session);
}

/**
 * Print a JSON error
 * @param session json session
 * @param message error message
 * @param parameter error parameter
 */
static void
_create_error_json(struct json_session *session,
    const char *message, const char *parameter) {
  json_start_object(session, NULL);

  _print_json_string(session, "type", "Error");
  _print_json_string(session, "message", message);
  _print_json_string(session, "parameter", parameter);

  json_end_object(session);
}

static const char *
_handle_netjson_object(struct json_session *session,
    const char *parameter, bool filter, bool *error) {
  const char *ptr;

  if ((ptr = str_hasnextword(parameter, JSON_NAME_GRAPH))) {
    _create_graph_json(session, filter ? ptr : NULL);
  }
  else if ((ptr = str_hasnextword(parameter, JSON_NAME_ROUTE))) {
    _create_route_json(session, filter ? ptr : NULL);
  }
  else if (!filter
      && (ptr = str_hasnextword(parameter, JSON_NAME_DOMAIN))) {
    _create_domain_json(session);
  }
  else {
    ptr = str_skipnextword(parameter);
    *error = true;
  }
  return ptr;
}

static void
_handle_filter(struct json_session *session, const char *parameter) {
  bool error = false;

  _handle_netjson_object(session, parameter, true, &error);
  if (error) {
    _create_error_json(session,
        "Could not parse sub-command for netjsoninfo",
        parameter);
  }
}

static void
_handle_collection(struct json_session *session, const char *parameter) {
  const char *next;
  bool error;

  json_start_object(session, NULL);
  _print_json_string(session, "type", "NetworkCollection");
  json_start_array(session, "collection");

  error = 0;
  next = parameter;
  while (next && *next) {
    next = _handle_netjson_object(session, next, false, &error);
  }

  if (error) {
    _create_error_json(session,
        "Could not parse sub-command for netjsoninfo",
        parameter);
  }

  json_end_array(session);
  json_end_object(session);
}

/**
 * Callback for netjsoninfo telnet command
 * @param con telnet connection
 * @return active or internal_error
 */
static enum oonf_telnet_result
_cb_netjsoninfo(struct oonf_telnet_data *con) {
  struct json_session session;
  struct autobuf out;
  const char *ptr, *next;

  if (abuf_init(&out)) {
    return TELNET_RESULT_INTERNAL_ERROR;
  }

  json_init_session(&session, &out);

  next = con->parameter;
  if (next && *next) {
    if ((ptr = str_hasnextword(next, JSON_NAME_FILTER))) {
      _handle_filter(&session, ptr);
    }
    else {
      _handle_collection(&session, next);
    }
  }

  /* copy output into telnet buffer */
  abuf_memcpy(con->out, abuf_getptr(&out), abuf_getlen(&out));
  abuf_free(&out);
  return TELNET_RESULT_ACTIVE;
}

/**
 * Helper to print a json string
 * @param session json session
 * @param key json key
 * @param value json string value
 */
static void
_print_json_string(struct json_session *session, const char *key, const char *value) {
  json_print(session, key, true, value);
}

/**
 * Helper to print a json number
 * @param session json session
 * @param key json key
 * @param value number
 */
static void
_print_json_number(struct json_session *session, const char *key, uint64_t value) {
  char buffer[21];

  snprintf(buffer, sizeof(buffer), "%" PRIu64, value);
  json_print(session, key, false, buffer);
}

/**
 * Helper function to print a json netaddr object
 * @param session json session
 * @param key json key
 * @param addr address
 */
static void
_print_json_netaddr(struct json_session *session, const char *key, const struct netaddr *addr) {
  struct netaddr_str nbuf;

  json_print(session, key, true, netaddr_to_string(&nbuf, addr));
}
