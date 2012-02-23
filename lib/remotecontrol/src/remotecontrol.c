
/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004-2009, the olsr.org team - see HISTORY file
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

#include <stdlib.h>

#include "common/common_types.h"
#include "common/autobuf.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "common/list.h"
#include "common/netaddr.h"
#include "common/string.h"

#include "config/cfg_cmd.h"
#include "config/cfg_db.h"
#include "config/cfg_schema.h"

#include "olsr_cfg.h"
#include "olsr_logging.h"
#include "olsr_memcookie.h"
#include "olsr_plugins.h"
#include "olsr_telnet.h"
#include "olsr_timer.h"
#include "olsr.h"
#include "os_routing.h"

/* variable definitions */
struct _remotecontrol_cfg {
  struct olsr_netaddr_acl acl;
};

struct _remotecontrol_session {
  struct list_entity node;
  struct olsr_telnet_cleanup cleanup;

  struct log_handler_mask_entry *mask;
};

/* prototypes */
static int _cb_plugin_load(void);
static int _cb_plugin_unload(void);
static int _cb_plugin_enable(void);
static int _cb_plugin_disable(void);

static enum olsr_telnet_result _cb_handle_resource(struct olsr_telnet_data *data);
static enum olsr_telnet_result _cb_handle_route(struct olsr_telnet_data *data);
static enum olsr_telnet_result _cb_handle_log(struct olsr_telnet_data *data);
static enum olsr_telnet_result _cb_handle_config(struct olsr_telnet_data *data);
static enum olsr_telnet_result _update_logfilter(struct olsr_telnet_data *data,
    struct log_handler_mask_entry *mask, const char *current, bool value);

static int _print_memory(struct autobuf *buf);
static int _print_timer(struct autobuf *buf);

static enum olsr_telnet_result _start_logging(struct olsr_telnet_data *data,
    struct _remotecontrol_session *rc_session);
static void _stop_logging(struct olsr_telnet_data *data);

static void _cb_print_log(struct log_handler_entry *,
    struct log_parameters *);


static void _cb_config_changed(void);
static struct _remotecontrol_session *
    _get_remotecontrol_session(struct olsr_telnet_data *data);
static void _cb_handle_session_cleanup(struct olsr_telnet_cleanup *cleanup);


/* plugin declaration */
OLSR_PLUGIN7 {
  .descr = "OLSRD remote control and debug plugin",
  .author = "Henning Rogge",

  .load = _cb_plugin_load,
  .unload = _cb_plugin_unload,
  .enable = _cb_plugin_enable,
  .disable = _cb_plugin_disable,

  .deactivate = true,
};

/* configuration */
static struct cfg_schema_section _remotecontrol_section = {
  .type = "remotecontrol",
  .cb_delta_handler = _cb_config_changed,
};

static struct cfg_schema_entry _remotecontrol_entries[] = {
  CFG_MAP_ACL(_remotecontrol_cfg, acl, "acl", "+127.0.0.1\0+::1\0default_reject", "acl for remote control commands"),
};

static struct _remotecontrol_cfg _remotecontrol_config;

/* command callbacks and names */
static struct olsr_telnet_command _telnet_cmds[] = {
  TELNET_CMD("resources", _cb_handle_resource,
      "\"resources memory\": display information about memory usage\n"
      "\"resources timer\": display information about active timers\n",
      .acl = &_remotecontrol_config.acl),
  TELNET_CMD("log", _cb_handle_log,
      "\"log\":      continuous output of logging to this console\n"
      "\"log show\": show configured logging option for debuginfo output\n"
      "\"log add <severity> <source1> <source2> ...\": Add one or more sources of a defined severity for logging\n"
      "\"log remove <severity> <source1> <source2> ...\": Remove one or more sources of a defined severity for logging\n",
      .acl = &_remotecontrol_config.acl),
  TELNET_CMD("config", _cb_handle_config,
      "\"config commit\":                                   Commit changed configuration\n"
      "\"config revert\":                                   Revert to active configuration\n"
      "\"config schema\":                                   Display all allowed section types of configuration\n"
      "\"config schema <section_type>\":                    Display all allowed entries of one configuration section\n"
      "\"config schema <section_type.key>\":                Display help text for configuration entry\n"
      "\"config load <SOURCE>\":                            Load configuration from a SOURCE\n"
      "\"config save <TARGET>\":                            Save configuration to a TARGET\n"
      "\"config set <section_type>.\":                      Add an unnamed section to the configuration\n"
      "\"config set <section_type>.<key>=<value>\":         Add a key/value pair to an unnamed section\n"
      "\"config set <section_type>[<name>].\":              Add a named section to the configuration\n"
      "\"config set <section_type>[<name>].<key>=<value>\": Add a key/value pair to a named section\n"
      "\"config remove <section_type>.\":                   Remove all sections of a certain type\n"
      "\"config remove <section_type>.<key>\":              Remove a key in an unnamed section\n"
      "\"config remove <section_type>[<name>].\":           Remove a named section\n"
      "\"config remove <section_type>[<name>].<key>\":      Remove a key in a named section\n"
      "\"config get\":                                      Show all section types in database\n"
      "\"config get <section_type>.\":                      Show all named sections of a certain type\n"
      "\"config get <section_type>.<key>\":                 Show the value(s) of a key in an unnamed section\n"
      "\"config get <section_type>[<name>].<key>\":         Show the value(s) of a key in a named section\n"
      "\"config format <FORMAT>\":                          Set the format for loading/saving data\n"
      "\"config format AUTO\":                              Set the format to automatic detection\n",
      .acl = &_remotecontrol_config.acl),
  TELNET_CMD("route", _cb_handle_route,
      "\"route set [src <src-ip>] [gw <gateway ip>] [dst <destination prefix>] [table <table-id>]\n"
      "            [proto <protocol-id>] [metric <metric>] interface <if-name>\n"
      "                                                     Set a route in the kernel routing table\n"
      "\"route remove [src <src-ip>] [gw <gateway ip>] [dst <destination prefix>] [table <table-id>]\n"
      "               [proto <protocol-id>] [metric <metric>] interface <if-name>\n"
      "                                                     Remove a route in the kernel routing table\n",
      .acl = &_remotecontrol_config.acl),
};

/* variables for log access */
static int _log_source_maxlen, _log_severity_maxlen;

/* list of telnet sessions with logging mask data */
static struct list_entity _remote_sessions;

/**
 * Initialize remotecontrol plugin
 * @return always returns 0 (cannot fail)
 */
static int
_cb_plugin_load(void)
{
  cfg_schema_add_section(olsr_cfg_get_schema(), &_remotecontrol_section,
      _remotecontrol_entries, ARRAYSIZE(_remotecontrol_entries));
  olsr_acl_add(&_remotecontrol_config.acl);

  return 0;
}

/**
 * Free all resources of remotecontrol plugin
 * @return always returns 0 (cannot fail)
 */
static int
_cb_plugin_unload(void)
{
  olsr_acl_remove(&_remotecontrol_config.acl);
  cfg_schema_remove_section(olsr_cfg_get_schema(), &_remotecontrol_section);
  return 0;
}

/**
 * Enable remotecontrol plugin
 * @return always returns 0 (cannot fail)
 */
static int
_cb_plugin_enable(void)
{
  size_t i;
  enum log_source src;
  enum log_severity sev;

  list_init_head(&_remote_sessions);

  /* calculate maximum length of log source names */
  _log_source_maxlen = 0;
  for (src=1; src<olsr_log_get_sourcecount(); src++) {
    int len = strlen(LOG_SOURCE_NAMES[src]);

    if (len > _log_source_maxlen) {
      _log_source_maxlen = len;
    }
  }

  /* calculate maximum length of log severity names */
  _log_severity_maxlen = 0;
  for (sev=1; sev<LOG_SEVERITY_COUNT; sev++) {
    int len = strlen(LOG_SEVERITY_NAMES[sev]);

    if (len > _log_severity_maxlen) {
      _log_severity_maxlen = len;
    }
  }

  for (i=0; i<ARRAYSIZE(_telnet_cmds); i++) {
    olsr_telnet_add(&_telnet_cmds[i]);
  }

  return 0;
}

/**
 * Deactivate remotecontrol plugin
 * @return always returns 0 (cannot fail)
 */
static int
_cb_plugin_disable(void)
{
  struct _remotecontrol_session *session, *it;
  size_t i;

  for (i=0; i<ARRAYSIZE(_telnet_cmds); i++) {
    olsr_telnet_remove(&_telnet_cmds[i]);
  }

  /* shutdown all running logging streams */
  list_for_each_element_safe(&_remote_sessions, session, node, it) {
    olsr_telnet_stop(session->cleanup.data);
  }

  return 0;
}

/**
 * Print current resources known to memory manager
 * @param buf output buffer
 * @return -1 if an error happened, 0 otherwise
 */
static int
_print_memory(struct autobuf *buf) {
  struct olsr_memcookie_info *c, *iterator;

  OLSR_FOR_ALL_COOKIES(c, iterator) {
    if (abuf_appendf(buf, "%-25s (MEMORY) size: %lu usage: %u freelist: %u\n",
        c->ci_name, (unsigned long)c->ci_size, c->ci_usage, c->ci_free_list_usage) < 0) {
      return -1;
    }
  }
  return 0;
}

/**
 * Print current resources known to timer scheduler
 * @param buf output buffer
 * @return -1 if an error happened, 0 otherwise
 */
static int
_print_timer(struct autobuf *buf) {
  struct olsr_timer_info *t, *iterator;

  OLSR_FOR_ALL_TIMERS(t, iterator) {
    if (abuf_appendf(buf, "%-25s (TIMER) usage: %u changes: %u\n",
        t->name, t->usage, t->changes) < 0) {
      return -1;
    }
  }
  return 0;
}

/**
 * Handle resource command
 * @param data pointer to telnet data
 * @return telnet result constant
 */
static enum olsr_telnet_result
_cb_handle_resource(struct olsr_telnet_data *data) {
  if (data->parameter == NULL || strcasecmp(data->parameter, "memory") == 0) {
    if (abuf_puts(data->out, "Memory cookies:\n") < 0) {
      return TELNET_RESULT_INTERNAL_ERROR;
    }

    if (_print_memory(data->out)) {
      return TELNET_RESULT_INTERNAL_ERROR;
    }
  }

  if (data->parameter == NULL || strcasecmp(data->parameter, "timer") == 0) {
    if (abuf_puts(data->out, "\nTimer cookies:\n") < 0) {
      return TELNET_RESULT_INTERNAL_ERROR;
    }

    if (_print_timer(data->out)) {
      return TELNET_RESULT_INTERNAL_ERROR;
    }
  }
  return TELNET_RESULT_ACTIVE;
}

/**
 * Update the remotecontrol logging filter
 * @param data pointer to telnet data
 * @param mask pointer to logging mask to manipulate
 * @param param parameters of log add/log remove command
 * @param value true if new source should be added, false
 *    if it should be removed
 * @return telnet result constant
 */
static enum olsr_telnet_result
_update_logfilter(struct olsr_telnet_data *data,
    struct log_handler_mask_entry *mask, const char *param, bool value) {
  const char *next;
  enum log_source src;
  enum log_severity sev;

  for (sev = 0; sev < LOG_SEVERITY_COUNT; sev++) {
    if ((next = str_hasnextword(param, LOG_SEVERITY_NAMES[sev])) != NULL) {
      break;
    }
  }
  if (sev == LOG_SEVERITY_COUNT) {
    abuf_appendf(data->out, "Error, unknown severity level: %s\n", param);
    return TELNET_RESULT_ACTIVE;
  }

  param = next;
  while (param && *param) {
    for (src = 0; src < olsr_log_get_sourcecount(); src++) {
      if ((next = str_hasnextword(param, LOG_SOURCE_NAMES[src])) != NULL) {
        mask[src].log_for_severity[sev] = value;
        value = false;
        break;
      }
    }
    if (src == olsr_log_get_sourcecount()) {
      abuf_appendf(data->out, "Error, unknown logging source: %s\n", param);
      return TELNET_RESULT_ACTIVE;
    }
    param = next;
  }

  olsr_log_updatemask();
  return TELNET_RESULT_ACTIVE;
}

/**
 * Log handler for telnet output
 * @param entry logging handler
 * @param param logging parameter set
 */
static void
_cb_print_log(struct log_handler_entry *h __attribute__((unused)),
    struct log_parameters *param) {
  struct olsr_telnet_session *telnet = h->custom;

  abuf_puts(&telnet->session.out, param->buffer);
  abuf_puts(&telnet->session.out, "\n");

  /* This might trigger logging output in olsr_socket_stream ! */
  olsr_stream_flush(&telnet->session);
}

/**
 * Stop handler for continous logging output
 * @param telnet pointer ot telnet telnet
 */
static void
_stop_logging(struct olsr_telnet_data *session) {
  struct log_handler_entry *log_handler;

  log_handler = session->stop_data[0];

  olsr_log_removehandler(log_handler);
  free (log_handler);

  session->stop_handler = NULL;
}

/**
 * Activate logging handler for telnet output
 * @param data pointer to telnet data
 * @param rc_session pointer to remotecontrol session
 * @return telnet result code
 */
static enum olsr_telnet_result
_start_logging(struct olsr_telnet_data *data,
    struct _remotecontrol_session *rc_session) {
  struct log_handler_entry *log_handler;

  log_handler = calloc(1, sizeof(*log_handler));
  if (log_handler == NULL) {
    return TELNET_RESULT_INTERNAL_ERROR;
  }

  log_handler->bitmask = rc_session->mask;
  log_handler->custom = data;
  log_handler->handler = _cb_print_log;

  data->stop_handler = _stop_logging;
  data->stop_data[0] = log_handler;

  return TELNET_RESULT_CONTINOUS;
}

/**
 * Handle resource command
 * @param data pointer to telnet data
 * @return telnet result constant
 */
static enum olsr_telnet_result
_cb_handle_log(struct olsr_telnet_data *data) {
  struct _remotecontrol_session *rc_session;
  const char *next;
  enum log_source src;

  rc_session = _get_remotecontrol_session(data);
  if (rc_session == NULL) {
    return TELNET_RESULT_INTERNAL_ERROR;
  }

  if (data->parameter == NULL) {
    if (data->stop_handler) {
      abuf_puts(data->out, "Error, you cannot stack continuous output commands\n");
      return TELNET_RESULT_ACTIVE;
    }

    return _start_logging(data, rc_session);
  }

  if (strcasecmp(data->parameter, "show") == 0) {
    abuf_appendf(data->out, "%*s %6s %6s %6s\n",
        _log_source_maxlen, "",
        LOG_SEVERITY_NAMES[SEVERITY_DEBUG],
        LOG_SEVERITY_NAMES[SEVERITY_INFO],
        LOG_SEVERITY_NAMES[SEVERITY_WARN]);

    for (src=0; src<olsr_log_get_sourcecount(); src++) {
      abuf_appendf(data->out, "%*s %*s %*s %*s\n",
        _log_source_maxlen, LOG_SOURCE_NAMES[src],
        (int)sizeof(LOG_SEVERITY_NAMES[SEVERITY_DEBUG]),
        rc_session->mask[src].log_for_severity[SEVERITY_DEBUG] ? "*" : "",
        (int)sizeof(LOG_SEVERITY_NAMES[SEVERITY_INFO]),
        rc_session->mask[src].log_for_severity[SEVERITY_INFO] ? "*" : "",
        (int)sizeof(LOG_SEVERITY_NAMES[SEVERITY_WARN]),
        rc_session->mask[src].log_for_severity[SEVERITY_WARN] ? "*" : "");
    }
    return TELNET_RESULT_ACTIVE;
  }

  if ((next = str_hasnextword(data->parameter, "add")) != NULL) {
    return _update_logfilter(data, rc_session->mask, next, true);
  }
  if ((next = str_hasnextword(data->parameter, "remove")) != NULL) {
    return _update_logfilter(data, rc_session->mask, next, false);
  }

  return TELNET_RESULT_UNKNOWN_COMMAND;
}

/**
 * Handle config command
 * @param data pointer to telnet data
 * @return telnet result constant
 */
static enum olsr_telnet_result
_cb_handle_config(struct olsr_telnet_data *data) {
  const char *next = NULL;

  if (data->parameter == NULL || *data->parameter == 0) {
    abuf_puts(data->out, "Error, 'config' needs a parameter\n");
    return TELNET_RESULT_ACTIVE;
  }

  if ((next = str_hasnextword(data->parameter, "commit"))) {
    if (!cfg_schema_validate(olsr_cfg_get_rawdb(),
        false, true, data->out)) {
      olsr_cfg_trigger_commit();
    }
  }
  else if ((next = str_hasnextword(data->parameter, "rollback"))) {
    olsr_cfg_rollback();
  }
  else if ((next = str_hasnextword(data->parameter, "format"))) {
    cfg_cmd_handle_format(olsr_cfg_get_instance(), next);
  }
  else if ((next = str_hasnextword(data->parameter, "get"))) {
    cfg_cmd_handle_get(olsr_cfg_get_instance(),
        olsr_cfg_get_rawdb(), next, data->out);
  }
  else if ((next = str_hasnextword(data->parameter, "load"))) {
    cfg_cmd_handle_load(olsr_cfg_get_instance(),
        olsr_cfg_get_rawdb(), next, data->out);
  }
  else if ((next = str_hasnextword(data->parameter, "remove"))) {
    cfg_cmd_handle_remove(olsr_cfg_get_instance(),
        olsr_cfg_get_rawdb(), next, data->out);
  }
  else if ((next = str_hasnextword(data->parameter, "save"))) {
    cfg_cmd_handle_save(olsr_cfg_get_instance(),
        olsr_cfg_get_rawdb(), next, data->out);
  }
  else if ((next = str_hasnextword(data->parameter, "schema"))) {
    cfg_cmd_handle_schema(
        olsr_cfg_get_rawdb(), next, data->out);
  }
  else if ((next = str_hasnextword(data->parameter, "set"))) {
    cfg_cmd_handle_set(olsr_cfg_get_instance(),
        olsr_cfg_get_rawdb(), next, data->out);
  }
  else {
    return TELNET_RESULT_UNKNOWN_COMMAND;
  }

  return TELNET_RESULT_ACTIVE;
}

/**
 * Handle the route command
 * @param data pointer to telnet data
 * @return telnet result constant
 */
static enum olsr_telnet_result
_cb_handle_route(struct olsr_telnet_data *data) {
  struct netaddr_str buf;
  const char *ptr = NULL, *next = NULL;
  struct netaddr src, gw, dst;
  int table = 0, protocol = 4, metric = -1, if_index = 0;
  bool set;

  memset (&src, 0, sizeof(src));
  memset (&gw, 0, sizeof(gw));
  memset (&dst, 0, sizeof(dst));

  if ((next = str_hasnextword(data->parameter, "set")) != NULL
      || (next = str_hasnextword(data->parameter, "remove")) != NULL) {
    set = strncasecmp(data->parameter, "set", 3) == 0;

    ptr = next;
    while (ptr) {
      if ((next = str_hasnextword(ptr, "src"))) {
        ptr = str_cpynextword(buf.buf, next, sizeof(buf));
        if (netaddr_from_string(&src, buf.buf)) {
          abuf_appendf(data->out, "Error, illegal source: %s", buf.buf);
          return TELNET_RESULT_ACTIVE;
        }
      }
      else if ((next = str_hasnextword(ptr, "gw"))) {
        ptr = str_cpynextword(buf.buf, next, sizeof(buf));
        if (netaddr_from_string(&gw, buf.buf)) {
          abuf_appendf(data->out, "Error, illegal gateway: %s", buf.buf);
          return TELNET_RESULT_ACTIVE;
        }
      }
      else if ((next = str_hasnextword(ptr, "dst"))) {
        ptr = str_cpynextword(buf.buf, next, sizeof(buf));
        if (netaddr_from_string(&dst, buf.buf)) {
          abuf_appendf(data->out, "Error, illegal destination: %s", buf.buf);
          return TELNET_RESULT_ACTIVE;
        }
      }
      else if ((next = str_hasnextword(ptr, "table"))) {
        ptr = str_cpynextword(buf.buf, next, sizeof(buf));
        table = atoi(buf.buf);
      }
      else if ((next = str_hasnextword(ptr, "proto"))) {
        ptr = str_cpynextword(buf.buf, next, sizeof(buf));
        protocol = atoi(buf.buf);
      }
      else if ((next = str_hasnextword(ptr, "metric"))) {
        ptr = str_cpynextword(buf.buf, next, sizeof(buf));
        table = atoi(buf.buf);
      }
      else if ((next = str_hasnextword(ptr, "interface"))) {
        ptr = str_cpynextword(buf.buf, next, sizeof(buf));
        if_index = if_nametoindex(buf.buf);
      }
      else {
        abuf_appendf(data->out, "Cannot parse remainder of parameter string: %s", ptr);
        return TELNET_RESULT_ACTIVE;
      }
    }
    if (if_index == 0) {
      abuf_appendf(data->out, "Missing or unknown interface");
      return TELNET_RESULT_ACTIVE;
    }
    if (dst.type != AF_INET && dst.type != AF_INET6) {
      abuf_appendf(data->out, "Error, IPv4 or IPv6 destination mandatory");
      return TELNET_RESULT_ACTIVE;
    }
    if (src.type != 0 && src.type != dst.type) {
      abuf_appendf(data->out, "Error, illegal address type of source ip");
      return TELNET_RESULT_ACTIVE;
    }
    if (gw.type == 0 || gw.type != dst.type) {
      abuf_appendf(data->out, "Error, illegal or missing gateway ip");
      return TELNET_RESULT_ACTIVE;
    }

    abuf_appendf(data->out, "set route: %d",
        os_routing_set(src.type == 0 ? NULL: &src, &gw, &dst,
            table, if_index, metric, protocol, set, true));
    return TELNET_RESULT_ACTIVE;
  }

  return TELNET_RESULT_UNKNOWN_COMMAND;
}

/**
 * Update configuration of remotecontrol plugin
 */
static void
_cb_config_changed(void) {
  if (cfg_schema_tobin(&_remotecontrol_config, _remotecontrol_section.post,
      _remotecontrol_entries, ARRAYSIZE(_remotecontrol_entries))) {
    OLSR_WARN(LOG_CONFIG, "Could not convert remotecontrol config to bin");
    return;
  }
}

/**
 * Look for remotecontrol session of telnet data. Create one if
 * necessary
 * @param data pointer to telnet data
 * @return remotecontrol session, NULL if an error happened
 */
static struct _remotecontrol_session *
_get_remotecontrol_session(struct olsr_telnet_data *data) {
  struct _remotecontrol_session *cl;

  list_for_each_element(&_remote_sessions, cl, node) {
    if (cl->cleanup.data == data) {
      return cl;
    }
  }

  /* create new telnet */
  cl = calloc(1, sizeof(*cl));
  if (cl == NULL) {
    OLSR_WARN_OOM(LOG_PLUGINS);
    return NULL;
  }

  cl->cleanup.cleanup_handler = _cb_handle_session_cleanup;
  cl->cleanup.custom = cl;
  olsr_telnet_add_cleanup(data, &cl->cleanup);

  /* copy global mask */
  cl->mask = olsr_log_allocate_mask();
  olsr_log_copy_mask(cl->mask, log_global_mask);

  /* add to remote telnet list */
  list_add_tail(&_remote_sessions, &cl->node);

  return cl;
}

/**
 * Cleanup remotecontrol session if telnet session is over
 * @param cleanup pointer to telnet cleanup handler
 */
static void
_cb_handle_session_cleanup(struct olsr_telnet_cleanup *cleanup) {
  struct _remotecontrol_session *session;

  session = cleanup->custom;
  list_remove(&session->node);
  olsr_log_free_mask(session->mask);
  free(session);
}
