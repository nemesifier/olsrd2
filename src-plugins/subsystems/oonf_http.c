
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

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

#include "common/avl.h"
#include "common/avl_comp.h"
#include "common/common_types.h"
#include "common/netaddr.h"
#include "common/netaddr_acl.h"

#include "config/cfg_schema.h"

#include "core/oonf_cfg.h"
#include "core/oonf_libdata.h"
#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"
#include "core/os_core.h"
#include "subsystems/oonf_stream_socket.h"
#include "subsystems/oonf_telnet.h"

#include "subsystems/oonf_http.h"

/* Definitions */
#define LOG_HTTP _oonf_http_subsystem.logging

/**
 * configuration of http plugin
 */
struct _http_config {
  /*! http tcp configuration */
  struct oonf_stream_managed_config smc;

  /*! directory for webserver functionality */
  char *www_dir;

  /*! internal variable with file descriptor to webserver directory */
  int www_dir_fd;
};
/* HTTP text constants */
static const char HTTP_VERSION_1_0[] = "HTTP/1.0";
static const char HTTP_VERSION_1_1[] = "HTTP/1.1";

static const char HTTP_GET[] = "GET";
static const char HTTP_POST[] = "POST";

static const char HTTP_CONTENT_LENGTH[] = "Content-Length";
static const char HTTP_CONTENT_TYPE[] = "Content-Type";

static const char HTTP_RESPONSE_200[] = "OK";
static const char HTTP_RESPONSE_400[] = "Bad Request";
static const char HTTP_RESPONSE_401[] = "Unauthorized";
static const char HTTP_RESPONSE_403[] = "Forbidden";
static const char HTTP_RESPONSE_404[] = "Not Found";
static const char HTTP_RESPONSE_413[] = "Request Entity Too Large";
static const char HTTP_RESPONSE_500[] = "Internal Server Error";
static const char HTTP_RESPONSE_501[] = "Not Implemented";
static const char HTTP_RESPONSE_503[] = "Service Unavailable";

/* http to telnet bridge path */
static const char HTTP_TO_TELNET[] = "/telnet/";
static const char HTTP_FILES[] = "/www/";

/* prototypes */
static int _init(void);
static void _cleanup(void);

static void _cb_config_changed(void);
static enum oonf_stream_session_state _cb_receive_data(
    struct oonf_stream_session *session);
static void _cb_create_error(struct oonf_stream_session *session,
    enum oonf_stream_errors error);
static void _cb_cleanup_session(struct oonf_stream_session *);

static bool _auth_okay(struct oonf_http_handler *handler,
    struct oonf_http_session *session);
static void _create_http_error(struct oonf_stream_session *session,
    enum oonf_http_result error);
static struct oonf_http_handler *_get_site_handler(const char *uri);
static const char *_get_headertype_string(enum oonf_http_result type);
static void _create_http_header(struct oonf_stream_session *session,
    enum oonf_http_result code, const char *content_type,
    size_t content_length);
static int _parse_http_header(char *header_data, size_t header_len,
    struct oonf_http_session *header);
static size_t _parse_query_string(char *s,
    char **name, char **value, size_t count);
static void  _decode_uri(char *src);
static enum oonf_http_result _cb_telnet_handler(
      struct autobuf *out, struct oonf_http_session *);
static enum oonf_http_result _cb_file_handler(
      struct autobuf *out, struct oonf_http_session *);

/* configuration variables */
static struct cfg_schema_entry _http_entries[] = {
  CFG_MAP_ACL_V46(_http_config, smc.acl,
      "acl", ACL_DEFAULT_ACCEPT, "Access control list for http interface"),
  CFG_MAP_ACL_V46(_http_config, smc.bindto,
      "bindto", "127.0.0.1\0" "::1\0" ACL_DEFAULT_REJECT, "Bind http socket to this address"),
  CFG_MAP_INT32_MINMAX(_http_config, smc.port,
      "port", "1980", "Network port for http interface", 0, false, 1, 65535),
  CFG_MAP_STRING(_http_config, www_dir, "webserver", "",
      "Path to map into the /www subdirectory of the HTTP server, empty path"
      " feature will be disabled"),
};

static struct cfg_schema_section _http_section = {
  .type = OONF_HTTP_SUBSYSTEM,
  .mode = CFG_SSMODE_UNNAMED,
  .entries = _http_entries,
  .entry_count = ARRAYSIZE(_http_entries),
  .help = "Settings for the http interface",
  .cb_delta_handler = _cb_config_changed
};

/* tree of http sites */
static struct avl_tree _http_site_tree;

/* http session handling */
static struct oonf_stream_managed _http_managed_socket = {
  .config = {
    .session_timeout = 120000, /* 120 seconds */
    .maximum_input_buffer = 65536,
    .allowed_sessions = 10,
    .receive_data = _cb_receive_data,
    .create_error = _cb_create_error,
    .cleanup = _cb_cleanup_session,
  },
};

static struct _http_config _config;

/* integrated telnet/file handler */
static struct oonf_http_handler _telnet_handler = {
  .site = HTTP_TO_TELNET,
  .content_handler = _cb_telnet_handler,
  .acl = {
      .accept_default = true,
  },
};

static struct oonf_http_handler _file_handler = {
  .site = HTTP_FILES,
  .content_handler = _cb_file_handler,
  .acl = {
      .accept_default = true,
  },
};

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_STREAM_SUBSYSTEM,
  OONF_TELNET_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_http_subsystem = {
  .name = OONF_HTTP_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
  .cfg_section = &_http_section,
};
DECLARE_OONF_PLUGIN(_oonf_http_subsystem);

/**
 * Initialize http subsystem
 * @return always returns 0
 */
static int
_init(void) {
  oonf_stream_add_managed(&_http_managed_socket);
  avl_init(&_http_site_tree, avl_comp_strcasecmp, false);

  oonf_http_add(&_telnet_handler);
  oonf_http_add(&_file_handler);

  _config.www_dir_fd = -1;
  return 0;
}

/**
 * Free all resources allocated by http subsystem
 */
void
_cleanup(void) {
  free (_config.www_dir);
  if (_config.www_dir_fd != -1) {
    close(_config.www_dir_fd);
  }

  oonf_http_remove(&_telnet_handler);
  oonf_http_remove(&_file_handler);
  oonf_stream_remove_managed(&_http_managed_socket, true);
  oonf_stream_free_managed_config(&_config.smc);
}

/**
 * Add a http handler to the server. The site variable has
 * to be initialized before this call.
 * @param handler pointer to http handler
 */
void
oonf_http_add(struct oonf_http_handler *handler) {
  assert(handler->site && handler->site[0] == '/');

  handler->directory = handler->site[strlen(handler->site)-1] == '/';
  handler->node.key = handler->site;
  avl_insert(&_http_site_tree, &handler->node);

  OONF_DEBUG(LOG_HTTP, "Added http handler for uri: %s", handler->site);
}

/**
 * Removes a http handler from the server
 * @param handler pointer to http handler
 */
void
oonf_http_remove(struct oonf_http_handler *handler) {
  avl_remove(&_http_site_tree, &handler->node);
}

/**
 * Helper function to look for a http header, get or post value
 * corresponding to a certain key.
 * Use the oonf_http_lookup_(get|post|header)() inline functions.
 *
 * @param keys pointer to list of strings (char pointers) with keys
 * @param values pointer to list of strings (char pointers) with values
 * @param count number of keys/values
 * @param key pointer to key string to look for
 * @return pointer to value or NULL if not found
 */
const char *
oonf_http_lookup_value(char **keys, char **values, size_t count, const char *key) {
  size_t i;

  for (i=0; i<count; i++) {
    if (strcmp(keys[i], key) == 0) {
      return values[i];
    }
  }
  return NULL;
}

/**
 * Callback for incoming http data
 * @param session pointer to tcp session
 * @return state of tcp session
 */
static enum oonf_stream_session_state
_cb_receive_data(struct oonf_stream_session *session) {
  struct oonf_http_session header;
  struct oonf_http_handler *handler;
  char uri[OONF_HTTP_MAX_URI_LENGTH+1];
  char *first_header;
  char *ptr;
  size_t len;

  /* search for end of http header */
  if ((first_header = strstr(abuf_getptr(&session->in), "\r\n\r\n"))) {
    first_header += 4;
  }
  else if ((first_header = strstr(abuf_getptr(&session->in), "\n\n"))) {
    first_header += 2;
  }
  else {
    /* still waiting for end of http header */
    return STREAM_SESSION_ACTIVE;
  }

  if (_parse_http_header(abuf_getptr(&session->in), abuf_getlen(&session->in), &header)) {
    OONF_INFO(LOG_HTTP, "Error, malformed HTTP header.\n");
    _create_http_error(session, HTTP_400_BAD_REQ);
    return STREAM_SESSION_SEND_AND_QUIT;
  }

  if (strcmp(header.http_version, HTTP_VERSION_1_0) != 0
      && strcmp(header.http_version, HTTP_VERSION_1_1) != 0) {
    OONF_INFO(LOG_HTTP, "Unknown HTTP version: '%s'\n", header.http_version);
    _create_http_error(session, HTTP_400_BAD_REQ);
    return STREAM_SESSION_SEND_AND_QUIT;
  }

  len = strlen(header.request_uri);
  if (len >= OONF_HTTP_MAX_URI_LENGTH) {
    OONF_INFO(LOG_HTTP, "Too long URI in HTTP header: '%s'\n", header.request_uri);
    _create_http_error(session, HTTP_400_BAD_REQ);
    return STREAM_SESSION_SEND_AND_QUIT;
  }

  OONF_DEBUG(LOG_HTTP, "Incoming HTTP request: %s %s %s\n",
      header.method, header.request_uri, header.http_version);

  /* make working copy of URI string */
  strscpy(uri, header.request_uri, sizeof(uri));

  if (strcmp(header.method, HTTP_POST) == 0) {
    const char *content_length;

    content_length = oonf_http_lookup_value(header.header_name, header.header_value,
        header.header_count, HTTP_CONTENT_LENGTH);
    if (!content_length) {
      OONF_INFO(LOG_HTTP, "Need 'content-length' for POST requests");
      _create_http_error(session, HTTP_400_BAD_REQ);
      return STREAM_SESSION_SEND_AND_QUIT;
    }

    if (strtoul(content_length, NULL, 10) > abuf_getlen(&session->in)) {
      /* header not complete */
      return STREAM_SESSION_ACTIVE;;
    }

    header.param_count = _parse_query_string(first_header,
        header.param_name, header.param_value, OONF_HTTP_MAX_PARAMS);
  }

  /* strip the URL fragment away */
  ptr = strchr(uri, '#');
  if (ptr) {
    *ptr = 0;
  }

  /* decode special characters of URI */
  _decode_uri(uri);

  if (strcmp(header.method, HTTP_GET) == 0) {
    /* HTTP-GET request */
    ptr = strchr(uri, '?');
    if (ptr != NULL) {
      *ptr++ = 0;
      header.param_count = _parse_query_string(ptr,
          header.param_name, header.param_value, OONF_HTTP_MAX_PARAMS);
    }
  } else if (strcmp(header.method, HTTP_POST) != 0) {
    OONF_INFO(LOG_HTTP, "HTTP method not implemented :'%s'", header.method);
    _create_http_error(session, HTTP_501_NOT_IMPLEMENTED);
    return STREAM_SESSION_SEND_AND_QUIT;
  }

  header.decoded_request_uri = uri;
  handler = _get_site_handler(uri);
  if (handler == NULL) {
    OONF_DEBUG(LOG_HTTP, "No HTTP handler for site: %s", uri);
    _create_http_error(session, HTTP_404_NOT_FOUND);
    return STREAM_SESSION_SEND_AND_QUIT;
  }

  if (handler->content) {
    /* static content */
    abuf_memcpy(&session->out, handler->content, handler->content_size);
    _create_http_header(session, HTTP_200_OK, NULL, abuf_getlen(&session->out));
  }
  else {
    /* custom handler */
    enum oonf_http_result result;
    /* check acl */
    if (!netaddr_acl_check_accept(&handler->acl, &session->remote_address)) {
      _create_http_error(session, HTTP_403_FORBIDDEN);
      return STREAM_SESSION_SEND_AND_QUIT;
    }

    /* check if username/password is necessary */
    if (!strarray_is_empty(&handler->auth)) {
      if (!_auth_okay(handler, &header)) {
        _create_http_error(session, HTTP_401_UNAUTHORIZED);
        return STREAM_SESSION_SEND_AND_QUIT;
      }
    }

    len = abuf_getlen(&session->out);
    result = handler->content_handler(&session->out, &header);
    if (abuf_has_failed(&session->out)) {
      abuf_setlen(&session->out, len);
      result = HTTP_500_INTERNAL_SERVER_ERROR;
    }

    if (result == HTTP_START_FILE_TRANSFER) {
      os_fd_init(&session->copy_fd, header.transfer_fd);
      session->copy_total_size = header.transfer_length;
      session->copy_bytes_sent = 0;

      _create_http_header(session, HTTP_200_OK,
          header.content_type, header.transfer_length);
    }
    else if (result != HTTP_200_OK) {
      /* create error message */
      _create_http_error(session, result);
    }
    else {
      _create_http_header(session, HTTP_200_OK,
          header.content_type, abuf_getlen(&session->out));
    }
  }
  return STREAM_SESSION_SEND_AND_QUIT;
}

/**
 * Close file transfer descriptor during cleanup
 * @param session
 */
static void
_cb_cleanup_session(struct oonf_stream_session *session) {
  os_fd_close(&session->copy_fd);
}

/**
 * Check if an incoming session is authorized to view a http site.
 * @param handler pointer to site handler
 * @param session pointer to http session.
 * @return true if authorized, false if not
 */
static bool
_auth_okay(struct oonf_http_handler *handler,
    struct oonf_http_session *session) {
  const char *auth, *name_pw_base64;
  char *ptr;

  auth = oonf_http_lookup_header(session, "Authorization");
  if (auth == NULL) {
    return false;
  }

  name_pw_base64 = str_hasnextword(auth, "Basic");
  if (name_pw_base64 == NULL) {
    return false;
  }

  strarray_for_each_element(&handler->auth, ptr) {
    if (strcmp(ptr, name_pw_base64) == 0) {
      return true;
    }
  }
  return false;
}

/**
 * Callback for generating a TCP error
 * @param session pointer to tcp session
 * @param error tcp error code
 */
static void
_cb_create_error(struct oonf_stream_session *session,
    enum oonf_stream_errors error) {
  _create_http_error(session, (enum oonf_http_result)error);
}

/**
 * Create body and header for a HTTP error
 * @param session pointer to tcp session
 * @param error http error code
 */
static void
_create_http_error(struct oonf_stream_session *session,
    enum oonf_http_result error) {
  abuf_appendf(&session->out, "<html><head><title>%s %s http server</title></head>"
      "<body><h1>HTTP error %d: %s</h1></body></html>",
      oonf_log_get_appdata()->app_name, oonf_log_get_libdata()->version,
      error, _get_headertype_string(error));
  _create_http_header(session, error, NULL, abuf_getlen(&session->out));
}

/**
 * Lookup the http site handler for an URI
 * @param uri pointer to URI
 * @return http site handler or NULL if none available
 */
static struct oonf_http_handler *
_get_site_handler(const char *uri) {
  struct oonf_http_handler *handler;
  size_t len;

  OONF_DEBUG(LOG_HTTP, "Look for handler for uri: %s", uri);

  /* look for exact match */
  handler = avl_find_element(&_http_site_tree, uri, handler, node);
  if (handler) {
    return handler;
  }

  /* look for directory handler with shorter URL */
  handler = avl_find_le_element(&_http_site_tree, uri, handler, node);
  if (handler && handler->directory) {
    len = strlen(handler->site);

    /* check if complete handler path (ending with /) matchs uri */
    if (strncasecmp(handler->site, uri, len) == 0) {
      return handler;
    }
  }

  /* user might have skipped trailing / for directory */
  handler = avl_find_ge_element(&_http_site_tree, uri, handler, node);
  if (handler) {
    len = strlen(uri);

    if (strncasecmp(handler->site, uri, len) == 0
        && handler->site[len] == '/' && handler->site[len+1] == 0) {
      return handler;
    }
  }
  return NULL;
}

/**
 * @param type http result code
 * @return string representation of http result code
 */
static const char *
_get_headertype_string(enum oonf_http_result type) {
  switch (type) {
    case HTTP_200_OK:
      return HTTP_RESPONSE_200;
    case HTTP_400_BAD_REQ:
      return HTTP_RESPONSE_400;
    case HTTP_401_UNAUTHORIZED:
      return HTTP_RESPONSE_401;
    case HTTP_403_FORBIDDEN:
      return HTTP_RESPONSE_403;
    case HTTP_404_NOT_FOUND:
      return HTTP_RESPONSE_404;
    case HTTP_413_REQUEST_TOO_LARGE:
      return HTTP_RESPONSE_413;
    case HTTP_500_INTERNAL_SERVER_ERROR:
      return HTTP_RESPONSE_500;
    case HTTP_501_NOT_IMPLEMENTED:
      return HTTP_RESPONSE_501;
    case HTTP_503_SERVICE_UNAVAILABLE:
      return HTTP_RESPONSE_503;
    default:
      return HTTP_RESPONSE_500;
  }
}

/**
 * Create a http header for an existing content and put
 * it in front of the content.
 * @param session pointer to tcp session
 * @param code http result code
 * @param content_type explicit content type or NULL for
 * @param content_length length of content, 0 for no content length
 *   plain html
 */
static void
_create_http_header(struct oonf_stream_session *session,
    enum oonf_http_result code, const char *content_type, size_t content_length) {
  struct autobuf buf;
  struct timeval currtime;

  abuf_init(&buf);

  abuf_appendf(&buf, "%s %d %s\r\n", HTTP_VERSION_1_0, code, _get_headertype_string(code));

  /* Date */
  os_core_gettimeofday(&currtime);
  abuf_strftime(&buf, "Date: %a, %d %b %Y %H:%M:%S GMT\r\n", localtime(&currtime.tv_sec));

  /* Server version */
  abuf_appendf(&buf, "Server: %s\r\n",
      oonf_log_get_libdata()->version);

  /* connection-type */
  abuf_puts(&buf, "Connection: closed\r\n");

  /* MIME type */
  if (content_type == NULL) {
    content_type = HTTP_CONTENTTYPE_HTML;
  }
  abuf_appendf(&buf, "%s: %s\r\n", HTTP_CONTENT_TYPE, content_type);

  /* Content length */
  if (content_length > 0) {
    abuf_appendf(&buf, "Content-length: %zu\r\n", content_length);
  }

  if (code == HTTP_401_UNAUTHORIZED) {
    abuf_appendf(&buf, "WWW-Authenticate: Basic realm=\"%s\"\r\n", "RealmName");
  }

  /*
   * Cache-control
   * No caching dynamic pages
   */
  abuf_puts(&buf, "Cache-Control: no-cache\r\n");

  /* End header */
  abuf_puts(&buf, "\r\n");

  abuf_memcpy_prepend(&session->out, abuf_getptr(&buf), abuf_getlen(&buf));
  OONF_DEBUG(LOG_HTTP, "Generated Http-Header:\n%s", abuf_getptr(&buf));

  abuf_free(&buf);
}

/**
 * Parse a HTTP header
 * @param header_data pointer to header data
 * @param header_len length of header data
 * @param header pointer to object to store the results
 * @return 0 if http header was correct, -1 if an error happened
 */
static int
_parse_http_header(char *header_data, size_t header_len,
    struct oonf_http_session *header) {
  size_t header_index;

  assert(header_data);
  assert(header);

  memset(header, 0, sizeof(struct oonf_http_session));
  header->method = header_data;

  while(true) {
    if (header_len < 2) {
      goto unexpected_end;
    }

    if (*header_data == ' ' && header->http_version == NULL) {
      *header_data = '\0';

      if (header->request_uri == NULL) {
        header->request_uri = &header_data[1];
      }
      else if (header->http_version == NULL) {
        header->http_version = &header_data[1];
      }
    }
    else if (*header_data == '\r') {
      *header_data = '\0';
    }
    else if (*header_data == '\n') {
      *header_data = '\0';

      header_data++; header_len--;
      break;
    }

    header_data++; header_len--;
  }

  if (header->http_version == NULL) {
    goto unexpected_end;
  }

  for(header_index = 0; true; header_index++) {
    if (*header_data == '\n') {
      break;
    }
    else if (*header_data == '\r') {
      if (header_len < 2) return true;

      if (header_data[1] == '\n') {
        break;
      }
    }

    if (header_index >= OONF_HTTP_MAX_HEADERS) {
      goto too_many_fields;
    }

    header->header_name[header_index] = header_data;

    while(true) {
      if (header_len < 1) {
        goto unexpected_end;
      }

      if (*header_data == ':') {
        *header_data = '\0';

        header_data++; header_len--;
        break;
      }
      else if (*header_data == ' ' || *header_data == '\t') {
        *header_data = '\0';
      }
      else if (*header_data == '\n' || *header_data == '\r') {
        goto unexpected_end;
      }

      header_data++; header_len--;
    }

    while(true) {
      if (header_len < 1) {
        goto unexpected_end;
      }

      if (header->header_value[header_index] == NULL) {
        if (*header_data != ' ' && *header_data != '\t') {
          header->header_value[header_index] = header_data;
        }
      }

      if (*header_data == '\n') {
        if (header_len < 2) {
          goto unexpected_end;
        }

        if (header_data[1] == ' ' || header_data[1] == '\t') {
          *header_data = ' ';
          header_data[1] = ' ';

          header_data += 2; header_len -= 2;
          continue;
        }

        *header_data = '\0';

        if (header->header_value[header_index] == NULL) {
          header->header_value[header_index] = header_data;
        }

        header_data++; header_len--;
        break;
      }
      else if (*header_data == '\r') {
        if (header_len < 2) {
          goto unexpected_end;
        }

        if (header_data[1] == '\n') {
          if (header_len < 3) {
            goto unexpected_end;
          }

          if (header_data[2] == ' ' || header_data[2] == '\t') {
            *header_data = ' ';
            header_data[1] = ' ';
            header_data[2] = ' ';

            header_data += 3; header_len -= 3;
            continue;
          }

          *header_data = '\0';

          if (header->header_value[header_index] == NULL) {
            header->header_value[header_index] = header_data;
          }

          header_data += 2; header_len -= 2;
          break;
        }
      }

      header_data++; header_len--;
    }
  }

  header->header_count = header_index;
  return 0;

too_many_fields:
  OONF_DEBUG(LOG_HTTP, "Error, too many HTTP header fields\n");
  return -1;

unexpected_end:
  OONF_DEBUG(LOG_HTTP, "Error, unexpected end of HTTP header\n");
  return -1;
}

/**
 * Parse the query string (either get or post) and store it into
 * a list of key/value pointers. The original string will be
 * modified for doing this.
 * @param s pointer to query string
 * @param name pointer to array of stringpointers for keys
 * @param value pointer to array of stringpointers for values
 * @param count maximum allowed number of keys/values
 * @return number of generated keys/values
 */
static size_t
_parse_query_string(char *s, char **name, char **value, size_t count) {
  char *ptr;
  size_t i = 0;

  assert(s);
  assert(name);
  assert(value);

  while (s != NULL && i < count) {
    name[i] = s;

    s = strchr(s, '&');
    if (s != NULL) {
      *s++ = '\0';
    }

    ptr = strchr(name[i], '=');
    if (ptr != NULL) {
      *ptr++ = '\0';
      value[i] = ptr;
    } else {
      value[i] = &name[i][strlen(name[i])];
    }

    if(name[i][0] != '\0') {
      i++;
    }
  }

  return i;
}

/**
 * Decode encoded characters of an URI. The URL will be modified
 * inline by this function.
 * @param src pointer to URI string
 */
static void
_decode_uri(char *src) {
  char *dst = src;

  while (*src) {
    if (*src == '%' && src[1] && src[2]) {
      int value = 0;

      src++;
      sscanf(src, "%02x", &value);
      *dst++ = (char) value;
      src += 2;
    } else {
      *dst++ = *src++;
    }
  }
  *dst = 0;
}

/**
 * Http to Telnet bridge
 * @param out output stream
 * @param session http session
 * @return http result calculated from telnet result
 */
static enum oonf_http_result
_cb_telnet_handler(struct autobuf *out, struct oonf_http_session *session) {
  static char EOL = 0;
  enum oonf_telnet_result result;
  char buffer[1024];
  char *ptr1, *ptr2, *ptr3;

  session->content_type = HTTP_CONTENTTYPE_TEXT;
  strscpy(buffer, &session->decoded_request_uri[sizeof(HTTP_TO_TELNET)-1], sizeof(buffer));

  ptr1 = buffer;
  while (true) {
    ptr2 = strchr(ptr1, '/');
    if (ptr2) {
      *ptr2 = 0;
    }

    OONF_DEBUG(LOG_HTTP, "Process '%s'", ptr1);
    ptr3 = strchr(ptr1, ' ');
    if (ptr3) {
      *ptr3++ = 0;
    }
    else {
      ptr3 = &EOL;
    }

    result = oonf_telnet_execute(ptr1, ptr3, out, session->remote);
    switch (result) {
      case TELNET_RESULT_ACTIVE:
      case TELNET_RESULT_QUIT:
        break;

      case _TELNET_RESULT_UNKNOWN_COMMAND:
        return HTTP_404_NOT_FOUND;

      default:
        return HTTP_400_BAD_REQ;
    }

    if (!ptr2) {
      break;
    }
    ptr1 = ptr2 + 1;
  }
  return HTTP_200_OK;
}

/**
 * Http File transfer handler
 * @param out output stream
 * @param session http session
 * @return http result
 */
static enum oonf_http_result
_cb_file_handler(struct autobuf *out __attribute__((unused)),
    struct oonf_http_session *session) {
  const char *file;
  struct stat st;
  int fd;

  if (_config.www_dir_fd == -1) {
    /* file server not active */
    return HTTP_404_NOT_FOUND;
  }

  if (strstr(session->decoded_request_uri, "/../")) {
    /* directory traversal is not allowed */
    OONF_INFO(LOG_HTTP, "Blocked directory traversal '%s' uri",
        session->decoded_request_uri);
    return HTTP_404_NOT_FOUND;
  }

  file = &session->decoded_request_uri[sizeof(HTTP_FILES)-1];
  if (file[0] == '/') {
    /* directory traversal is not allowed */
    OONF_INFO(LOG_HTTP, "Blocked directory traversal '%s' uri",
        session->decoded_request_uri);
    return HTTP_404_NOT_FOUND;
  }

  fd = openat(_config.www_dir_fd, file, O_NONBLOCK, O_RDONLY);
  if (fd == -1) {
    OONF_INFO(LOG_HTTP, "Could not open file '%s': %s (%d)",
        file, strerror(errno), errno);
    return HTTP_404_NOT_FOUND;
  }

  if (fstat(fd, &st)) {
    OONF_WARN(LOG_HTTP, "Could not get file statistics of '%s': %s (%d)",
        file, strerror(errno), errno);
    return HTTP_404_NOT_FOUND;
  }

  /* initialize file transfer */
  session->content_type = oonf_http_lookup_header(session, HTTP_CONTENT_TYPE);
  session->transfer_fd = fd;
  session->transfer_length = st.st_size;

  /* start file transfer */
  return HTTP_START_FILE_TRANSFER;
}

/**
 * Callback for configuration changes
 */
static void
_cb_config_changed(void) {
  /* generate binary config */
  if (cfg_schema_tobin(&_config, _http_section.post,
      _http_entries, ARRAYSIZE(_http_entries))) {
    /* error in conversion */
    OONF_WARN(LOG_HTTP, "Cannot map http config to binary data");
    return;
  }

  oonf_stream_apply_managed(&_http_managed_socket, &_config.smc);

  if (_config.www_dir_fd != -1) {
    close(_config.www_dir_fd);
    _config.www_dir_fd = -1;
  }
  if (_config.www_dir && _config.www_dir[0]) {
    _config.www_dir_fd = open(_config.www_dir, O_DIRECTORY, O_RDONLY);
    if (_config.www_dir_fd == -1) {
      OONF_WARN(LOG_HTTP, "Could not open file directory '%s': %s (%d)",
          _config.www_dir, strerror(errno), errno);
    }
  }
}
