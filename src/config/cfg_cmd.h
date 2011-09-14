
/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004-2011, the olsr.org team - see HISTORY file
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

#ifndef CFG_CMD_H_
#define CFG_CMD_H_

#include "common/common_types.h"
#include "config/cfg_db.h"
#include "config/cfg.h"

/* state for parsing a command line */
struct cfg_cmd_state {
  /* currently selected parser, NULL for 'auto' */
  char *format;

  /* last used section type */
  char *section_type;

  /* last used section name, NULL for unnamed section */
  char *section_name;
};

EXPORT void cfg_cmd_add(struct cfg_cmd_state *state);
EXPORT void cfg_cmd_remove(struct cfg_cmd_state *state);
EXPORT int cfg_cmd_handle_set(struct cfg_db *db,
    struct cfg_cmd_state *state, const char *arg, struct autobuf *log);
EXPORT int cfg_cmd_handle_remove(struct cfg_db *db,
    struct cfg_cmd_state *state, const char *arg, struct autobuf *log);
EXPORT int cfg_cmd_handle_get(struct cfg_db *db,
    struct cfg_cmd_state *state, const char *arg, struct autobuf *log);
EXPORT int cfg_cmd_handle_load(struct cfg_db *db,
    struct cfg_cmd_state *state, const char *arg, struct autobuf *log);
EXPORT int cfg_cmd_handle_save(struct cfg_db *db,
    struct cfg_cmd_state *state, const char *arg, struct autobuf *log);
EXPORT int cfg_cmd_handle_format(struct cfg_cmd_state *state, const char *arg);
EXPORT int cfg_cmd_handle_schema(struct cfg_db *db,
    const char *arg, struct autobuf *log);

#endif /* CFG_CMD_H_ */
