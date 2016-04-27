
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
#include <fcntl.h>
#include <unistd.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "common/common_types.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "core/oonf_subsystem.h"
#include "subsystems/os_vif.h"

/* Definitions */
#define LOG_OS_VIF _oonf_os_vif_subsystem.logging

static int _init(void);
static void _cleanup(void);

/* subsystem definition */
static const char *_dependencies[0] = {
};

static struct oonf_subsystem _oonf_os_vif_subsystem = {
  .name = OONF_OS_VIF_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_os_vif_subsystem);

static struct avl_tree _vif_tree;

/**
 * Initialize virtual interface subsystem
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  avl_init(&_vif_tree, avl_comp_strcasecmp, false);
  return 0;
}

/**
 * Cleanup virtual interface subsystem
 */
static void
_cleanup(void) {
  struct os_vif *vif, *vif_it;

  avl_for_each_element_safe(&_vif_tree, vif, _vif_node, vif_it) {
    os_vif_close(vif);
  }
}

/**
 * Open a new virtual interface
 * @param sock os socket
 * @param vif pointer to virtual interface object
 * @return -1 if an error happened, 0 otherwise
 */
int
os_vif_linux_open(struct os_fd *sock, struct os_vif *vif) {
  struct ifreq if_req;
  int fd, flag;

  switch (vif->type) {
    case OS_VIF_MAC:
      flag = IFF_TAP;
      break;
    case OS_VIF_IP:
      flag = IFF_TUN;
      break;
    default:
      OONF_WARN(LOG_OS_VIF, "Unknown vif type: %d", vif->type);
      return -1;
  }

  fd = open("/dev/net/tun", O_RDWR);
  if (fd < 0) {
    OONF_WARN(LOG_OS_VIF, "Cannot open virtual interface device: %s (%d)",
        strerror(errno), errno);
    return -1;
  }

  memset(&if_req, 0, sizeof(if_req));
  strscpy(if_req.ifr_name, vif->if_name, IF_NAMESIZE);

  /*
   * Specify the IFF_TAP flag for Ethernet packets.
   * Specify IFF_NO_PI for not receiving extra meta packet information.
   */
  if_req.ifr_flags = flag | IFF_NO_PI;

  if (ioctl(fd, TUNSETIFF, (void *)&if_req) < 0) {
    OONF_WARN(LOG_OS_VIF, "Cannot set mode of virtual interface device: %s (%d)",
        strerror(errno), errno);
    close(fd);
    return -1;
  }

  /* initialize vif memory */
  os_fd_init(sock, fd);
  vif->_vif_node.key = vif->if_name;

  avl_insert(&_vif_tree, &vif->_vif_node);

  return 0;
}

/**
 * Close a virtual interface
 * @param vif pointer to virtual interface object
 */
void
os_vif_linux_close(struct os_vif *vif) {
  if (avl_is_node_added(&vif->_vif_node)) {
    os_fd_close(vif->fd);
    avl_remove(&_vif_tree, &vif->_vif_node);
  }
}

/**
 * get virtual interface tree
 * @return vif tree
 */
struct avl_tree *
os_vif_linux_get_tree(void) {
  return &_vif_tree;
}
