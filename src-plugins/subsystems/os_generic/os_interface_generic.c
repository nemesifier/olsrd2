/*
 * os_interface_generic_get_bindaddress.c
 *
 *  Created on: 07.03.2016
 *      Author: rogge
 */

#include "common/common_types.h"
#include "common/avl.h"
#include "subsystems/os_interface.h"

static const struct netaddr *_get_fixed_prefix(
    int af_type, struct netaddr_acl *filter);
static const struct netaddr *_get_exact_match_bindaddress(
    int af_type, struct netaddr_acl *filter,
    struct os_interface *os_if);
static const struct netaddr *_get_matching_bindaddress(
    int af_type, struct netaddr_acl *filter,
    struct os_interface *os_if);

/**
 * Calculate the IP address a socket should bind to
 * @param af_type address family for result
 * @param filter filter for IP address to bind on
 * @param os_if interface to bind to socket on, NULL if not
 *   bound to an interface.
 * @return pointer to address, NULL if no valid address was found
 */
const struct netaddr *
os_interface_generic_get_bindaddress(int af_type,
    struct netaddr_acl *filter, struct os_interface *os_if) {
  const struct netaddr *result;

  result = NULL;
  if (os_if == NULL) {
    result = _get_fixed_prefix(af_type, filter);
  }
  if (!result) {
    result = _get_exact_match_bindaddress(af_type, filter, os_if);
  }
  if (!result) {
    result = _get_matching_bindaddress(af_type, filter, os_if);
  }
  return result;
}

/**
 * Search for an interface by its base-index
 * @param ifindex index of the interface
 * @return first fitting interface data, NULL if not found
 */
struct os_interface *
os_interface_generic_get_data_by_ifbaseindex(unsigned ifindex) {
  struct os_interface *os_if;

  avl_for_each_element(os_interface_get_tree(), os_if, _node) {
    if (os_if->base_index == ifindex) {
      return os_if;
    }
  }
  return NULL;
}

/**
 * Search for an interface by its index
 * @param ifindex index of the interface
 * @return interface data, NULL if not found
 */
struct os_interface *
os_interface_generic_get_data_by_ifindex(unsigned ifindex) {
  struct os_interface *os_if;

  avl_for_each_element(os_interface_get_tree(), os_if, _node) {
    if (os_if->index == ifindex) {
      return os_if;
    }
  }
  return NULL;
}

/**
 * Get the prefix of an interface fitting to a destination address
 * @param destination destination address
 * @param os_if interface data, NULL to search over all interfaces
 * @return network prefix (including full host), NULL if not found
 */
const struct netaddr *
os_interface_generic_get_prefix_from_dst(
    struct netaddr *destination, struct os_interface *os_if) {
  struct os_interface_ip *ip;
  const struct netaddr *result;

  if (os_if == NULL) {
    avl_for_each_element(os_interface_get_tree(), os_if, _node) {
      result = os_interface_get_prefix_from_dst(destination, os_if);
      if (result) {
        return result;
      }
    }
    return NULL;
  }

  avl_for_each_element(&os_if->addresses, ip, _node) {
    if (netaddr_is_in_subnet(&ip->prefix, destination)) {
      return &ip->prefix;
    }
  }

  return NULL;
}

/**
 * Checks if the whole ACL is one maximum length address
 * (or two, one for each possible address type).
 * @param af_type requested address family
 * @param filter filter to parse
 * @return pointer to address to bind socket to, NULL if no match
 */
static const struct netaddr *
_get_fixed_prefix(int af_type, struct netaddr_acl *filter) {
  const struct netaddr *first, *second;
  if (filter->reject_count > 0) {
    return NULL;
  }

  if (filter->accept_count == 0 || filter->accept_count > 2) {
    return NULL;
  }

  first = &filter->accept[0];
  if (netaddr_get_prefix_length(first) != netaddr_get_maxprefix(first)) {
    return NULL;
  }

  if (filter->accept_count == 2) {
    second = &filter->accept[1];

    if (netaddr_get_address_family(first) ==
        netaddr_get_address_family(second)) {
      /* must be two different address families */
      return NULL;
    }

    if (netaddr_get_prefix_length(second) != netaddr_get_maxprefix(second)) {
      return NULL;
    }
    if (netaddr_get_address_family(second) == af_type) {
      return second;
    }
  }

  if (netaddr_get_address_family(first) == af_type) {
    return first;
  }
  return NULL;
}

/**
 * Finds an IP on an/all interfaces that matches an exact (maximum length)
 * filter rule
 *
 * @param af_type address family type to look for
 * @param filter filter that must be matched
 * @param os_if interface to look through, NULL for all interfaces
 * @return pointer to address to bind socket to, NULL if no match
 */
static const struct netaddr *
_get_exact_match_bindaddress(int af_type, struct netaddr_acl *filter,
    struct os_interface *os_if) {
  struct os_interface_ip *ip;
  const struct netaddr *result;
  size_t i;

  /* handle the 'all interfaces' case */
  if (os_if == NULL) {
    avl_for_each_element(os_interface_get_tree(), os_if, _node) {
      if ((result = _get_exact_match_bindaddress(af_type, filter, os_if)) != NULL) {
        return result;
      }
    }
    return NULL;
  }

  /* run through all filters */
  for (i=0; i<filter->accept_count; i++) {
    /* look for maximum prefix length filters */
    if (netaddr_get_prefix_length(&filter->accept[i]) != netaddr_get_af_maxprefix(af_type)) {
      continue;
    }

    /* run through all interface addresses and look for match */
    avl_for_each_element(&os_if->addresses, ip, _node) {
      if (netaddr_cmp(&ip->address, &filter->accept[i]) == 0) {
        return &filter->accept[i];
      }
    }
  }

  /* no exact match found */
  return NULL;
}

/**
 * Finds an IP on an/all interfaces that matches a filter rule
 *
 * @param af_type address family type to look for
 * @param filter filter that must be matched
 * @param os_if interface to look through, NULL for all interfaces
 * @return pointer to address to bind socket to, NULL if no match
 */
static const struct netaddr *
_get_matching_bindaddress(int af_type, struct netaddr_acl *filter,
    struct os_interface *os_if) {
  struct os_interface_ip *ip;
  const struct netaddr *result;

  /* handle the 'all interfaces' case */
  if (os_if == NULL) {
    avl_for_each_element(os_interface_get_tree(), os_if, _node) {
      if ((result = _get_matching_bindaddress(af_type, filter, os_if)) != NULL) {
        return result;
      }
    }
    return NULL;
  }

  /* run through interface address list looking for filter match */
  avl_for_each_element(&os_if->addresses, ip, _node) {
    if (netaddr_get_address_family(&ip->address) != af_type) {
      continue;
    }

    if (netaddr_acl_check_accept(filter, &ip->address)) {
      return &ip->address;
    }
  }
  return NULL;
}
