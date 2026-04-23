/*
 * Copyright 2020 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <netlink/route/neighbour.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <netlink/route/rule.h>

#include "safec_lib_common.h"

#include "libnet_util.h"

/************** Common helpers ******************/

int libnet_connect(struct nl_sock *socket, int proto)
{
        int err = 0;

        err = nl_connect(socket, proto);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to connect netlink socket (proto=%d): %s (err=%d)\n",
                        proto, nl_geterror(err), err);
        }

        return err;
}

struct nl_sock *libnet_alloc_socket(void)
{
        struct nl_sock *socket;

        socket = nl_socket_alloc();
        if (socket == NULL) {
                CNL_LOG_ERROR("Failed to allocate netlink socket\n");
                return NULL;
        }

        return socket;
}

int libnet_addr_parse(const char *str, int family, struct nl_addr **addr)
{
        int err = 0;

        err = nl_addr_parse(str, family, addr);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to parse address '%s': %s (err=%d)\n",
                        str, nl_geterror(err), err);
                return err;
        }

        return err;
}

struct nl_cache *libnet_alloc_cache(struct nl_sock *socket, const char *name,
                                    int (*ac)(struct nl_sock *, struct nl_cache **))
{
        struct nl_cache *cache;
        int err;

        err = ac(socket, &cache);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to allocate %s cache: %s (err=%d)\n",
                        name, nl_geterror(err), err);
                return NULL;
        }

        return cache;
}

struct nl_cache *libnet_alloc_cache_flags(struct nl_sock *socket,
                                          const char *name, unsigned int flags,
                                          int (*ac)(struct nl_sock *, struct nl_cache **,
                                                    unsigned int))
{
        struct nl_cache *cache;
        int err;

        err = ac(socket, &cache, flags);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to allocate %s cache (flags=0x%x): %s (err=%d)\n",
                        name, flags, nl_geterror(err), err);
                return NULL;
        }

        return cache;
}

/************** Link helpers ******************/

struct rtnl_link *libnet_link_alloc(void)
{
        struct rtnl_link *rt_link;

        rt_link = rtnl_link_alloc();
        if (rt_link == NULL) {
                CNL_LOG_ERROR("Failed to allocate link object\n");
                return NULL;
        }

        return rt_link;
}

struct nl_cache *libnet_link_alloc_cache_family_flags(struct nl_sock *socket,
                                                      int family,
                                                      unsigned int flags)
{
        struct nl_cache *cache;
        int err;

        err = rtnl_link_alloc_cache_flags(socket, family, &cache, flags);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to allocate link cache (family=%d, flags=0x%x): %s (err=%d)\n",
                        family, flags, nl_geterror(err), err);
                return NULL;
        }

        return cache;
}

struct nl_cache *libnet_link_alloc_cache_family(struct nl_sock *socket, int family)
{
        return libnet_link_alloc_cache_family_flags(socket, family, 0);
}

struct nl_cache *libnet_link_alloc_cache(struct nl_sock *socket)
{
        return libnet_link_alloc_cache_family(socket, AF_UNSPEC);
}

struct nl_cache *libnet_link_alloc_cache_flags(struct nl_sock *socket,
                                               unsigned int flags)
{
        return libnet_link_alloc_cache_family_flags(socket, AF_UNSPEC, flags);
}

/************** Address helpers ******************/

struct rtnl_addr *libnet_addr_alloc(void)
{
        struct rtnl_addr *address;

        address = rtnl_addr_alloc();
        if (address == NULL) {
                CNL_LOG_ERROR("Failed to allocate address object\n");
                return NULL;
        }

        return address;
}

int libnet_addr_parse_local(struct rtnl_addr *address, char *args)
{
        struct nl_addr *nl_a;
        int err = 0;

        err = libnet_addr_parse(args, rtnl_addr_get_family(address), &nl_a);
        if (err != 0) {
                return err;
        }

        err = rtnl_addr_set_local(address, nl_a);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to set local address '%s': %s (err=%d)\n",
                        args, nl_geterror(err), err);
        }

FREE_ADDR:
        nl_addr_put(nl_a);
        return err;
}

int libnet_addr_parse_dev(struct rtnl_addr *address, struct nl_cache *link_cache,
                          char *args)
{
        int ival;
        int err = 0;

        if (link_cache == NULL) {
                CNL_LOG_ERROR("link_cache is NULL\n");
                return EINVAL;
        }

        ival = rtnl_link_name2i(link_cache, args);
        if (ival <= 0) {
                CNL_LOG_ERROR("Link '%s' does not exist or invalid index\n", args);
                return ENOENT;
        }

        rtnl_addr_set_ifindex(address, ival);
        return err;
}

int libnet_addr_parse_label(struct rtnl_addr *address, char *args)
{
        int err = 0;

        err = rtnl_addr_set_label(address, args);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to set address label '%s': %s (err=%d)\n",
                        args, nl_geterror(err), err);
        }

        return err;
}

int libnet_addr_parse_peer(struct rtnl_addr *address, char *args)
{
        struct nl_addr *nl_a;
        int err = 0;

        err = libnet_addr_parse(args, rtnl_addr_get_family(address), &nl_a);
        if (err != 0) {
                return err;
        }

        err = rtnl_addr_set_peer(address, nl_a);
        if (err < 0)
                CNL_LOG_ERROR("Failed to set peer address '%s': %s (err=%d)\n",
                        args, nl_geterror(err), err);

FREE_ADDR:
        nl_addr_put(nl_a);
        return err;
}

int libnet_addr_parse_broadcast(struct rtnl_addr *address, char *args)
{
        struct nl_addr *nl_a;
        int err = 0;

        err = libnet_addr_parse(args, rtnl_addr_get_family(address), &nl_a);
        if (err != 0) {
                return err;
        }

        err = rtnl_addr_set_broadcast(address, nl_a);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to set broadcast address '%s': %s (err=%d)\n",
                        args, nl_geterror(err), err);
                goto FREE_ADDR;
        }

FREE_ADDR:
        nl_addr_put(nl_a);
        return err;
}

static uint32_t parse_lifetime(const char *args, int *err)
{
        uint64_t msecs;

        if (!strcasecmp(args, "forever"))
                return 0xFFFFFFFFU;

        *err = nl_str2msec(args, &msecs);
        if (*err < 0) {
                CNL_LOG_ERROR("Failed to parse time string '%s': %s (err=%d)\n",
                        args, nl_geterror(*err), *err);
                return 0;
        }

        *err = 0;
        return (msecs / 1000);
}

int libnet_addr_parse_preferred(struct rtnl_addr *address, char *args)
{
        int err = 0;
        uint32_t lifetime = parse_lifetime(args, &err);

        if (err != 0) {
                return err;
        } else {
                rtnl_addr_set_preferred_lifetime(address, lifetime);
                return 0;
        }
}

int libnet_addr_parse_valid(struct rtnl_addr *address, char *args)
{
        int err = 0;
        uint32_t lifetime = parse_lifetime(args, &err);

        if (err != 0) {
                return err;
        } else {
                rtnl_addr_set_valid_lifetime(address, lifetime);
                return 0;
        }
}

/************** Route helpers ******************/

struct rtnl_route *libnet_route_alloc(void)
{
        struct rtnl_route *rt_route;

        rt_route = rtnl_route_alloc();
        if (rt_route == NULL) {
                CNL_LOG_ERROR("Failed to allocate route object\n");
                return NULL;
        }

        return rt_route;
}

struct nl_cache *libnet_route_alloc_cache(struct nl_sock *socket, int flags)
{
        struct nl_cache *cache;
        int err;

        err = rtnl_route_alloc_cache(socket, AF_UNSPEC, flags, &cache);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to allocate route cache (flags=%d): %s (err=%d)\n",
                        flags, nl_geterror(err), err);
                return NULL;
        }

        return cache;
}

/*
 * Convert addr_str to a netlink address object using the route's address
 * family, then set it as the route destination via rtnl_route_set_dst.
 */
int libnet_route_parse_dst(struct rtnl_route *rt_route, char *args)
{
        struct nl_addr *addr;
        int err = 0;

        err = libnet_addr_parse(args, rtnl_route_get_family(rt_route), &addr);
        if (err != 0) {
                return err;
        }

        err = rtnl_route_set_dst(rt_route, addr);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to set destination address '%s': %s (err=%d)\n",
                        args, nl_geterror(err), err);
                goto FREE_ADDR;
        }

FREE_ADDR:
        nl_addr_put(addr);
        return err;
}

/*
 * Parse a comma-separated "name=value" options string, resolve each metric
 * name to its RTAX_* kernel constant via an explicit lookup table, convert
 * the value with strtoul, then apply it via rtnl_route_set_metric.
 */
int libnet_route_parse_metric(struct rtnl_route *route, char *options)
{
        /*
         * Map metric names to their explicit RTAX_* kernel constants.
         * Using named constants decouples the lookup from any assumed
         * positional ordering and clearly documents the kernel origin.
         */
        static const struct {
                const char *name;
                int         rtax_id;
        } metric_map[] = {
                { "lock",        RTAX_LOCK        },
                { "mtu",         RTAX_MTU         },
                { "window",      RTAX_WINDOW      },
                { "rtt",         RTAX_RTT         },
                { "rttvar",      RTAX_RTTVAR      },
                { "sstresh",     RTAX_SSTHRESH    },
                { "cwnd",        RTAX_CWND        },
                { "advmss",      RTAX_ADVMSS      },
                { "reordering",  RTAX_REORDERING  },
                { "hoplimit",    RTAX_HOPLIMIT    },
                { "initcwnd",    RTAX_INITCWND    },
                { "features",    RTAX_FEATURES    },
        };
        static const size_t metric_map_len = sizeof(metric_map) / sizeof(metric_map[0]);

        char *saveptr = NULL;
        char *token;
        int ret = 0;

        for (token = strtok_r(options, ",", &saveptr);
             token != NULL;
             token = strtok_r(NULL, ",", &saveptr)) {

                const char *metric_name;
                const char *metric_str;
                char *parse_tail;
                unsigned long metric_val;
                char *eq;
                size_t i;

                eq = strchr(token, '=');
                if (eq == NULL) {
                        CNL_LOG_ERROR("Metric token \"%s\" is not in name=value form\n", token);
                        return -EINVAL;
                }
                *eq = '\0';
                metric_name = token;
                metric_str  = eq + 1;

                for (i = 0; i < metric_map_len; i++) {
                        if (strcmp(metric_name, metric_map[i].name) == 0)
                                break;
                }
                if (i == metric_map_len) {
                        CNL_LOG_ERROR("Metric name \"%s\" is not recognised\n", metric_name);
                        return -EINVAL;
                }

                if (*metric_str == '\0') {
                        CNL_LOG_ERROR("Metric \"%s\" has no value\n", metric_name);
                        return -EINVAL;
                }

                metric_val = strtoul(metric_str, &parse_tail, 0);
                if (parse_tail == metric_str) {
                        CNL_LOG_ERROR("Metric \"%s\" value \"%s\" is not a valid integer\n",
                                metric_name, metric_str);
                        return -EINVAL;
                }

                ret = rtnl_route_set_metric(route, metric_map[i].rtax_id, metric_val);
                if (ret < 0) {
                        CNL_LOG_ERROR("Failed to set metric \"%s\": %s (err=%d)\n",
                                metric_name, nl_geterror(ret), ret);
                        return ret;
                }
        }
        return ret;
}

/*
 * Parse subopt tokens ("dev", "via", "weight", "as") from subopts, resolve
 * each to a nexthop attribute (interface index, gateway address, weight, or
 * new-destination address), then attach the nexthop to rt_route via
 * rtnl_route_add_nexthop.
 */
int libnet_route_parse_nexthop(struct rtnl_route *rt_route, char *subopts,
                               struct nl_cache *link_cache)
{
        enum {
                NEXTHOP_DEV,
                NEXTHOP_VIA,
                NEXTHOP_WEIGHT,
                NEXTHOP_AS,
        };
        static char *const tokens[] = {
                "dev",
                "via",
                "weight",
                "as",
                NULL,
        };
        unsigned long weight_val;
        struct rtnl_nexthop *nexthop;
        char *tok_val;
        char *scan_end;
        struct nl_addr *nh_addr;
        int link_idx;
        int status = 0;

        if (!(nexthop = rtnl_route_nh_alloc())) {
                CNL_LOG_ERROR("Out of memory\n");
                return ENOMEM;
        }

        while (*subopts != '\0') {
                int ret = getsubopt(&subopts, tokens, &tok_val);
                if (ret == -1) {
                        CNL_LOG_ERROR("Unknown nexthop token %s\n", tok_val);
                        return EINVAL;
                }

                if (tok_val == NULL) {
                        CNL_LOG_ERROR("Missing argument to option %s\n", tokens[ret]);
                        return EINVAL;
                }

                switch (ret) {
                case NEXTHOP_DEV:
                        if (!(link_idx = rtnl_link_name2i(link_cache, tok_val))) {
                                CNL_LOG_ERROR("Link device '%s' does not exist\n", tok_val);
                                return ENOENT;
                        }

                        rtnl_route_nh_set_ifindex(nexthop, link_idx);
                        break;

                case NEXTHOP_VIA:
                        if (rtnl_route_get_family(rt_route) == AF_MPLS) {
                                if ((status = libnet_addr_parse(tok_val, 0, &nh_addr)) != 0) {
                                        return status;
                                }
                                rtnl_route_nh_set_via(nexthop, nh_addr);
                        } else {
                                if ((status = libnet_addr_parse(tok_val, rtnl_route_get_family(rt_route), &nh_addr)) != 0) {
                                        return status;
                                }
                                rtnl_route_nh_set_gateway(nexthop, nh_addr);
                        }
                        nl_addr_put(nh_addr);
                        break;

                case NEXTHOP_AS:
                        if ((status = libnet_addr_parse(tok_val, rtnl_route_get_family(rt_route), &nh_addr)) != 0) {
                                return status;
                        }
                        rtnl_route_nh_set_newdst(nexthop, nh_addr);
                        nl_addr_put(nh_addr);
                        break;

                case NEXTHOP_WEIGHT:
                        weight_val = strtoul(tok_val, &scan_end, 0);
                        if (scan_end == tok_val) {
                                CNL_LOG_ERROR("Invalid weight %s, not numeric\n", tok_val);
                                return EINVAL;
                        }
                        rtnl_route_nh_set_weight(nexthop, weight_val);
                        break;
                }
        }

        rtnl_route_add_nexthop(rt_route, nexthop);
        return status;
}

/*
 * Convert addr_str to a netlink address object using the route's address
 * family, then set it as the preferred source address via
 * rtnl_route_set_pref_src.
 */
int libnet_route_parse_pref_src(struct rtnl_route *rt_route, char *args)
{
        struct nl_addr *addr;
        int err = 0;

        err = libnet_addr_parse(args, rtnl_route_get_family(rt_route), &addr);
        if (err != 0) {
                return err;
        }

        err = rtnl_route_set_pref_src(rt_route, addr);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to set preferred source address '%s': %s (err=%d)\n",
                        args, nl_geterror(err), err);
                goto FREE_ADDR;
        }

FREE_ADDR:
        nl_addr_put(addr);
        return err;
}

/*
 * Convert input_str to an unsigned integer with strtoul, then set it as the
 * route priority (metric) via rtnl_route_set_priority.
 */
int libnet_route_parse_prio(struct rtnl_route *route, char *input_str)
{
        unsigned long numeric_val;
        char *scan_end;

        numeric_val = strtoul(input_str, &scan_end, 0);
        if (scan_end == input_str) {
                CNL_LOG_ERROR("Priority must be a valid decimal or hex integer\n");
                return -1;
        }
        rtnl_route_set_priority(route, numeric_val);
        return 0;
}

/*
 * Try to parse input_str first as a decimal/hex integer with strtoul; if that
 * fails, resolve it by name via rtnl_route_str2proto.  Then set the routing
 * protocol on the route via rtnl_route_set_protocol.
 */
int libnet_route_parse_protocol(struct rtnl_route *route, char *input_str)
{
        unsigned long numeric_val;
        char *scan_end;
        int protocol_id;

        numeric_val = strtoul(input_str, &scan_end, 0);
        if (scan_end == input_str) {
                if ((protocol_id = rtnl_route_str2proto(input_str)) < 0) {
                        CNL_LOG_ERROR("Routing protocol \"%s\" is not known to the kernel\n",
                                input_str);
                        return -1;
                }
        }
        else {
                protocol_id = numeric_val;
        }

        rtnl_route_set_protocol(route, protocol_id);
        return 0;
}

/*
 * Resolve input_str to a kernel routing scope constant via rtnl_str2scope,
 * then apply it to the route via rtnl_route_set_scope.
 */
int libnet_route_parse_scope(struct rtnl_route *route, char *input_str)
{
        int result_code;

        if ((result_code = rtnl_str2scope(input_str)) < 0) {
                CNL_LOG_ERROR("Routing scope identifier \"%s\" could not be resolved: %s (err=%d)\n",
                        input_str, nl_geterror(result_code), result_code);
                return -1;
        }
        rtnl_route_set_scope(route, result_code);
        return 0;
}

/*
 * Convert addr_str to a netlink address object using the route's address
 * family, then set it as the route source via rtnl_route_set_src.
 */
int libnet_route_parse_src(struct rtnl_route *rt_route, char *args)
{
        struct nl_addr *addr;
        int err = 0;

        err = libnet_addr_parse(args, rtnl_route_get_family(rt_route), &addr);
        if (err != 0) {
                return err;
        }

        err = rtnl_route_set_src(rt_route, addr);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to set source address '%s': %s (err=%d)\n",
                        args, nl_geterror(err), err);
                goto FREE_ADDR;
        }

FREE_ADDR:
        nl_addr_put(addr);
        return err;
}

/*
 * Try to parse input_str first as a decimal/hex integer with strtoul; if that
 * fails, resolve it by name via rtnl_route_str2table.  Then set the routing
 * table on the route via rtnl_route_set_table.
 */
int libnet_route_parse_table(struct rtnl_route *rt_route, char *input_str)
{
        unsigned long numeric_val;
        char *scan_end;
        int table_id;
        int err = 0;

        numeric_val = strtoul(input_str, &scan_end, 0);
        if (scan_end == input_str) {
                table_id = rtnl_route_str2table(input_str);
                if (table_id < 0) {
                        CNL_LOG_ERROR("Unknown table name %s\n", input_str);
                        return EINVAL;
                }
        }
        else {
                table_id = numeric_val;
        }

        rtnl_route_set_table(rt_route, table_id);
        return err;
}

/*
 * Resolve input_str to a kernel route type constant via nl_str2rtntype,
 * then apply it to the route via rtnl_route_set_type.
 */
int libnet_route_parse_type(struct rtnl_route *route, char *input_str)
{
        int result_code;

        if ((result_code = nl_str2rtntype(input_str)) < 0) {
                CNL_LOG_ERROR("Route type \"%s\" is not a recognised kernel type: %s (err=%d)\n",
                        input_str, nl_geterror(result_code), result_code);
        }

        if ((result_code = rtnl_route_set_type(route, result_code)) < 0) {
                CNL_LOG_ERROR("Setting the route type failed: %s (err=%d)\n",
                        nl_geterror(result_code), result_code);
        }
        return result_code;
}

/************** Rule helpers ******************/

struct rtnl_rule *libnet_rule_alloc(void)
{
        struct rtnl_rule *rt_rule;

        rt_rule = rtnl_rule_alloc();
        if (rt_rule == NULL) {
                CNL_LOG_ERROR("Failed to allocate rule object\n");
                return NULL;
        }

        return rt_rule;
}

struct nl_cache *libnet_rule_alloc_cache(struct nl_sock *socket)
{
        struct nl_cache *cache;
        int err = 0;

        err = rtnl_rule_alloc_cache(socket, AF_UNSPEC, &cache);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to allocate routing rule cache: %s (err=%d)\n",
                        nl_geterror(err), err);
                return NULL;
        }

        return cache;
}

/************** Neighbour helpers ******************/

struct rtnl_neigh *libnet_neigh_alloc(void)
{
        struct rtnl_neigh *rt_neigh;

        rt_neigh = rtnl_neigh_alloc();
        if (rt_neigh == NULL)
                CNL_LOG_ERROR("Failed to allocate neighbour object\n");
        return rt_neigh;
}

int libnet_neigh_parse_dst(struct rtnl_neigh *rt_neigh, char *args)
{
        int err = 0;
        struct nl_addr *nl_a;

        err = libnet_addr_parse(args, rtnl_neigh_get_family(rt_neigh), &nl_a);
        if (err != 0)
                return err;
        err = rtnl_neigh_set_dst(rt_neigh, nl_a);
        if (err < 0) {
                CNL_LOG_ERROR("Failed to set neighbour destination address '%s': %s (err=%d)\n",
                        args, nl_geterror(err), err);
                goto FREE_ADDR;
        }
FREE_ADDR:
        nl_addr_put(nl_a);
        return err;
}

int libnet_neigh_parse_dev(struct rtnl_neigh *rt_neigh,
                           struct nl_cache *link_cache, char *args)
{
        int err = ENOENT;
        int ival;

        ival = rtnl_link_name2i(link_cache, args);
        if (ival == 0) {
                CNL_LOG_ERROR("Neighbour device '%s' does not exist\n", args);
                return err;
        }
        rtnl_neigh_set_ifindex(rt_neigh, ival);
        err = 0;
        return err;
}
