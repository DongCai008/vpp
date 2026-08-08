/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#pragma once

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/udp/udp_local.h>
#include <vlib/vlib.h>

typedef struct
{
  ip4_address_t src;
  ip4_address_t dst;
  u16 src_port;
  u16 dst_port;
} udp_echo_trace_t;

#define foreach_udp_echo_error                                                                     \
  _ (PROCESSED, "UDP echo packets processed")                                                      \
  _ (CLONE_FAIL, "UDP echo clone failures")                                                        \
  _ (COW_FAIL, "UDP echo shared-buffer copy failures")

typedef enum
{
#define _(sym, str) UDP_ECHO_ERROR_##sym,
  foreach_udp_echo_error
#undef _
    UDP_ECHO_N_ERROR,
} udp_echo_error_t;

typedef enum
{
  UDP_ECHO_NEXT_IP4_LOOKUP,
  UDP_ECHO_NEXT_DROP,
  UDP_ECHO_N_NEXT,
} udp_echo_next_t;

format_function_t format_udp_echo_trace;

typedef struct
{
  /* Registered port */
  u16 port;
  u8 enabled;
  u8 n_clones;
  u8 linearize;
  u8 regen_udp_cksum;
  u8 regen_ip_cksum;
} udp_echo_main_t;

extern udp_echo_main_t udp_echo_main;

extern vlib_node_registration_t udp_echo_node;
