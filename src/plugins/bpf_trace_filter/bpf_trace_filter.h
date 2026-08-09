/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco and/or its affiliates.
 */

#ifndef _BPF_TRACE_FILTER_H_
#define _BPF_TRACE_FILTER_H_
#include <vlib/vlib.h>
#include <pcap.h>

#define BPF_TRACE_FILTER_WORKSPACE_SIZE 65535

typedef struct
{
  u8 workspace[BPF_TRACE_FILTER_WORKSPACE_SIZE];
} bpf_trace_filter_per_thread_data_t;

typedef struct
{
  pcap_t *pcap;	    /* for DLT_EN10MB (Ethernet) */
  pcap_t *pcap_raw; /* for DLT_RAW (raw IP) */
  bpf_trace_filter_per_thread_data_t *per_thread_data;
  u16 msg_id_base;
  u8 prog_set;
  u8 prog_raw_set;
  struct bpf_program prog;     /* compiled for Ethernet */
  struct bpf_program prog_raw; /* compiled for raw IP */
} bpf_trace_filter_main_t;

extern bpf_trace_filter_main_t bpf_trace_filter_main;
clib_error_t *bpf_trace_filter_set_unset (const char *bpf_expr, u8 is_del,
					  u8 optimize);
u8 *format_bpf_trace_filter (u8 *s, va_list *a);
int bpf_is_packet_traced (vlib_buffer_t *b, u32 classify_table_index, int func);
#endif /* _BPF_TRACE_FILTER_H_ */
