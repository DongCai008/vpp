/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/buffer.h>
#include <bpf_trace_filter/bpf_trace_filter.h>

clib_error_t *
bpf_trace_filter_init (vlib_main_t *vm)
{
  bpf_trace_filter_main_t *btm = &bpf_trace_filter_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  btm->pcap = pcap_open_dead (DLT_EN10MB, 65535);
  btm->pcap_raw = pcap_open_dead (DLT_RAW, 65535);
  vec_validate_aligned (btm->per_thread_data, tm->n_vlib_mains - 1, CLIB_CACHE_LINE_BYTES);

  return 0;
}

int vnet_is_packet_traced (vlib_buffer_t *b, u32 classify_table_index,
			   int func);

u8 *
format_bpf_trace_filter (u8 *s, va_list *a)
{
  bpf_trace_filter_main_t *btm = va_arg (*a, bpf_trace_filter_main_t *);
  struct bpf_insn *insn;

  if (!btm->prog_set)
    return format (s, "bpf trace filter is not set");

  insn = btm->prog.bf_insns;
  for (int i = 0; i < btm->prog.bf_len; insn++, i++)
    s = format (s, "%s\n", bpf_image (insn, i));

  return s;
}

clib_error_t *
bpf_trace_filter_set_unset (const char *bpf_expr, u8 is_del, u8 optimize)
{
  bpf_trace_filter_main_t *btm = &bpf_trace_filter_main;
  if (is_del)
    {
      if (btm->prog_set)
	{
	  btm->prog_set = 0;
	  pcap_freecode (&btm->prog);
	}
      if (btm->prog_raw_set)
	{
	  btm->prog_raw_set = 0;
	  pcap_freecode (&btm->prog_raw);
	}
    }
  else if (bpf_expr)
    {
      if (btm->prog_set)
	pcap_freecode (&btm->prog);
      btm->prog_set = 0;
      if (pcap_compile (btm->pcap, &btm->prog, (char *) bpf_expr, optimize, PCAP_NETMASK_UNKNOWN))
	return clib_error_return (0, "Failed pcap_compile of %s", bpf_expr);
      btm->prog_set = 1;

      /* Also compile for raw IP to support packets without Ethernet header */
      if (btm->prog_raw_set)
	pcap_freecode (&btm->prog_raw);
      btm->prog_raw_set = 0;
      if (pcap_compile (btm->pcap_raw, &btm->prog_raw, (char *) bpf_expr, optimize,
			PCAP_NETMASK_UNKNOWN) == 0)
	btm->prog_raw_set = 1;
    }
  return 0;
};

static_always_inline u8 *
bpf_trace_filter_packet_data (vlib_main_t *vm, vlib_buffer_t *b, struct pcap_pkthdr *phdr)
{
  bpf_trace_filter_main_t *btm = &bpf_trace_filter_main;
  bpf_trace_filter_per_thread_data_t *ptd;
  uword logical_length;
  uword copied;

  ptd = vec_elt_at_index (btm->per_thread_data, vlib_get_thread_index ());
  logical_length = vlib_buffer_chain_view_length (vm, b, 0);
  copied = vlib_buffer_chain_view_copy (vm, b, ptd->workspace, BPF_TRACE_FILTER_WORKSPACE_SIZE, 0);
  phdr->len = logical_length;
  phdr->caplen = copied;

  return ptd->workspace;
}

int
bpf_is_packet_traced (vlib_buffer_t *b, u32 classify_table_index, int func)
{
  bpf_trace_filter_main_t *bfm = &bpf_trace_filter_main;
  struct pcap_pkthdr phdr = { 0 };
  vlib_main_t *vm = vlib_get_main ();
  u8 *packet_data;
  int res;
  int res1;

  if (classify_table_index != ~0 &&
      (res1 = vnet_is_packet_traced (b, classify_table_index, 0)) != 1)
    return res1;

  if (!bfm->prog_set)
    return 1;

  packet_data = bpf_trace_filter_packet_data (vm, b, &phdr);

  /*
   * Determine if packet is at L3 (raw IP without Ethernet header)
   * Use DLT_RAW filter only when L3_HDR_OFFSET_VALID is set AND current_data
   * equals l3_hdr_offset, else, default to Ethernet filter (DLT_EN10MB)
   */
  if (bfm->prog_raw_set && (b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID) &&
      (b->current_data == vnet_buffer (b)->l3_hdr_offset))
    res = pcap_offline_filter (&bfm->prog_raw, &phdr, packet_data);
  else
    res = pcap_offline_filter (&bfm->prog, &phdr, packet_data);
  return res != 0;
}

VLIB_REGISTER_TRACE_FILTER_FUNCTION (bpf_trace_filter_fn, static) = {
  .name = "bpf_trace_filter",
  .description = "bpf based trace filter",
  .priority = 10,
  .function = bpf_is_packet_traced
};

VLIB_INIT_FUNCTION (bpf_trace_filter_init);
bpf_trace_filter_main_t bpf_trace_filter_main;
