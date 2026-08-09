/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/buffer.h>

#include <bpf_trace_filter/bpf_trace_filter.h>

#define BPF_TRACE_FILTER_TEST(_cond, _comment)                                                     \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	{                                                                                          \
	  fformat (stderr, "FAIL:%d: %s\\n", __LINE__, _comment);                                  \
	  goto done;                                                                               \
	}                                                                                          \
    }                                                                                              \
  while (0)

static int
bpf_trace_filter_test_alloc (vlib_main_t *vm, u32 *buffers, u32 n_buffers)
{
  u32 n_alloc;

  n_alloc = vlib_buffer_alloc (vm, buffers, n_buffers);
  if (n_alloc != n_buffers)
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }
  return 1;
}

static int
bpf_trace_filter_test (vlib_main_t *vm)
{
  bpf_trace_filter_main_t *btm = &bpf_trace_filter_main;
  bpf_trace_filter_per_thread_data_t *ptd;
  vlib_buffer_t *descriptor;
  vlib_buffer_t *root;
  vlib_buffer_t *tail;
  u32 buffers[3];
  u32 n_buffers = 0;
  int ret = 0;

  BPF_TRACE_FILTER_TEST (bpf_trace_filter_set_unset ("ether[14] = 0x42", 0, 1) == 0,
			 "compile Ethernet chain-view filter");
  BPF_TRACE_FILTER_TEST (bpf_trace_filter_test_alloc (vm, buffers, 3),
			 "allocate Ethernet root, tail, and descriptor");
  n_buffers = 3;
  root = vlib_get_buffer (vm, buffers[0]);
  tail = vlib_get_buffer (vm, buffers[1]);
  root->current_length = 14;
  tail->current_length = 1;
  root->next_buffer = buffers[1];
  root->flags |= VLIB_BUFFER_NEXT_PRESENT;
  clib_memset (vlib_buffer_get_current (root), 0, root->current_length);
  *(u8 *) vlib_buffer_get_current (tail) = 0x42;
  BPF_TRACE_FILTER_TEST (vlib_buffer_shared_view_attach (vm, buffers[2], buffers[0]) == 0,
			 "attach Ethernet descriptor");
  BPF_TRACE_FILTER_TEST (bpf_is_packet_traced (vlib_get_buffer (vm, buffers[2]), ~0, 0),
			 "filter reads Ethernet payload from descriptor tail");
  vlib_buffer_free_one (vm, buffers[2]);
  vlib_buffer_free_one (vm, buffers[0]);
  n_buffers = 0;

  BPF_TRACE_FILTER_TEST (bpf_trace_filter_set_unset ("ip", 0, 1) == 0,
			 "compile raw-IP chain-view filter");
  BPF_TRACE_FILTER_TEST (btm->prog_raw_set, "raw-IP filter is available");
  BPF_TRACE_FILTER_TEST (bpf_trace_filter_test_alloc (vm, buffers, 2),
			 "allocate raw-IP root and descriptor");
  n_buffers = 2;
  root = vlib_get_buffer (vm, buffers[0]);
  root->current_length = 1;
  *(u8 *) vlib_buffer_get_current (root) = 0x45;
  BPF_TRACE_FILTER_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			 "attach raw-IP descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
  vnet_buffer (descriptor)->l3_hdr_offset = descriptor->current_data;
  BPF_TRACE_FILTER_TEST (bpf_is_packet_traced (descriptor, ~0, 0),
			 "raw-IP descriptor selects raw filter");
  vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  n_buffers = 0;

  BPF_TRACE_FILTER_TEST (bpf_trace_filter_set_unset ("ether[20] = 0xa5", 0, 1) == 0,
			 "compile short-packet bounds filter");
  BPF_TRACE_FILTER_TEST (bpf_trace_filter_test_alloc (vm, buffers, 2),
			 "allocate short Ethernet root and descriptor");
  n_buffers = 2;
  root = vlib_get_buffer (vm, buffers[0]);
  root->current_length = 15;
  clib_memset (vlib_buffer_get_current (root), 0, root->current_length);
  BPF_TRACE_FILTER_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			 "attach short Ethernet descriptor");
  ptd = vec_elt_at_index (btm->per_thread_data, vlib_get_thread_index ());
  clib_memset (ptd->workspace, 0xa5, sizeof (ptd->workspace));
  BPF_TRACE_FILTER_TEST (!bpf_is_packet_traced (vlib_get_buffer (vm, buffers[1]), ~0, 0),
			 "filter does not read sentinel bytes past logical packet");
  ret = 1;

done:
  bpf_trace_filter_set_unset (0, 1, 0);
  if (n_buffers == 3)
    {
      vlib_buffer_free_one (vm, buffers[2]);
      vlib_buffer_free_one (vm, buffers[0]);
    }
  else if (n_buffers == 2)
    {
      vlib_buffer_free_one (vm, buffers[1]);
      vlib_buffer_free_one (vm, buffers[0]);
    }
  return ret;
}

static clib_error_t *
test_bpf_trace_filter_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input");
  if (!bpf_trace_filter_test (vm))
    return clib_error_return (0, "BPF trace filter test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_bpf_trace_filter_command, static) = {
  .path = "test bpf-trace-filter",
  .short_help = "test bpf-trace-filter",
  .function = test_bpf_trace_filter_fn,
};
