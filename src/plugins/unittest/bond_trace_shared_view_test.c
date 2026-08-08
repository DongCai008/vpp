/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/buffer_shinfo.h>
#include <vnet/bonding/node.h>

#define BOND_TRACE_TEST(_cond, _comment)                                                           \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	{                                                                                          \
	  error = clib_error_return (0, _comment);                                                 \
	  goto done;                                                                               \
	}                                                                                          \
    }                                                                                              \
  while (0)

static clib_error_t *
bond_trace_shared_view_test (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_buffer_t *root, *tail;
  u32 buffers[2];
  u32 descriptor_index = ~0;
  bond_packet_trace_t rx_trace;
  bond_packet_trace_t tx_trace;
  u8 zero_header[sizeof (ethernet_header_t)] = {};
  clib_error_t *error = 0;
  u32 i;

  if (vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers)) != ARRAY_LEN (buffers))
    return clib_error_return (0, "buffer allocation failed");

  root = vlib_get_buffer (vm, buffers[0]);
  tail = vlib_get_buffer (vm, buffers[1]);
  root->current_data = 0;
  root->current_length = 8;
  root->next_buffer = buffers[1];
  root->total_length_not_including_first_buffer = 6;
  root->flags |= VLIB_BUFFER_NEXT_PRESENT;
  tail->current_data = 3;
  tail->current_length = 6;

  for (i = 0; i < root->current_length; i++)
    root->data[root->current_data + i] = i;
  for (i = 0; i < tail->current_length; i++)
    tail->data[tail->current_data + i] = root->current_length + i;

  BOND_TRACE_TEST (vnet_buffer_shinfo_clone (vm, buffers[0], &descriptor_index) == 0,
		   "headerless descriptor clone failed");
  clib_memset (&rx_trace, 0xa5, sizeof (rx_trace));
  clib_memset (&tx_trace, 0xa5, sizeof (tx_trace));
  bond_trace_snapshot_ethernet (vm, vlib_get_buffer (vm, descriptor_index), &rx_trace);
  bond_trace_snapshot_ethernet (vm, vlib_get_buffer (vm, descriptor_index), &tx_trace);
  BOND_TRACE_TEST (
    clib_memcmp (&rx_trace.ethernet, root->data + root->current_data, root->current_length) == 0 &&
      clib_memcmp ((u8 *) &rx_trace.ethernet + root->current_length, vlib_buffer_get_current (tail),
		   tail->current_length) == 0 &&
      clib_memcmp (&rx_trace.ethernet, &tx_trace.ethernet, sizeof (rx_trace.ethernet)) == 0,
    "bond RX/TX trace snapshots did not cross the descriptor root/tail boundary");

  tail->current_length = 3;
  clib_memset (&rx_trace, 0xa5, sizeof (rx_trace));
  bond_trace_snapshot_ethernet (vm, vlib_get_buffer (vm, descriptor_index), &rx_trace);
  BOND_TRACE_TEST (
    clib_memcmp (&rx_trace.ethernet, root->data + root->current_data, root->current_length) == 0 &&
      clib_memcmp ((u8 *) &rx_trace.ethernet + root->current_length, vlib_buffer_get_current (tail),
		   tail->current_length) == 0 &&
      clib_memcmp ((u8 *) &rx_trace.ethernet + root->current_length + tail->current_length,
		   zero_header,
		   sizeof (rx_trace.ethernet) - root->current_length - tail->current_length) == 0,
    "short bond trace snapshot did not zero its Ethernet suffix");

done:
  if (descriptor_index != ~0)
    vlib_buffer_free_one (vm, descriptor_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return error;
}

VLIB_CLI_COMMAND (test_bond_trace_shared_view_command, static) = {
  .path = "test bond-trace-shared-view",
  .short_help = "test bond-trace-shared-view",
  .function = bond_trace_shared_view_test,
};
