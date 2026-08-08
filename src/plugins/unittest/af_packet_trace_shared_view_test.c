/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/buffer_shinfo.h>
#include <af_packet/af_packet.h>

#define AF_PACKET_TRACE_TEST(_cond, _comment)                                                      \
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
af_packet_trace_shared_view_test (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_buffer_t *root, *tail;
  u32 buffers[2];
  u32 descriptor_index = ~0;
  u8 snapshot[VLIB_BUFFER_PRE_DATA_SIZE];
  u8 zero_suffix[VLIB_BUFFER_PRE_DATA_SIZE] = {};
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

  AF_PACKET_TRACE_TEST (vnet_buffer_shinfo_clone (vm, buffers[0], &descriptor_index) == 0,
			"headerless descriptor clone failed");
  clib_memset_u8 (snapshot, 0xa5, sizeof (snapshot));
  af_packet_trace_snapshot_pre_data (vm, vlib_get_buffer (vm, descriptor_index), snapshot);
  AF_PACKET_TRACE_TEST (
    clib_memcmp (snapshot, root->data + root->current_data, root->current_length) == 0 &&
      clib_memcmp (snapshot + root->current_length, vlib_buffer_get_current (tail),
		   tail->current_length) == 0 &&
      clib_memcmp (snapshot + root->current_length + tail->current_length, zero_suffix,
		   sizeof (snapshot) - root->current_length - tail->current_length) == 0,
    "AF_PACKET trace snapshot did not copy the descriptor root/tail view");

done:
  if (descriptor_index != ~0)
    vlib_buffer_free_one (vm, descriptor_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return error;
}

VLIB_CLI_COMMAND (test_af_packet_trace_shared_view_command, static) = {
  .path = "test af-packet-trace-shared-view",
  .short_help = "test af-packet-trace-shared-view",
  .function = af_packet_trace_shared_view_test,
};
