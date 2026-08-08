/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/buffer_shinfo.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/interface_output.h>

#define DROP_CAPTURE_TEST(_cond, _comment)                                                         \
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
drop_capture_shared_view_test (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_buffer_t *root, *tail, *descriptor;
  ethernet_header_t *ethernet;
  ip4_header_t *ip4;
  u8 snapshot[sizeof (*ethernet) + sizeof (*ip4)];
  u8 expected[sizeof (snapshot)];
  u32 buffers[2];
  u32 descriptor_index = ~0;
  i16 root_current_data;
  u16 root_current_length;
  clib_error_t *error = 0;
  uword copied;

  if (vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers)) != ARRAY_LEN (buffers))
    return clib_error_return (0, "buffer allocation failed");

  root = vlib_get_buffer (vm, buffers[0]);
  tail = vlib_get_buffer (vm, buffers[1]);
  root->current_data = 14;
  root->current_length = 4;
  root->next_buffer = buffers[1];
  root->total_length_not_including_first_buffer = sizeof (snapshot) - 8;
  root->flags |= VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_L2_HDR_OFFSET_VALID;
  vnet_buffer (root)->l2_hdr_offset = 10;
  tail->current_data = 3;
  tail->current_length = root->total_length_not_including_first_buffer;

  ethernet = (void *) expected;
  ethernet->type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4);
  clib_memset (ethernet->src_address, 0x11, sizeof (ethernet->src_address));
  clib_memset (ethernet->dst_address, 0x22, sizeof (ethernet->dst_address));
  ip4 = (void *) (ethernet + 1);
  clib_memset (ip4, 0, sizeof (*ip4));
  ip4->ip_version_and_header_length = 0x45;
  ip4->length = clib_host_to_net_u16 (sizeof (*ip4));
  ip4->src_address.as_u32 = clib_host_to_net_u32 (0x0a000001);
  ip4->dst_address.as_u32 = clib_host_to_net_u32 (0x0a000002);
  clib_memcpy_fast (root->data + vnet_buffer (root)->l2_hdr_offset, expected, 8);
  clib_memcpy_fast (vlib_buffer_get_current (tail), expected + 8, tail->current_length);

  DROP_CAPTURE_TEST (vnet_buffer_shinfo_clone (vm, buffers[0], &descriptor_index) == 0,
		     "headerless descriptor clone failed");
  descriptor = vlib_get_buffer (vm, descriptor_index);
  root_current_data = root->current_data;
  root_current_length = root->current_length;
  clib_memset (snapshot, 0xa5, sizeof (snapshot));
  copied = vnet_buffer_l2_snapshot (vm, descriptor, snapshot, sizeof (snapshot));
  DROP_CAPTURE_TEST (copied == sizeof (snapshot),
		     "drop catchup snapshot did not reach the root/tail boundary");
  DROP_CAPTURE_TEST (clib_memcmp (root->data + vnet_buffer (root)->l2_hdr_offset, expected, 8) == 0,
		     "drop catchup test did not initialize the root prefix");
  DROP_CAPTURE_TEST (clib_memcmp (snapshot, expected, 8) == 0,
		     "drop catchup snapshot did not preserve the root prefix");
  DROP_CAPTURE_TEST (clib_memcmp (snapshot + 8, expected + 8, sizeof (snapshot) - 8) == 0,
		     "drop catchup snapshot did not preserve the tail suffix");
  DROP_CAPTURE_TEST (root->current_data == root_current_data &&
		       root->current_length == root_current_length &&
		       descriptor->current_data == 0 && descriptor->current_length == 0,
		     "drop catchup snapshot changed shared packet state");

  root->current_data = 10;
  root->current_length = 8;
  root->total_length_not_including_first_buffer = sizeof (snapshot) - 4;
  vnet_buffer (root)->l2_hdr_offset = 14;
  tail->current_length = root->total_length_not_including_first_buffer;
  clib_memcpy_fast (root->data + vnet_buffer (root)->l2_hdr_offset, expected, 4);
  clib_memcpy_fast (vlib_buffer_get_current (tail), expected + 4, tail->current_length);
  root_current_data = root->current_data;
  root_current_length = root->current_length;
  clib_memset (snapshot, 0xa5, sizeof (snapshot));
  copied = vnet_buffer_l2_snapshot (vm, descriptor, snapshot, sizeof (snapshot));
  DROP_CAPTURE_TEST (copied == sizeof (snapshot),
		     "drop catchup forward snapshot did not reach the root/tail boundary");
  DROP_CAPTURE_TEST (clib_memcmp (snapshot, expected, sizeof (snapshot)) == 0,
		     "drop catchup forward snapshot did not preserve the L2-started view");
  DROP_CAPTURE_TEST (root->current_data == root_current_data &&
		       root->current_length == root_current_length &&
		       descriptor->current_data == 0 && descriptor->current_length == 0,
		     "drop catchup forward snapshot changed shared packet state");

done:
  if (descriptor_index != ~0)
    vlib_buffer_free_one (vm, descriptor_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return error;
}

VLIB_CLI_COMMAND (test_drop_capture_shared_view_command, static) = {
  .path = "test drop-capture-shared-view",
  .short_help = "test drop-capture-shared-view",
  .function = drop_capture_shared_view_test,
};
