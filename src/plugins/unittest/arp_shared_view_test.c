/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/arp/arp_packet.h>

#define ARP_TEST(_cond, _comment)                                                                  \
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
arp_shared_view_test (vlib_main_t *vm)
{
  ethernet_arp_header_t *arp;
  vlib_buffer_t *buffer;
  vlib_buffer_t *root;
  u32 buffers[2];
  u32 frame_slot;
  int attached = 0;
  int ret = 0;

  if (vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers)) != ARRAY_LEN (buffers))
    return 0;

  root = vlib_get_buffer (vm, buffers[0]);
  root->current_length = sizeof (*arp);
  arp = vlib_buffer_get_current (root);
  clib_memset (arp, 0, sizeof (*arp));
  arp->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request);

  ARP_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	    "attach ARP shared-view descriptor");
  attached = 1;
  frame_slot = buffers[1];
  buffer = vlib_get_buffer (vm, frame_slot);

  ARP_TEST (arp_buffer_make_writable (vm, &frame_slot, &buffer) == 0,
	    "make ARP frame slot writable");
  ARP_TEST (frame_slot != buffers[1] && !vlib_buffer_shared_view_is_shared (buffer),
	    "replace descriptor frame slot with ordinary buffer");

  arp = vlib_buffer_get_current (buffer);
  ARP_TEST (arp->opcode == clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request),
	    "read ARP request through replacement");
  arp->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply);
  ARP_TEST (((ethernet_arp_header_t *) vlib_buffer_get_current (root))->opcode ==
	      clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request),
	    "ARP mutation leaves canonical root unchanged");

  ret = 1;
done:
  if (attached)
    {
      vlib_buffer_free_one (vm, frame_slot);
      vlib_buffer_free_one (vm, buffers[0]);
    }
  else
    vlib_buffer_free (vm, buffers, ARRAY_LEN (buffers));

  return ret;
}

static clib_error_t *
test_arp_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!arp_shared_view_test (vm))
    return clib_error_return (0, "ARP shared-view test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_arp_shared_view_command, static) = {
  .path = "test arp-shared-view",
  .short_help = "test arp-shared-view",
  .function = test_arp_shared_view_fn,
};
