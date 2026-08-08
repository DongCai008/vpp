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
	  fformat (stderr, "FAIL:%d: %s\n", __LINE__, _comment);                                   \
	  goto done;                                                                               \
	}                                                                                          \
    }                                                                                              \
  while (0)

static int
arp_shared_view_dispatch (vlib_main_t *vm, const char *node_name, u32 descriptor_index,
			  u32 *forwarded_index)
{
  vlib_node_t *node;
  vlib_node_runtime_t *runtime;
  vlib_pending_frame_t *pending;
  vlib_frame_t *frame;
  u32 pending_len;
  u32 i;
  int ret = -1;

  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  if (node == 0)
    return -1;

  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  if (frame == 0)
    return -1;

  pending_len = vec_len (vm->node_main.pending_frames);
  ((u32 *) vlib_frame_vector_args (frame))[0] = descriptor_index;
  frame->n_vectors = 1;
  runtime->function (vm, runtime, frame);

  if (vec_len (vm->node_main.pending_frames) != pending_len + 1)
    goto done;

  pending = vec_elt_at_index (vm->node_main.pending_frames, pending_len);
  if (pending->frame->n_vectors != 1)
    goto done;

  *forwarded_index = ((u32 *) vlib_frame_vector_args (pending->frame))[0];
  ret = 0;

done:
  for (i = pending_len; i < vec_len (vm->node_main.pending_frames); i++)
    {
      pending = vec_elt_at_index (vm->node_main.pending_frames, i);
      if (pending->next_frame_index != VLIB_PENDING_FRAME_NO_NEXT_FRAME)
	{
	  vlib_next_frame_t *next_frame;

	  next_frame = vec_elt_at_index (vm->node_main.next_frames, pending->next_frame_index);
	  next_frame->flags &= ~VLIB_FRAME_PENDING;
	}
      pending->frame->frame_flags &= ~VLIB_FRAME_PENDING;
      pending->frame->n_vectors = 0;
    }
  vec_set_len (vm->node_main.pending_frames, pending_len);
  vlib_frame_free (vm, frame);

  return ret;
}

static int
arp_shared_view_node_test (vlib_main_t *vm, const char *node_name, u32 expected_error)
{
  ethernet_arp_header_t *arp;
  vlib_buffer_t *root;
  vlib_node_t *node;
  u32 buffers[2];
  u32 forwarded_index = ~0;
  u32 n_alloc;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }

  root = vlib_get_buffer (vm, buffers[0]);
  root->current_length = sizeof (*arp);
  vnet_buffer (root)->sw_if_index[VLIB_RX] = ~0;
  arp = vlib_buffer_get_current (root);
  clib_memset (arp, 0, sizeof (*arp));
  arp->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request);

  ARP_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	    "attach ARP shared-view descriptor");
  ARP_TEST (arp_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index) == 0,
	    "dispatch ARP node with headerless descriptor");
  ARP_TEST (forwarded_index != buffers[1] &&
	      !vlib_buffer_shared_view_is_shared (vlib_get_buffer (vm, forwarded_index)),
	    "replace descriptor in forwarded frame slot");
  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  if (vlib_get_buffer (vm, forwarded_index)->error !=
      vlib_node_get_runtime (vm, node->index)->errors[expected_error])
    {
      fformat (stderr, "FAIL:%d: direct-path error got %u expected %u\\n", __LINE__,
	       vlib_get_buffer (vm, forwarded_index)->error,
	       vlib_node_get_runtime (vm, node->index)->errors[expected_error]);
      goto done;
    }

  arp = vlib_buffer_get_current (vlib_get_buffer (vm, forwarded_index));
  ARP_TEST (arp->opcode == clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request),
	    "read canonical ARP request through replacement");
  arp->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply);
  ARP_TEST (((ethernet_arp_header_t *) vlib_buffer_get_current (root))->opcode ==
	      clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request),
	    "reply mutation leaves canonical root unchanged");

  ret = 1;
done:
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);

  return ret;
}

static int
arp_shared_view_test (vlib_main_t *vm)
{
  return arp_shared_view_node_test (vm, "arp-input", ARP_ERROR_L3_DST_ADDRESS_UNSET) &&
	 arp_shared_view_node_test (vm, "arp-reply", ARP_ERROR_INTERFACE_NO_TABLE) &&
	 arp_shared_view_node_test (vm, "arp-proxy", ARP_ERROR_INTERFACE_NO_TABLE);
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
