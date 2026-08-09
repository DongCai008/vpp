/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/buffer_fault_injector.h>
#include <vlib/vlib.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip_types.h>

#include <wireguard/wireguard.h>
#include <wireguard/wireguard_if.h>
#include <wireguard/wireguard_key.h>
#include <wireguard/wireguard_peer.h>

#define WG_OUTPUT_TEST(_cond, _comment)                                                            \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	{                                                                                          \
	  fformat (stderr, "FAIL:%d: %s\\n", __LINE__, _comment);                                  \
	  goto done;                                                                               \
	}                                                                                          \
    }                                                                                              \
  while (0)

/* Mirrors the private wireguard output error ordering. */
enum
{
  WG_OUTPUT_TEST_ERROR_NO_BUFFERS = 3,
};

static int
wg_output_shared_view_dispatch (vlib_main_t *vm, u32 node_index, u32 buffer_index,
				u32 *forwarded_index)
{
  vlib_node_t *node = vlib_get_node (vm, node_index);
  vlib_node_runtime_t *runtime;
  vlib_pending_frame_t *pending;
  vlib_frame_t *frame;
  u32 pending_len;
  u32 i;
  int ret = -1;

  if (node == 0)
    return -1;

  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  if (frame == 0)
    return -1;

  pending_len = vec_len (vm->node_main.pending_frames);
  ((u32 *) vlib_frame_vector_args (frame))[0] = buffer_index;
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
	  vlib_next_frame_t *next_frame =
	    vec_elt_at_index (vm->node_main.next_frames, pending->next_frame_index);

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
wg_output_shared_view_select_feature (vlib_main_t *vm, u32 sw_if_index, vlib_buffer_t *buffer,
				      u32 *node_index)
{
  vlib_node_t *ip4_output;
  vlib_node_t *next;
  u32 next_index = 0;
  u8 arc_index;

  arc_index = vnet_get_feature_arc_index ("ip4-output");
  if (arc_index == (u8) ~0)
    return -1;
  ip4_output = vlib_get_node_by_name (vm, (u8 *) "ip4-output");
  if (ip4_output == 0)
    return -1;

  vnet_feature_arc_start (arc_index, sw_if_index, &next_index, buffer);
  next = vlib_get_next_node (vm, ip4_output->index, next_index);
  if (next == 0 || next->index != wg4_output_tun_node.index)
    return -1;

  *node_index = next->index;
  return 0;
}

static int
wg_output_shared_view_setup (vlib_main_t *vm, u32 *sw_if_index, index_t *peer_index,
			     adj_index_t *adj_index)
{
  fib_prefix_t allowed = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 24,
    .fp_addr.ip4.as_u32 = clib_host_to_net_u32 (0x0a000000),
  };
  ip46_address_t endpoint = {
    .ip4.as_u32 = clib_host_to_net_u32 (0xc6336401),
  };
  ip46_address_t next_hop = {
    .ip4.as_u32 = clib_host_to_net_u32 (0x0a000002),
  };
  ip4_address_t src = {
    .as_u32 = clib_host_to_net_u32 (0xc0000201),
  };
  ip_address_t source;
  u8 private_key[NOISE_PUBLIC_KEY_LEN];
  u8 public_key[NOISE_PUBLIC_KEY_LEN];

  *sw_if_index = ~0;
  *peer_index = INDEX_INVALID;
  *adj_index = ADJ_INDEX_INVALID;
  ip_address_set (&source, &src, AF_IP4);
  if (!curve25519_gen_secret (private_key) || !curve25519_gen_secret (public_key))
    return -1;
  if (wg_if_create (~0, private_key, 51820, &source, sw_if_index))
    return -1;

  *adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP4, VNET_LINK_IP4, &next_hop, *sw_if_index);
  if (*adj_index == ADJ_INDEX_INVALID)
    return -1;

  if (wg_peer_add (*sw_if_index, 0, false, public_key, 0, &endpoint, &allowed, 51821, 0,
		   peer_index))
    return -1;
  if (vec_len (wg_peer_get (*peer_index)->adj_indices) != 1 ||
      wg_peer_get (*peer_index)->adj_indices[0] != *adj_index ||
      wg_peer_get_by_adj_index (*adj_index) != *peer_index)
    return -1;

  return 0;
}

static int
wg_output_shared_view_test (vlib_main_t *vm, u8 fault)
{
  vlib_buffer_t *root;
  vlib_buffer_t *forwarded;
  vlib_node_runtime_t *runtime;
  u32 buffers[2];
  u32 forwarded_index = ~0;
  u32 node_index = ~0;
  u32 sw_if_index = ~0;
  u32 n_alloc = 0;
  index_t peer_index = INDEX_INVALID;
  adj_index_t adj_index = ADJ_INDEX_INVALID;
  u8 root_byte;
  int ret = 0;

  if (fault && vlib_buffer_alloc_fault_injector_set (vm, 0))
    return -1;
  WG_OUTPUT_TEST (wg_output_shared_view_setup (vm, &sw_if_index, &peer_index, &adj_index) == 0,
		  "create WireGuard interface, peer, and neighbor adjacency");

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  WG_OUTPUT_TEST (n_alloc == ARRAY_LEN (buffers), "allocate WireGuard shared-view buffers");
  root = vlib_get_buffer (vm, buffers[0]);
  root->current_length = 1;
  *(u8 *) vlib_buffer_get_current (root) = 0xa5;
  root_byte = *(u8 *) vlib_buffer_get_current (root);

  WG_OUTPUT_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
		  "attach WireGuard output shared-view descriptor");
  vnet_buffer (vlib_get_buffer (vm, buffers[1]))->sw_if_index[VLIB_TX] = sw_if_index;
  vnet_buffer (vlib_get_buffer (vm, buffers[1]))->ip.adj_index[VLIB_TX] = adj_index;
  WG_OUTPUT_TEST (wg_output_shared_view_select_feature (
		    vm, sw_if_index, vlib_get_buffer (vm, buffers[1]), &node_index) == 0,
		  "select WireGuard output through the real ip4-output feature arc");
  if (fault)
    WG_OUTPUT_TEST (vlib_buffer_alloc_fault_injector_set (vm, 1) == 0,
		    "arm WireGuard output COW allocation failure");

  WG_OUTPUT_TEST (wg_output_shared_view_dispatch (vm, node_index, buffers[1], &forwarded_index) ==
		    0,
		  "dispatch shared view through selected WireGuard output node");
  vlib_buffer_alloc_fault_injector_set (vm, 0);
  forwarded = vlib_get_buffer (vm, forwarded_index);
  runtime = vlib_node_get_runtime (vm, node_index);

  if (fault)
    {
      WG_OUTPUT_TEST (forwarded_index == buffers[1],
		      "retain descriptor after WireGuard output COW allocation failure");
      WG_OUTPUT_TEST (forwarded->error == runtime->errors[WG_OUTPUT_TEST_ERROR_NO_BUFFERS],
		      "send WireGuard output COW failure to no-buffers drop");
      WG_OUTPUT_TEST (*(u8 *) vlib_buffer_get_current (root) == root_byte,
		      "leave WireGuard output canonical root unchanged after COW failure");
    }
  else
    {
      WG_OUTPUT_TEST (forwarded_index != buffers[1],
		      "replace descriptor in WireGuard output frame slot");
      WG_OUTPUT_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
		      "forward ordinary WireGuard output replacement");
      *(u8 *) vlib_buffer_get_current (forwarded) ^= 0xff;
      WG_OUTPUT_TEST (*(u8 *) vlib_buffer_get_current (root) == root_byte,
		      "WireGuard output replacement leaves canonical root unchanged");
    }
  ret = 1;

done:
  vlib_buffer_alloc_fault_injector_set (vm, 0);
  if (forwarded_index != ~0)
    vlib_buffer_free_one (vm, forwarded_index);
  else if (n_alloc == ARRAY_LEN (buffers))
    vlib_buffer_free_one (vm, buffers[1]);
  if (n_alloc == ARRAY_LEN (buffers))
    vlib_buffer_free_one (vm, buffers[0]);
  if (peer_index != INDEX_INVALID)
    wg_peer_remove (peer_index);
  if (adj_index != ADJ_INDEX_INVALID)
    adj_unlock (adj_index);
  if (sw_if_index != ~0)
    wg_if_delete (sw_if_index);

  return ret;
}

static clib_error_t *
test_wg_output_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u8 fault = 0;

  if (unformat (input, "fault"))
    fault = 1;
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input");
  if (!wg_output_shared_view_test (vm, fault))
    return clib_error_return (0, "WireGuard output shared-view test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_wg_output_shared_view_command, static) = {
  .path = "test wireguard-output-shared-view",
  .short_help = "test wireguard-output-shared-view [fault]",
  .function = test_wg_output_shared_view_fn,
};
