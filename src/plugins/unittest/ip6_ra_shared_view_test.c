/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vlib/buffer_fault_injector.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/ip6-nd/ip6_ra.h>

#define IP6_RA_SHARED_VIEW_TEST(_cond, _comment)                                                   \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	{                                                                                          \
	  fformat (stderr, "FAIL:%d: %s\\n", __LINE__, _comment);                                  \
	  goto done;                                                                               \
	}                                                                                          \
    }                                                                                              \
  while (0)

static void
ip6_ra_shared_view_discard_pending (vlib_main_t *vm, u32 pending_len)
{
  vlib_pending_frame_t *pending;
  u32 i;

  for (i = pending_len; i < vec_len (vm->node_main.pending_frames); i++)
    {
      pending = vec_elt_at_index (vm->node_main.pending_frames, i);
      vlib_buffer_free (vm, vlib_frame_vector_args (pending->frame), pending->frame->n_vectors);
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
}

static int
ip6_ra_shared_view_dispatch (vlib_main_t *vm, u32 buffer_index, u32 *forwarded_index,
			     u32 *forwarded_runtime_index, u32 *pending_len)
{
  vlib_frame_t *frame;
  vlib_node_runtime_t *runtime;
  vlib_node_t *node;
  vlib_pending_frame_t *pending;
  u32 i;

  node = vlib_get_node_by_name (vm, (u8 *) "icmp6-router-solicitation");
  if (node == 0)
    return -1;
  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  if (frame == 0)
    return -1;

  *pending_len = vec_len (vm->node_main.pending_frames);
  *forwarded_index = ~0;
  *forwarded_runtime_index = ~0;
  ((u32 *) vlib_frame_vector_args (frame))[0] = buffer_index;
  frame->n_vectors = 1;
  runtime->function (vm, runtime, frame);
  vlib_frame_free (vm, frame);

  for (i = *pending_len; i < vec_len (vm->node_main.pending_frames); i++)
    {
      pending = vec_elt_at_index (vm->node_main.pending_frames, i);
      if (pending->frame->n_vectors)
	{
	  *forwarded_index = ((u32 *) vlib_frame_vector_args (pending->frame))[0];
	  *forwarded_runtime_index = pending->node_runtime_index;
	  return pending->frame->n_vectors == 1 ? 0 : -1;
	}
    }
  return -1;
}

static void
ip6_ra_shared_view_init_rs (vlib_buffer_t *buffer, u32 sw_if_index)
{
  icmp6_neighbor_discovery_header_t *neighbor;
  ip6_header_t *ip;

  buffer->current_length = sizeof (*ip) + sizeof (*neighbor);
  ip = vlib_buffer_get_current (buffer);
  clib_memset (ip, 0, buffer->current_length);
  ip->protocol = IP_PROTOCOL_ICMP6;
  ip->payload_length = clib_host_to_net_u16 (sizeof (*neighbor));
  ip6_address_copy (&ip->src_address, ip6_get_link_local_address (sw_if_index));
  neighbor = (void *) (ip + 1);
  neighbor->icmp.type = ICMP6_router_solicitation;
  vnet_buffer (buffer)->sw_if_index[VLIB_RX] = sw_if_index;
}

static int
ip6_ra_shared_view_setup (vlib_main_t *vm, u32 *sw_if_index)
{
  u8 mac_address[6] = { 0x02, 0, 0, 0, 0, 0x6a };

  if (vnet_create_loopback_interface (sw_if_index, mac_address, 0, 0) ||
      ip6_link_enable (*sw_if_index, 0) ||
      ip6_ra_config (vm, *sw_if_index, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    return -1;
  return 0;
}

static int
ip6_ra_shared_view_success_test (vlib_main_t *vm, u32 sw_if_index)
{
  vlib_buffer_t *forwarded;
  vlib_buffer_t *root;
  vlib_node_t *reply_node;
  u32 buffers[2];
  u32 forwarded_index;
  u32 forwarded_runtime_index;
  u32 n_alloc;
  u32 pending_len = 0;
  u8 root_bytes[sizeof (ip6_header_t) + sizeof (icmp6_neighbor_discovery_header_t)];
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }

  root = vlib_get_buffer (vm, buffers[0]);
  ip6_ra_shared_view_init_rs (root, sw_if_index);
  clib_memcpy_fast (root_bytes, vlib_buffer_get_current (root), sizeof (root_bytes));
  IP6_RA_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			   "attach router solicitation shared-view descriptor");
  IP6_RA_SHARED_VIEW_TEST (vlib_get_buffer (vm, buffers[1])->current_length == 0,
			   "use headerless router solicitation descriptor");
  IP6_RA_SHARED_VIEW_TEST (ip6_ra_shared_view_dispatch (vm, buffers[1], &forwarded_index,
							&forwarded_runtime_index,
							&pending_len) == 0,
			   "dispatch headerless router solicitation descriptor");
  reply_node = vlib_get_node_by_name (vm, (u8 *) "ip6-rewrite-mcast");
  IP6_RA_SHARED_VIEW_TEST (reply_node != 0, "find router advertisement rewrite node");
  forwarded = vlib_get_buffer (vm, forwarded_index);
  IP6_RA_SHARED_VIEW_TEST (forwarded_index != buffers[1], "replace router solicitation frame slot");
  IP6_RA_SHARED_VIEW_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
			   "forward ordinary router advertisement replacement");
  IP6_RA_SHARED_VIEW_TEST (forwarded_runtime_index == reply_node->runtime_index,
			   "send router advertisement to multicast rewrite");
  IP6_RA_SHARED_VIEW_TEST (
    root->current_length == sizeof (root_bytes) &&
      clib_memcmp (vlib_buffer_get_current (root), root_bytes, sizeof (root_bytes)) == 0,
    "leave canonical router solicitation root unchanged");
  ret = 1;

done:
  if (pending_len < vec_len (vm->node_main.pending_frames))
    ip6_ra_shared_view_discard_pending (vm, pending_len);
  else
    vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
ip6_ra_shared_view_failure_test (vlib_main_t *vm, u32 sw_if_index)
{
  vlib_buffer_t *descriptor = 0;
  vlib_buffer_t *root;
  vlib_node_t *drop_node;
  vlib_node_t *node;
  vlib_node_runtime_t *runtime;
  u32 buffers[2];
  u32 forwarded_index;
  u32 forwarded_runtime_index;
  u32 n_alloc;
  u32 pending_len = 0;
  u8 root_bytes[sizeof (ip6_header_t) + sizeof (icmp6_neighbor_discovery_header_t)];
  f64 success_rate;
  int ret = 0;

  if (vlib_buffer_alloc_fault_injector_set (vm, 0))
    return 1;

  success_rate = vm->buffer_alloc_success_rate;
  vm->buffer_alloc_success_rate = 1.0;
  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      vm->buffer_alloc_success_rate = success_rate;
      return 0;
    }

  root = vlib_get_buffer (vm, buffers[0]);
  ip6_ra_shared_view_init_rs (root, sw_if_index);
  clib_memcpy_fast (root_bytes, vlib_buffer_get_current (root), sizeof (root_bytes));
  IP6_RA_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			   "attach router solicitation COW-failure descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  IP6_RA_SHARED_VIEW_TEST (vlib_buffer_alloc_fault_injector_set (vm, 1) == 0,
			   "fail router solicitation COW allocation");
  IP6_RA_SHARED_VIEW_TEST (ip6_ra_shared_view_dispatch (vm, buffers[1], &forwarded_index,
							&forwarded_runtime_index,
							&pending_len) == 0,
			   "dispatch router solicitation COW-failure descriptor");
  node = vlib_get_node_by_name (vm, (u8 *) "icmp6-router-solicitation");
  drop_node = vlib_get_node_by_name (vm, (u8 *) "ip6-drop");
  IP6_RA_SHARED_VIEW_TEST (node && drop_node, "find router solicitation failure nodes");
  runtime = vlib_node_get_runtime (vm, node->index);
  IP6_RA_SHARED_VIEW_TEST (forwarded_index == buffers[1],
			   "retain descriptor after router solicitation COW failure");
  IP6_RA_SHARED_VIEW_TEST (forwarded_runtime_index == drop_node->runtime_index,
			   "drop router solicitation after COW allocation failure");
  IP6_RA_SHARED_VIEW_TEST (descriptor->error == runtime->errors[ICMP6_ERROR_ALLOC_FAILURE],
			   "account router solicitation COW failure as allocation failure");
  IP6_RA_SHARED_VIEW_TEST (vlib_buffer_shared_view_is_shared (descriptor),
			   "retain shared router solicitation descriptor after COW failure");
  IP6_RA_SHARED_VIEW_TEST (
    root->current_length == sizeof (root_bytes) &&
      clib_memcmp (vlib_buffer_get_current (root), root_bytes, sizeof (root_bytes)) == 0,
    "leave canonical router solicitation root unchanged after COW failure");
  ret = 1;

done:
  vlib_buffer_alloc_fault_injector_set (vm, 0);
  vm->buffer_alloc_success_rate = success_rate;
  if (pending_len < vec_len (vm->node_main.pending_frames))
    ip6_ra_shared_view_discard_pending (vm, pending_len);
  else if (descriptor)
    vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_ip6_ra_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 sw_if_index = ~0;
  int fault_injector_available;
  clib_error_t *error = 0;

  CLIB_UNUSED (unformat_input_t * input0) = input;
  CLIB_UNUSED (vlib_cli_command_t * cmd0) = cmd;
  if (ip6_ra_shared_view_setup (vm, &sw_if_index))
    return clib_error_return (0, "router solicitation shared-view setup failed");

  fault_injector_available = vlib_buffer_alloc_fault_injector_set (vm, 0) == 0;
  if (!ip6_ra_shared_view_success_test (vm, sw_if_index))
    error = clib_error_return (0, "router solicitation shared-view success test failed");
  else if (fault_injector_available && !ip6_ra_shared_view_failure_test (vm, sw_if_index))
    error = clib_error_return (0, "router solicitation shared-view failure test failed");

  if (fault_injector_available)
    vlib_buffer_alloc_fault_injector_set (vm, 0);
  ip6_link_disable (sw_if_index);
  vnet_delete_loopback_interface (sw_if_index);
  return error;
}

VLIB_CLI_COMMAND (test_ip6_ra_shared_view_command, static) = {
  .path = "test ip6-ra-shared-view",
  .short_help = "test ip6-ra-shared-view",
  .function = test_ip6_ra_shared_view_fn,
};
