/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <udp-echo/udp_echo.h>

#define UDP_ECHO_TEST(_cond, _comment)                                                             \
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
udp_echo_shared_view_dispatch (vlib_main_t *vm, u32 buffer_index, u32 *forwarded_index,
			       u32 *forwarded_runtime_index)
{
  vlib_node_runtime_t *runtime;
  vlib_pending_frame_t *pending;
  vlib_frame_t *frame;
  u32 pending_len;
  u32 i;
  int ret = -1;

  runtime = vlib_node_get_runtime (vm, udp_echo_node.index);
  frame = vlib_get_frame_to_node (vm, udp_echo_node.index);
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
  *forwarded_runtime_index = pending->node_runtime_index;
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

static void
udp_echo_shared_view_init_packet (vlib_buffer_t *buffer)
{
  ip4_header_t *ip;
  udp_header_t *udp;

  buffer->current_length = sizeof (*ip) + sizeof (*udp);
  vnet_buffer (buffer)->l3_hdr_offset = 0;
  ip = vlib_buffer_get_current (buffer);
  clib_memset (ip, 0, buffer->current_length);
  ip->ip_version_and_header_length = 0x45;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = clib_host_to_net_u32 (0x0a000001);
  ip->dst_address.as_u32 = clib_host_to_net_u32 (0x0a000002);
  udp = ip4_next_header (ip);
  udp->src_port = clib_host_to_net_u16 (1000);
  udp->dst_port = clib_host_to_net_u16 (2000);
}

static int
udp_echo_shared_view_ordinary_test (vlib_main_t *vm)
{
  vlib_buffer_t *forwarded;
  vlib_buffer_t *input;
  ip4_header_t *ip;
  u32 buffer_index;
  u32 forwarded_index = ~0;
  u32 forwarded_runtime_index = ~0;
  int ret = 0;

  if (vlib_buffer_alloc (vm, &buffer_index, 1) != 1)
    return 0;

  input = vlib_get_buffer (vm, buffer_index);
  udp_echo_shared_view_init_packet (input);
  UDP_ECHO_TEST (udp_echo_shared_view_dispatch (vm, buffer_index, &forwarded_index,
						&forwarded_runtime_index) == 0,
		 "dispatch ordinary UDP echo buffer");
  UDP_ECHO_TEST (forwarded_index == buffer_index, "retain ordinary UDP echo frame slot");
  UDP_ECHO_TEST (forwarded_runtime_index ==
		   vlib_node_runtime_get_next_frame (
		     vm, vlib_node_get_runtime (vm, udp_echo_node.index), UDP_ECHO_NEXT_IP4_LOOKUP)
		     ->node_runtime_index,
		 "send ordinary UDP echo buffer to ip4-lookup");
  forwarded = vlib_get_buffer (vm, forwarded_index);
  UDP_ECHO_TEST (forwarded == input, "retain ordinary UDP echo buffer pointer");
  ip = vlib_buffer_get_current (forwarded);
  UDP_ECHO_TEST (ip->src_address.as_u32 == clib_host_to_net_u32 (0x0a000002) &&
		   ip->dst_address.as_u32 == clib_host_to_net_u32 (0x0a000001),
		 "rewrite ordinary UDP echo buffer");
  ret = 1;

done:
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffer_index : forwarded_index);
  return ret;
}

static int
udp_echo_shared_view_success_test (vlib_main_t *vm)
{
  vlib_buffer_t *descriptor;
  vlib_buffer_t *forwarded;
  vlib_buffer_t *root;
  ip4_header_t *ip;
  udp_header_t *udp;
  u32 buffers[2];
  u32 forwarded_index = ~0;
  u32 forwarded_runtime_index = ~0;
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
  udp_echo_shared_view_init_packet (root);
  UDP_ECHO_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
		 "attach UDP echo shared-view descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  UDP_ECHO_TEST (
    udp_echo_shared_view_dispatch (vm, buffers[1], &forwarded_index, &forwarded_runtime_index) == 0,
    "dispatch UDP echo shared-view descriptor");
  UDP_ECHO_TEST (forwarded_index != buffers[1], "replace UDP echo descriptor frame slot");
  UDP_ECHO_TEST (forwarded_runtime_index ==
		   vlib_node_runtime_get_next_frame (
		     vm, vlib_node_get_runtime (vm, udp_echo_node.index), UDP_ECHO_NEXT_IP4_LOOKUP)
		     ->node_runtime_index,
		 "send UDP echo COW replacement to ip4-lookup");
  forwarded = vlib_get_buffer (vm, forwarded_index);
  UDP_ECHO_TEST (forwarded != descriptor, "reload UDP echo pointer after descriptor COW");
  UDP_ECHO_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
		 "forward ordinary UDP echo replacement after COW");
  ip = vlib_buffer_get_current (forwarded);
  udp = ip4_next_header (ip);
  UDP_ECHO_TEST (ip->src_address.as_u32 == clib_host_to_net_u32 (0x0a000002) &&
		   ip->dst_address.as_u32 == clib_host_to_net_u32 (0x0a000001),
		 "swap UDP echo IP addresses in replacement");
  UDP_ECHO_TEST (udp->src_port == clib_host_to_net_u16 (2000) &&
		   udp->dst_port == clib_host_to_net_u16 (1000),
		 "swap UDP echo ports in replacement");
  ip = vlib_buffer_get_current (root);
  udp = ip4_next_header (ip);
  UDP_ECHO_TEST (ip->src_address.as_u32 == clib_host_to_net_u32 (0x0a000001) &&
		   ip->dst_address.as_u32 == clib_host_to_net_u32 (0x0a000002) &&
		   udp->src_port == clib_host_to_net_u16 (1000) &&
		   udp->dst_port == clib_host_to_net_u16 (2000),
		 "leave UDP echo canonical root unchanged");
  ret = 1;

done:
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
udp_echo_shared_view_failure_test (vlib_main_t *vm)
{
  vlib_buffer_t *descriptor = 0;
  vlib_buffer_t *root;
  vlib_node_runtime_t *runtime;
  u32 buffers[2];
  u32 descriptor_next = 0;
  u32 forwarded_index = ~0;
  u32 forwarded_runtime_index = ~0;
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
  udp_echo_shared_view_init_packet (root);
  UDP_ECHO_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
		 "attach malformed UDP echo descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  UDP_ECHO_TEST (
    udp_echo_shared_view_dispatch (vm, buffers[1], &forwarded_index, &forwarded_runtime_index) == 0,
    "dispatch UDP echo COW-failure descriptor");
  descriptor->next_buffer = descriptor_next;
  UDP_ECHO_TEST (forwarded_index == buffers[1], "retain UDP echo descriptor after COW failure");
  UDP_ECHO_TEST (vlib_get_buffer (vm, forwarded_index) == descriptor,
		 "retain UDP echo pointer after COW failure");
  runtime = vlib_node_get_runtime (vm, udp_echo_node.index);
  UDP_ECHO_TEST (
    forwarded_runtime_index ==
      vlib_node_runtime_get_next_frame (vm, runtime, UDP_ECHO_NEXT_DROP)->node_runtime_index,
    "send UDP echo COW failure to error drop");
  UDP_ECHO_TEST (descriptor->error == runtime->errors[UDP_ECHO_ERROR_COW_FAIL],
		 "send UDP echo COW failure to error drop");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_udp_echo_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!udp_echo_shared_view_ordinary_test (vm) || !udp_echo_shared_view_success_test (vm) ||
      !udp_echo_shared_view_failure_test (vm))
    return clib_error_return (0, "UDP echo shared-view test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_udp_echo_shared_view_command, static) = {
  .path = "test udp-echo-shared-view",
  .short_help = "test udp-echo-shared-view",
  .function = test_udp_echo_shared_view_fn,
};
