/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/ip/icmp46_packet.h>
#include <ping/ping.h>

#define PING_TEST(_cond, _comment)                                                                 \
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
ping_shared_view_dispatch (vlib_main_t *vm, const char *node_name, u32 buffer_index,
			   u32 *forwarded_index, u32 *forwarded_runtime_index)
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
ping_shared_view_init_packet (vlib_buffer_t *buffer, int is_ip6)
{
  icmp46_header_t *icmp;

  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (buffer);

      buffer->current_length = sizeof (*ip6) + sizeof (*icmp);
      clib_memset (ip6, 0, buffer->current_length);
      ip6->protocol = IP_PROTOCOL_ICMP6;
      ip6->src_address.as_u64[1] = clib_host_to_net_u64 (1);
      ip6->dst_address.as_u64[1] = clib_host_to_net_u64 (2);
      icmp = ip6_next_header (ip6);
      icmp->type = ICMP6_echo_request;
    }
  else
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (buffer);

      buffer->current_length = sizeof (*ip4) + sizeof (*icmp);
      clib_memset (ip4, 0, buffer->current_length);
      ip4->ip_version_and_header_length = 0x45;
      ip4->protocol = IP_PROTOCOL_ICMP;
      ip4->src_address.as_u32 = clib_host_to_net_u32 (0x0a000001);
      ip4->dst_address.as_u32 = clib_host_to_net_u32 (0x0a000002);
      icmp = ip4_next_header (ip4);
      icmp->type = ICMP4_echo_request;
    }
}

static int
ping_shared_view_success_test (vlib_main_t *vm, int is_ip6)
{
  const char *node_name = is_ip6 ? "ip6-icmp-echo-request" : "ip4-icmp-echo-request";
  vlib_buffer_t *forwarded;
  vlib_buffer_t *root;
  vlib_node_runtime_t *runtime;
  icmp46_header_t *icmp;
  u32 buffers[2];
  u32 forwarded_index = ~0;
  u32 forwarded_runtime_index = ~0;
  u32 n_alloc;
  u32 next = is_ip6 ? ICMP6_ECHO_REQUEST_NEXT_LOOKUP : ICMP4_ECHO_REQUEST_NEXT_LOOKUP;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }

  root = vlib_get_buffer (vm, buffers[0]);
  ping_shared_view_init_packet (root, is_ip6);
  PING_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	     "attach ping shared-view descriptor");
  PING_TEST (ping_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index,
					&forwarded_runtime_index) == 0,
	     "dispatch ping shared-view descriptor");
  PING_TEST (forwarded_index != buffers[1], "replace ping descriptor frame slot");
  runtime = vlib_node_get_runtime (vm, vlib_get_node_by_name (vm, (u8 *) node_name)->index);
  PING_TEST (forwarded_runtime_index ==
	       vlib_node_runtime_get_next_frame (vm, runtime, next)->node_runtime_index,
	     "send ping replacement to lookup");
  forwarded = vlib_get_buffer (vm, forwarded_index);
  PING_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
	     "forward ordinary ping replacement after COW");
  icmp = is_ip6 ? ip6_next_header (vlib_buffer_get_current (forwarded)) :
		  ip4_next_header (vlib_buffer_get_current (forwarded));
  PING_TEST (icmp->type == (is_ip6 ? ICMP6_echo_reply : ICMP4_echo_reply),
	     "rewrite ping reply in replacement");
  icmp = is_ip6 ? ip6_next_header (vlib_buffer_get_current (root)) :
		  ip4_next_header (vlib_buffer_get_current (root));
  PING_TEST (icmp->type == (is_ip6 ? ICMP6_echo_request : ICMP4_echo_request),
	     "leave ping canonical root unchanged");
  ret = 1;

done:
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
ping_shared_view_failure_test (vlib_main_t *vm, int is_ip6)
{
  const char *node_name = is_ip6 ? "ip6-icmp-echo-request" : "ip4-icmp-echo-request";
  vlib_buffer_t *descriptor = 0;
  vlib_buffer_t *root;
  vlib_node_runtime_t *runtime;
  u32 buffers[2];
  u32 descriptor_next = 0;
  u32 forwarded_index = ~0;
  u32 forwarded_runtime_index = ~0;
  u32 n_alloc;
  u32 next = is_ip6 ? ICMP6_ECHO_REQUEST_NEXT_DROP : ICMP4_ECHO_REQUEST_NEXT_DROP;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }

  root = vlib_get_buffer (vm, buffers[0]);
  ping_shared_view_init_packet (root, is_ip6);
  PING_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	     "attach malformed ping descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  PING_TEST (ping_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index,
					&forwarded_runtime_index) == 0,
	     "dispatch ping COW-failure descriptor");
  descriptor->next_buffer = descriptor_next;
  PING_TEST (forwarded_index == buffers[1], "retain ping descriptor after COW failure");
  runtime = vlib_node_get_runtime (vm, vlib_get_node_by_name (vm, (u8 *) node_name)->index);
  PING_TEST (forwarded_runtime_index ==
	       vlib_node_runtime_get_next_frame (vm, runtime, next)->node_runtime_index,
	     "send ping COW failure to error drop");
  PING_TEST (descriptor->error == runtime->errors[ICMP_ECHO_REQUEST_ERROR_COW_FAIL],
	     "account ping COW failure");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_ping_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!ping_shared_view_success_test (vm, 0) || !ping_shared_view_success_test (vm, 1) ||
      !ping_shared_view_failure_test (vm, 0) || !ping_shared_view_failure_test (vm, 1))
    return clib_error_return (0, "ping shared-view test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_ping_shared_view_command, static) = {
  .path = "test ping-shared-view",
  .short_help = "test ping-shared-view",
  .function = test_ping_shared_view_fn,
};
