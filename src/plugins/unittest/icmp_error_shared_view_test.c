/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>

#define ICMP_ERROR_SHARED_VIEW_TEST(_cond, _comment)                                               \
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
icmp_error_shared_view_clear_pending (vlib_main_t *vm, u32 pending_len, int free_buffers)
{
  vlib_pending_frame_t *pending;
  u32 i;

  for (i = pending_len; i < vec_len (vm->node_main.pending_frames); i++)
    {
      pending = vec_elt_at_index (vm->node_main.pending_frames, i);
      if (free_buffers)
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
icmp_error_shared_view_dispatch (vlib_main_t *vm, const char *node_name, u32 buffer_index,
				 u32 *forwarded_indices, u32 *forwarded_runtime_indices,
				 u32 max_forwarded, u32 *n_forwarded, u32 *pending_len)
{
  vlib_node_t *node;
  vlib_node_runtime_t *runtime;
  vlib_pending_frame_t *pending;
  vlib_frame_t *frame;
  u32 i;
  int ret = -1;

  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  if (node == 0)
    return -1;
  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  if (frame == 0)
    return -1;

  *pending_len = vec_len (vm->node_main.pending_frames);
  *n_forwarded = 0;
  ((u32 *) vlib_frame_vector_args (frame))[0] = buffer_index;
  frame->n_vectors = 1;
  runtime->function (vm, runtime, frame);

  for (i = *pending_len; i < vec_len (vm->node_main.pending_frames); i++)
    {
      u32 *from;
      u32 j;

      pending = vec_elt_at_index (vm->node_main.pending_frames, i);
      from = vlib_frame_vector_args (pending->frame);
      for (j = 0; j < pending->frame->n_vectors; j++)
	{
	  if (*n_forwarded == max_forwarded)
	    goto done;
	  forwarded_indices[*n_forwarded] = from[j];
	  forwarded_runtime_indices[*n_forwarded] = pending->node_runtime_index;
	  *n_forwarded += 1;
	}
    }
  ret = 0;

done:
  vlib_frame_free (vm, frame);
  return ret;
}

static void
icmp_error_shared_view_init_ip4 (vlib_buffer_t *buffer)
{
  ip4_header_t *ip = vlib_buffer_get_current (buffer);

  clib_memset (ip, 0, 64);
  ip->ip_version_and_header_length = 0x45;
  ip->length = clib_host_to_net_u16 (64);
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = clib_host_to_net_u32 (0xc0000201);
  ip->dst_address.as_u32 = clib_host_to_net_u32 (0xc6336401);
  ip->checksum = ip4_header_checksum (ip);
  buffer->current_length = 64;
}

static void
icmp_error_shared_view_init_ip6 (vlib_buffer_t *buffer)
{
  ip6_header_t *ip = vlib_buffer_get_current (buffer);

  clib_memset (ip, 0, 64);
  ip->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (6 << 28);
  ip->payload_length = clib_host_to_net_u16 (24);
  ip->hop_limit = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u8[15] = 1;
  ip->dst_address.as_u8[15] = 2;
  buffer->current_length = 64;
}

static int
icmp_error_shared_view_success_test (vlib_main_t *vm, const char *node_name, int is_ip6)
{
  vlib_buffer_t *root;
  vlib_buffer_t *buffer;
  vlib_buffer_t *reply = 0;
  vlib_buffer_t *original = 0;
  u32 buffers[2];
  u32 forwarded_indices[2] = { ~0, ~0 };
  u32 forwarded_runtime_indices[2] = { ~0, ~0 };
  u32 n_alloc;
  u32 n_forwarded = 0;
  u32 pending_len = 0;
  u32 i;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }

  root = vlib_get_buffer (vm, buffers[0]);
  if (is_ip6)
    icmp_error_shared_view_init_ip6 (root);
  else
    icmp_error_shared_view_init_ip4 (root);
  vnet_buffer (root)->sw_if_index[VLIB_RX] = ~0;

  ICMP_ERROR_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			       "attach ICMP error shared-view descriptor");
  buffer = vlib_get_buffer (vm, buffers[1]);
  ICMP_ERROR_SHARED_VIEW_TEST (buffer->current_length == 0, "use headerless ICMP error descriptor");
  vnet_buffer (buffer)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (buffer)->ip.icmp.type = is_ip6 ? ICMP6_time_exceeded : ICMP4_time_exceeded;
  vnet_buffer (buffer)->ip.icmp.code = is_ip6 ? ICMP6_time_exceeded_ttl_exceeded_in_transit :
						ICMP4_time_exceeded_ttl_exceeded_in_transit;
  vnet_buffer (buffer)->ip.icmp.data = 0x11223344;

  ICMP_ERROR_SHARED_VIEW_TEST (
    icmp_error_shared_view_dispatch (vm, node_name, buffers[1], forwarded_indices,
				     forwarded_runtime_indices, ARRAY_LEN (forwarded_indices),
				     &n_forwarded, &pending_len) == 0,
    "dispatch headerless ICMP error descriptor");
  ICMP_ERROR_SHARED_VIEW_TEST (n_forwarded == ARRAY_LEN (forwarded_indices),
			       "emit reply and consume the ordinary replacement");
  for (i = 0; i < n_forwarded; i++)
    {
      buffer = vlib_get_buffer (vm, forwarded_indices[i]);
      if (buffer->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED)
	reply = buffer;
      else
	original = buffer;
    }
  ICMP_ERROR_SHARED_VIEW_TEST (reply && original, "identify reply and replacement frames");
  ICMP_ERROR_SHARED_VIEW_TEST (vlib_get_buffer_index (vm, original) != buffers[1] &&
				 !vlib_buffer_shared_view_is_shared (original),
			       "drop an ordinary replacement instead of the descriptor");
  ICMP_ERROR_SHARED_VIEW_TEST (vnet_buffer (original)->sw_if_index[VLIB_RX] == 0,
			       "preserve descriptor-local receive interface across COW");

  if (is_ip6)
    {
      ip6_header_t *ip = vlib_buffer_get_current (reply);
      icmp46_header_t *icmp = (icmp46_header_t *) (ip + 1);

      ICMP_ERROR_SHARED_VIEW_TEST (ip->protocol == IP_PROTOCOL_ICMP6 &&
				     icmp->type == ICMP6_time_exceeded &&
				     icmp->code == ICMP6_time_exceeded_ttl_exceeded_in_transit &&
				     *((u32 *) (icmp + 1)) == clib_host_to_net_u32 (0x11223344),
				   "preserve descriptor-local ICMPv6 metadata");
      ip->hop_limit = 1;
      ICMP_ERROR_SHARED_VIEW_TEST (((ip6_header_t *) vlib_buffer_get_current (root))->hop_limit ==
				     64,
				   "leave canonical IPv6 root unchanged");
    }
  else
    {
      ip4_header_t *ip = vlib_buffer_get_current (reply);
      icmp46_header_t *icmp = (icmp46_header_t *) (ip + 1);

      ICMP_ERROR_SHARED_VIEW_TEST (ip->protocol == IP_PROTOCOL_ICMP &&
				     icmp->type == ICMP4_time_exceeded &&
				     icmp->code == ICMP4_time_exceeded_ttl_exceeded_in_transit &&
				     *((u32 *) (icmp + 1)) == clib_host_to_net_u32 (0x11223344),
				   "preserve descriptor-local ICMPv4 metadata");
      ip->ttl = 1;
      ICMP_ERROR_SHARED_VIEW_TEST (((ip4_header_t *) vlib_buffer_get_current (root))->ttl == 64,
				   "leave canonical IPv4 root unchanged");
    }
  ret = 1;

done:
  if (pending_len || n_forwarded)
    icmp_error_shared_view_clear_pending (vm, pending_len, 1);
  else
    vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
icmp_error_shared_view_failure_test (vlib_main_t *vm, const char *node_name, u32 expected_error)
{
  vlib_buffer_t *descriptor = 0;
  vlib_node_t *node;
  vlib_node_runtime_t *runtime;
  u32 buffers[2];
  u32 descriptor_next = 0;
  u32 forwarded_indices[2] = { ~0, ~0 };
  u32 forwarded_runtime_indices[2] = { ~0, ~0 };
  u32 n_alloc;
  u32 n_forwarded = 0;
  u32 pending_len = 0;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }

  vlib_get_buffer (vm, buffers[0])->current_length = 64;
  ICMP_ERROR_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			       "attach malformed ICMP error descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];

  ICMP_ERROR_SHARED_VIEW_TEST (
    icmp_error_shared_view_dispatch (vm, node_name, buffers[1], forwarded_indices,
				     forwarded_runtime_indices, ARRAY_LEN (forwarded_indices),
				     &n_forwarded, &pending_len) == 0,
    "dispatch malformed ICMP error descriptor");
  descriptor->next_buffer = descriptor_next;

  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  runtime = vlib_node_get_runtime (vm, node->index);
  ICMP_ERROR_SHARED_VIEW_TEST (n_forwarded == 1 && forwarded_indices[0] == buffers[1],
			       "retain malformed descriptor on COW failure");
  ICMP_ERROR_SHARED_VIEW_TEST (
    forwarded_runtime_indices[0] ==
      vlib_node_runtime_get_next_frame (vm, runtime, 0)->node_runtime_index,
    "send ICMP COW failure to the existing drop next");
  ICMP_ERROR_SHARED_VIEW_TEST (descriptor->error == runtime->errors[expected_error],
			       "account ICMP COW failure as a drop");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  if (pending_len || n_forwarded)
    icmp_error_shared_view_clear_pending (vm, pending_len, 1);
  else
    vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_icmp_error_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!icmp_error_shared_view_success_test (vm, "ip4-icmp-error", 0) ||
      !icmp_error_shared_view_success_test (vm, "ip6-icmp-error", 1) ||
      !icmp_error_shared_view_failure_test (vm, "ip4-icmp-error", ICMP4_ERROR_DROP) ||
      !icmp_error_shared_view_failure_test (vm, "ip6-icmp-error", ICMP6_ERROR_DROP))
    return clib_error_return (0, "ICMP error shared-view test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_icmp_error_shared_view_command, static) = {
  .path = "test icmp-error-shared-view",
  .short_help = "test icmp-error-shared-view",
  .function = test_icmp_error_shared_view_fn,
};
