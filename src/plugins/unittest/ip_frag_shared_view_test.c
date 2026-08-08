/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip_frag.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#include <stdbool.h>

#define IP_FRAG_TEST(_cond, _comment)                                                              \
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
ip_frag_shared_view_discard_pending (vlib_main_t *vm, u32 pending_len)
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

static void
ip_frag_shared_view_init_ip4 (vlib_buffer_t *buffer)
{
  ip4_header_t *ip = vlib_buffer_get_current (buffer);
  u32 i;

  clib_memset (ip, 0, 96);
  ip->ip_version_and_header_length = 0x45;
  ip->length = clib_host_to_net_u16 (96);
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  for (i = sizeof (*ip); i < 96; i++)
    ((u8 *) ip)[i] = i;
  ip->checksum = ip4_header_checksum (ip);
  buffer->current_length = 96;
}

static void
ip_frag_shared_view_init_ip6 (vlib_buffer_t *buffer)
{
  ip6_header_t *ip = vlib_buffer_get_current (buffer);
  u32 i;

  clib_memset (ip, 0, 104);
  ip->payload_length = clib_host_to_net_u16 (64);
  ip->hop_limit = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  for (i = sizeof (*ip); i < 104; i++)
    ((u8 *) ip)[i] = i;
  buffer->current_length = 104;
}

static int
ip_frag_shared_view_test_node (vlib_main_t *vm, const char *node_name, bool is_ip6)
{
  vlib_buffer_t *descriptor;
  vlib_buffer_t *root;
  vlib_node_runtime_t *runtime;
  vlib_node_t *node;
  vlib_pending_frame_t *pending;
  vlib_frame_t *frame = 0;
  u32 buffers[2];
  u32 fragment_count = 0;
  u32 i;
  u32 j;
  u32 n_alloc;
  u32 pending_len = vec_len (vm->node_main.pending_frames);
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
    ip_frag_shared_view_init_ip6 (root);
  else
    ip_frag_shared_view_init_ip4 (root);
  vnet_buffer (root)->ip_frag.mtu = is_ip6 ? 80 : 60;
  vnet_buffer (root)->ip_frag.next_index = IP_FRAG_NEXT_DROP;

  IP_FRAG_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
		"attach fragmentation shared-view descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  IP_FRAG_TEST (descriptor->current_length == 0,
		"use headerless descriptor for fragmentation node");

  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  IP_FRAG_TEST (node != 0, "find fragmentation node");
  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  IP_FRAG_TEST (frame != 0, "allocate fragmentation frame");
  pending_len = vec_len (vm->node_main.pending_frames);
  ((u32 *) vlib_frame_vector_args (frame))[0] = buffers[1];
  frame->n_vectors = 1;
  runtime->function (vm, runtime, frame);

  for (i = pending_len; i < vec_len (vm->node_main.pending_frames); i++)
    {
      pending = vec_elt_at_index (vm->node_main.pending_frames, i);
      fragment_count += pending->frame->n_vectors;
      for (j = 0; j < pending->frame->n_vectors; j++)
	IP_FRAG_TEST (!vlib_buffer_shared_view_is_shared (
			vlib_get_buffer (vm, ((u32 *) vlib_frame_vector_args (pending->frame))[j])),
		      "forward ordinary fragments after shared-view COW");
    }

  IP_FRAG_TEST (fragment_count >= 2, "fragment headerless descriptor payload");
  if (is_ip6)
    {
      ip6_header_t *ip = vlib_buffer_get_current (root);

      IP_FRAG_TEST (root->current_length == 104 && ip->protocol == IP_PROTOCOL_UDP &&
		      ip->payload_length == clib_host_to_net_u16 (64),
		    "leave canonical IPv6 root unchanged");
    }
  else
    {
      ip4_header_t *ip = vlib_buffer_get_current (root);

      IP_FRAG_TEST (root->current_length == 96 && ip->ttl == 64 &&
		      ip->length == clib_host_to_net_u16 (96),
		    "leave canonical IPv4 root unchanged");
    }
  ret = 1;

done:
  if (frame)
    vlib_frame_free (vm, frame);
  ip_frag_shared_view_discard_pending (vm, pending_len);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_ip_frag_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!ip_frag_shared_view_test_node (vm, "ip4-frag", 0) ||
      !ip_frag_shared_view_test_node (vm, "ip6-frag", 1))
    return clib_error_return (0, "IP fragmentation shared-view test failed");
  return 0;
}

VLIB_CLI_COMMAND (test_ip_frag_shared_view_command, static) = {
  .path = "test ip-frag-shared-view",
  .short_help = "test ip-frag-shared-view",
  .function = test_ip_frag_shared_view_fn,
};
