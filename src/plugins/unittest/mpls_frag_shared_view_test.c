/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/adj/adj.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip_frag.h>
#include <vnet/mpls/mpls.h>

#define MPLS_FRAG_TEST(_cond, _comment)                                                            \
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
mpls_frag_shared_view_discard_pending (vlib_main_t *vm, u32 pending_len)
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
mpls_frag_shared_view_init_ip4 (vlib_buffer_t *buffer)
{
  mpls_unicast_header_t *mpls = vlib_buffer_get_current (buffer);
  ip4_header_t *ip = (ip4_header_t *) (mpls + 1);
  u32 i;

  clib_memset (mpls, 0, sizeof (*mpls) + 96);
  ip->ip_version_and_header_length = 0x45;
  ip->length = clib_host_to_net_u16 (96);
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  for (i = sizeof (*ip); i < 96; i++)
    ((u8 *) ip)[i] = i;
  ip->checksum = ip4_header_checksum (ip);
  buffer->current_length = sizeof (*mpls) + 96;
  vnet_buffer (buffer)->l3_hdr_offset = buffer->current_data + sizeof (*mpls);
  vnet_buffer (buffer)->mpls.pyld_proto = DPO_PROTO_IP4;
}

static adj_index_t
mpls_frag_shared_view_add_adj (u16 *max_l3_packet_bytes, u32 *lookup_next_index)
{
  ip46_address_t nh = {
    .ip4.as_u32 = clib_host_to_net_u32 (0x0a000001),
  };
  adj_index_t adj_index;
  ip_adjacency_t *adj;

  adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP4, VNET_LINK_MPLS, &nh, 0);
  adj = adj_get (adj_index);
  *max_l3_packet_bytes = adj->rewrite_header.max_l3_packet_bytes;
  *lookup_next_index = adj->lookup_next_index;
  adj->rewrite_header.max_l3_packet_bytes = 60;
  adj->lookup_next_index = IP_LOOKUP_NEXT_REWRITE;
  return adj_index;
}

static int
mpls_frag_shared_view_success_test (vlib_main_t *vm)
{
  adj_index_t adj_index = ADJ_INDEX_INVALID;
  vlib_buffer_t *root;
  vlib_node_runtime_t *runtime;
  vlib_node_t *node;
  vlib_pending_frame_t *pending;
  vlib_frame_t *frame = 0;
  u32 buffers[2];
  u32 i;
  u32 j;
  u32 n_alloc;
  u32 n_forwarded = 0;
  u32 pending_len = vec_len (vm->node_main.pending_frames);
  u32 lookup_next_index = 0;
  u16 max_l3_packet_bytes = 0;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }

  root = vlib_get_buffer (vm, buffers[0]);
  mpls_frag_shared_view_init_ip4 (root);
  adj_index = mpls_frag_shared_view_add_adj (&max_l3_packet_bytes, &lookup_next_index);
  MPLS_FRAG_TEST (adj_index != ADJ_INDEX_INVALID, "create MPLS test adjacency");
  vnet_buffer (root)->ip.adj_index[VLIB_TX] = adj_index;
  MPLS_FRAG_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
		  "attach MPLS fragmentation shared-view descriptor");
  MPLS_FRAG_TEST (vlib_get_buffer (vm, buffers[1])->current_length == 0,
		  "use headerless MPLS fragmentation descriptor");

  node = vlib_get_node_by_name (vm, (u8 *) "mpls-frag");
  MPLS_FRAG_TEST (node != 0, "find MPLS fragmentation node");
  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  MPLS_FRAG_TEST (frame != 0, "allocate MPLS fragmentation frame");
  pending_len = vec_len (vm->node_main.pending_frames);
  ((u32 *) vlib_frame_vector_args (frame))[0] = buffers[1];
  frame->n_vectors = 1;
  runtime->function (vm, runtime, frame);

  for (i = pending_len; i < vec_len (vm->node_main.pending_frames); i++)
    {
      pending = vec_elt_at_index (vm->node_main.pending_frames, i);
      n_forwarded += pending->frame->n_vectors;
      for (j = 0; j < pending->frame->n_vectors; j++)
	MPLS_FRAG_TEST (!vlib_buffer_shared_view_is_shared (vlib_get_buffer (
			  vm, ((u32 *) vlib_frame_vector_args (pending->frame))[j])),
			"forward ordinary MPLS fragments after COW");
    }

  MPLS_FRAG_TEST (n_forwarded >= 2, "fragment MPLS shared-view descriptor");
  MPLS_FRAG_TEST (
    root->current_length == sizeof (mpls_unicast_header_t) + 96 &&
      ((ip4_header_t *) (vlib_buffer_get_current (root) + sizeof (mpls_unicast_header_t)))->ttl ==
	64,
    "leave canonical MPLS root unchanged");
  ret = 1;

done:
  if (frame)
    vlib_frame_free (vm, frame);
  mpls_frag_shared_view_discard_pending (vm, pending_len);
  if (adj_index != ADJ_INDEX_INVALID)
    {
      ip_adjacency_t *adj = adj_get (adj_index);

      adj->rewrite_header.max_l3_packet_bytes = max_l3_packet_bytes;
      adj->lookup_next_index = lookup_next_index;
      adj_unlock (adj_index);
    }
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
mpls_frag_shared_view_failure_test (vlib_main_t *vm)
{
  vlib_buffer_t *descriptor = 0;
  vlib_buffer_t *root;
  vlib_node_runtime_t *runtime;
  vlib_node_t *node;
  vlib_node_t *drop_node;
  vlib_pending_frame_t *pending;
  vlib_frame_t *frame = 0;
  u32 buffers[2];
  u32 descriptor_next = 0;
  u32 forwarded_index = ~0;
  u32 forwarded_runtime_index = ~0;
  u32 i;
  u32 n_alloc;
  u32 n_forwarded = 0;
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
  mpls_frag_shared_view_init_ip4 (root);
  MPLS_FRAG_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
		  "attach MPLS COW-failure descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];

  node = vlib_get_node_by_name (vm, (u8 *) "mpls-frag");
  MPLS_FRAG_TEST (node != 0, "find MPLS fragmentation node");
  drop_node = vlib_get_node_by_name (vm, (u8 *) "mpls-drop");
  MPLS_FRAG_TEST (drop_node != 0, "find MPLS drop node");
  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  MPLS_FRAG_TEST (frame != 0, "allocate MPLS fragmentation failure frame");
  pending_len = vec_len (vm->node_main.pending_frames);
  ((u32 *) vlib_frame_vector_args (frame))[0] = buffers[1];
  frame->n_vectors = 1;
  runtime->function (vm, runtime, frame);

  for (i = pending_len; i < vec_len (vm->node_main.pending_frames); i++)
    {
      pending = vec_elt_at_index (vm->node_main.pending_frames, i);
      if (n_forwarded == 0 && pending->frame->n_vectors)
	{
	  forwarded_index = ((u32 *) vlib_frame_vector_args (pending->frame))[0];
	  forwarded_runtime_index = pending->node_runtime_index;
	}
      n_forwarded += pending->frame->n_vectors;
    }

  MPLS_FRAG_TEST (n_forwarded == 1 && forwarded_index == buffers[1],
		  "retain MPLS descriptor after COW failure");
  MPLS_FRAG_TEST (forwarded_runtime_index == drop_node->runtime_index,
		  "send MPLS COW failure to drop");
  MPLS_FRAG_TEST (vlib_buffer_shared_view_is_shared (descriptor),
		  "retain shared MPLS descriptor after COW failure");
  MPLS_FRAG_TEST (
    root->current_length == sizeof (mpls_unicast_header_t) + 96 &&
      ((ip4_header_t *) (vlib_buffer_get_current (root) + sizeof (mpls_unicast_header_t)))->ttl ==
	64,
    "leave canonical MPLS root unchanged after COW failure");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  if (frame)
    vlib_frame_free (vm, frame);
  if (pending_len < vec_len (vm->node_main.pending_frames))
    mpls_frag_shared_view_discard_pending (vm, pending_len);
  else if (descriptor)
    vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_mpls_frag_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!mpls_frag_shared_view_success_test (vm))
    return clib_error_return (0, "MPLS fragmentation shared-view success test failed");
  if (!mpls_frag_shared_view_failure_test (vm))
    return clib_error_return (0, "MPLS fragmentation shared-view failure test failed");
  return 0;
}

VLIB_CLI_COMMAND (test_mpls_frag_shared_view_command, static) = {
  .path = "test mpls-frag-shared-view",
  .short_help = "test mpls-frag-shared-view",
  .function = test_mpls_frag_shared_view_fn,
};
