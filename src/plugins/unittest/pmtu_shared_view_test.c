/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/dpo/dpo.h>
#include <vnet/ip/ip_frag.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_path_mtu.h>

#include <stdbool.h>

#define PMTU_TEST(_cond, _comment)                                                                 \
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
pmtu_shared_view_discard_pending (vlib_main_t *vm, u32 pending_len)
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
pmtu_shared_view_init_ip4 (vlib_buffer_t *buffer)
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
pmtu_shared_view_init_ip6 (vlib_buffer_t *buffer)
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
pmtu_shared_view_success_test (vlib_main_t *vm, const char *node_name, dpo_proto_t proto)
{
  dpo_id_t parent = DPO_INVALID;
  dpo_id_t pmtu = DPO_INVALID;
  vlib_buffer_t *root;
  vlib_node_runtime_t *runtime;
  vlib_node_t *node;
  vlib_pending_frame_t *pending;
  vlib_frame_t *frame = 0;
  u32 buffers[2];
  u32 fragments = 0;
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
  if (proto == DPO_PROTO_IP6)
    pmtu_shared_view_init_ip6 (root);
  else
    pmtu_shared_view_init_ip4 (root);

  dpo_set (&parent, DPO_DROP, proto, proto);
  ip_pmtu_dpo_add_or_lock (60, &parent, &pmtu);
  dpo_reset (&parent);
  vnet_buffer (root)->ip.adj_index[VLIB_TX] = pmtu.dpoi_index;
  PMTU_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	     "attach PMTU shared-view descriptor");
  PMTU_TEST (vlib_get_buffer (vm, buffers[1])->current_length == 0,
	     "use headerless PMTU descriptor");

  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  PMTU_TEST (node != 0, "find PMTU node");
  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  PMTU_TEST (frame != 0, "allocate PMTU frame");
  pending_len = vec_len (vm->node_main.pending_frames);
  ((u32 *) vlib_frame_vector_args (frame))[0] = buffers[1];
  frame->n_vectors = 1;
  runtime->function (vm, runtime, frame);

  for (i = pending_len; i < vec_len (vm->node_main.pending_frames); i++)
    {
      pending = vec_elt_at_index (vm->node_main.pending_frames, i);
      fragments += pending->frame->n_vectors;
      for (j = 0; j < pending->frame->n_vectors; j++)
	PMTU_TEST (!vlib_buffer_shared_view_is_shared (
		     vlib_get_buffer (vm, ((u32 *) vlib_frame_vector_args (pending->frame))[j])),
		   "forward ordinary fragments after PMTU COW");
    }

  PMTU_TEST (fragments >= 2, "fragment PMTU shared-view descriptor");
  if (proto == DPO_PROTO_IP6)
    {
      ip6_header_t *ip = vlib_buffer_get_current (root);

      PMTU_TEST (root->current_length == 104 && ip->hop_limit == 64 &&
		   ip->payload_length == clib_host_to_net_u16 (64),
		 "leave canonical IPv6 root unchanged");
    }
  else
    {
      ip4_header_t *ip = vlib_buffer_get_current (root);

      PMTU_TEST (root->current_length == 96 && ip->ttl == 64 &&
		   ip->length == clib_host_to_net_u16 (96),
		 "leave canonical IPv4 root unchanged");
    }
  ret = 1;

done:
  if (frame)
    vlib_frame_free (vm, frame);
  pmtu_shared_view_discard_pending (vm, pending_len);
  dpo_reset (&pmtu);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
pmtu_shared_view_failure_test (vlib_main_t *vm)
{
  vlib_buffer_t *descriptor = 0;
  vlib_buffer_t *root;
  vlib_node_runtime_t *runtime;
  vlib_node_t *node;
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
  pmtu_shared_view_init_ip4 (root);
  PMTU_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	     "attach PMTU COW-failure descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];

  node = vlib_get_node_by_name (vm, (u8 *) "ip4-pmtu-dpo");
  PMTU_TEST (node != 0, "find IPv4 PMTU node");
  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  PMTU_TEST (frame != 0, "allocate PMTU failure frame");
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

  PMTU_TEST (n_forwarded == 1 && forwarded_index == buffers[1],
	     "retain PMTU descriptor after COW failure");
  PMTU_TEST (forwarded_runtime_index ==
	       vlib_node_runtime_get_next_frame (vm, runtime, 1)->node_runtime_index,
	     "send PMTU COW failure to drop");
  PMTU_TEST (descriptor->error == runtime->errors[IP_FRAG_ERROR_MEMORY],
	     "account PMTU COW failure as memory error");
  PMTU_TEST (vlib_buffer_shared_view_is_shared (descriptor),
	     "retain shared PMTU descriptor after COW failure");
  PMTU_TEST (root->current_length == 96 &&
	       ((ip4_header_t *) vlib_buffer_get_current (root))->ttl == 64,
	     "leave canonical IPv4 root unchanged after COW failure");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  if (frame)
    vlib_frame_free (vm, frame);
  if (pending_len < vec_len (vm->node_main.pending_frames))
    pmtu_shared_view_discard_pending (vm, pending_len);
  else if (descriptor)
    vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_pmtu_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!pmtu_shared_view_success_test (vm, "ip4-pmtu-dpo", DPO_PROTO_IP4) ||
      !pmtu_shared_view_success_test (vm, "ip6-pmtu-dpo", DPO_PROTO_IP6) ||
      !pmtu_shared_view_failure_test (vm))
    return clib_error_return (0, "PMTU shared-view test failed");
  return 0;
}

VLIB_CLI_COMMAND (test_pmtu_shared_view_command, static) = {
  .path = "test pmtu-shared-view",
  .short_help = "test pmtu-shared-view",
  .function = test_pmtu_shared_view_fn,
};
