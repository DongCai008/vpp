/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/adj/adj_internal.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>

#define IP_REWRITE_TEST(_cond, _comment)                                                           \
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
ip_rewrite_shared_view_dispatch (vlib_main_t *vm, const char *node_name, u32 buffer_index,
				 u32 *forwarded_index)
{
  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) node_name);
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

static adj_index_t ip_rewrite_shared_view_adj[2] = { ADJ_INDEX_INVALID, ADJ_INDEX_INVALID };

static adj_index_t
ip_rewrite_shared_view_get_adj (fib_protocol_t proto)
{
  adj_index_t *adj_index = &ip_rewrite_shared_view_adj[proto == FIB_PROTOCOL_IP6];
  ip_adjacency_t *adj;

  if (*adj_index != ADJ_INDEX_INVALID)
    return *adj_index;

  adj = adj_alloc (proto);
  clib_memset (&adj->rewrite_header, 0, sizeof (adj->rewrite_header));
  adj->rewrite_header.max_l3_packet_bytes = ~0;
  *adj_index = adj_get_index (adj);
  return *adj_index;
}

static void
ip_rewrite_shared_view_init_ip4 (vlib_buffer_t *buffer)
{
  ip4_header_t *ip = vlib_buffer_get_current (buffer);

  clib_memset (ip, 0, sizeof (*ip));
  ip->ip_version_and_header_length = 0x45;
  ip->length = clib_host_to_net_u16 (sizeof (*ip));
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->checksum = ip4_header_checksum (ip);
  buffer->current_length = sizeof (*ip);
}

static void
ip_rewrite_shared_view_init_ip6 (vlib_buffer_t *buffer)
{
  ip6_header_t *ip = vlib_buffer_get_current (buffer);

  clib_memset (ip, 0, sizeof (*ip));
  ip->payload_length = 0;
  ip->hop_limit = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  buffer->current_length = sizeof (*ip);
}

static int
ip_rewrite_shared_view_success_test (vlib_main_t *vm, const char *node_name, bool is_ip6)
{
  vlib_buffer_t *root;
  vlib_buffer_t *forwarded;
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
  if (is_ip6)
    {
      ip_rewrite_shared_view_init_ip6 (root);
      vnet_buffer (root)->ip.adj_index[VLIB_TX] = ip_rewrite_shared_view_get_adj (FIB_PROTOCOL_IP6);
    }
  else
    {
      ip_rewrite_shared_view_init_ip4 (root);
      vnet_buffer (root)->ip.adj_index[VLIB_TX] = ip_rewrite_shared_view_get_adj (FIB_PROTOCOL_IP4);
    }

  IP_REWRITE_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
		   "attach rewrite shared-view descriptor");
  IP_REWRITE_TEST (vlib_get_buffer (vm, buffers[1])->current_length == 0,
		   "use headerless rewrite descriptor");
  IP_REWRITE_TEST (ip_rewrite_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index) ==
		     0,
		   "dispatch rewrite shared-view descriptor");
  IP_REWRITE_TEST (forwarded_index != buffers[1], "replace rewrite descriptor frame slot");
  forwarded = vlib_get_buffer (vm, forwarded_index);
  IP_REWRITE_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
		   "forward ordinary replacement after rewrite COW");

  if (is_ip6)
    {
      ((ip6_header_t *) vlib_buffer_get_current (forwarded))->hop_limit = 1;
      IP_REWRITE_TEST (((ip6_header_t *) vlib_buffer_get_current (root))->hop_limit == 64,
		       "leave canonical IPv6 root unchanged");
    }
  else
    {
      ((ip4_header_t *) vlib_buffer_get_current (forwarded))->ttl = 1;
      IP_REWRITE_TEST (((ip4_header_t *) vlib_buffer_get_current (root))->ttl == 64,
		       "leave canonical IPv4 root unchanged");
    }
  ret = 1;

done:
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
ip_rewrite_shared_view_failure_test (vlib_main_t *vm, const char *node_name, bool is_ip6)
{
  vlib_buffer_t *descriptor = 0;
  vlib_buffer_t *root;
  vlib_node_t *node;
  u32 buffers[2];
  u32 descriptor_next = 0;
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
  if (is_ip6)
    ip_rewrite_shared_view_init_ip6 (root);
  else
    ip_rewrite_shared_view_init_ip4 (root);
  IP_REWRITE_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
		   "attach malformed rewrite descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  IP_REWRITE_TEST (ip_rewrite_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index) ==
		     0,
		   "dispatch malformed rewrite descriptor");
  descriptor->next_buffer = descriptor_next;
  IP_REWRITE_TEST (forwarded_index == buffers[1], "retain rewrite input after COW failure");

  node = vlib_get_node_by_name (vm, (u8 *) (is_ip6 ? "ip6-input" : "ip4-input"));
  IP_REWRITE_TEST (node != 0, "find rewrite COW-failure error node");
  IP_REWRITE_TEST (
    descriptor->error ==
      vlib_node_get_runtime (vm, node->index)
	->errors[is_ip6 ? IP6_ERROR_REWRITE_NO_BUFFERS : IP4_ERROR_REWRITE_NO_BUFFERS],
    "send rewrite COW failure to no-buffers drop");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_ip_rewrite_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!ip_rewrite_shared_view_success_test (vm, "ip4-rewrite", 0) ||
      !ip_rewrite_shared_view_success_test (vm, "ip6-rewrite", 1) ||
      !ip_rewrite_shared_view_failure_test (vm, "ip4-rewrite", 0) ||
      !ip_rewrite_shared_view_failure_test (vm, "ip6-rewrite", 1))
    return clib_error_return (0, "IP rewrite shared-view test failed");
  return 0;
}

VLIB_CLI_COMMAND (test_ip_rewrite_shared_view_command, static) = {
  .path = "test ip-rewrite-shared-view",
  .short_help = "test ip-rewrite-shared-view",
  .function = test_ip_rewrite_shared_view_fn,
};
