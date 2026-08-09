/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/adj/adj_internal.h>
#include <vnet/ip/ip6.h>

#define IP6_HBH_SHARED_VIEW_TEST(_cond, _comment)                                                  \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	{                                                                                          \
	  fformat (stderr, "FAIL:%d: %s\\n", __LINE__, _comment);                                  \
	  goto done;                                                                               \
	}                                                                                          \
    }                                                                                              \
  while (0)

#define IP6_HBH_SHARED_VIEW_OPTION    0xfc
#define IP6_HBH_SHARED_VIEW_OPAQUE2   0x6a5a4a3a
#define IP6_HBH_SHARED_VIEW_FLOW_ID   0x6b5b4b3b
#define IP6_HBH_SHARED_VIEW_CONFIG    0x6c5c4c3c
#define IP6_HBH_SHARED_VIEW_DUAL_PEER 0x6d5d4d3d

/* Keep this in lockstep with foreach_ip6_hop_by_hop_error. */
typedef enum
{
  IP6_HBH_SHARED_VIEW_ERROR_PROCESSED,
  IP6_HBH_SHARED_VIEW_ERROR_FORMAT,
  IP6_HBH_SHARED_VIEW_ERROR_UNKNOWN_OPTION,
  IP6_HBH_SHARED_VIEW_ERROR_NO_BUFFERS,
} ip6_hbh_shared_view_error_t;

typedef struct
{
  u32 flow_id;
  u32 opaque2;
  u32 adj_index;
  u32 current_config_index;
  u32 trace_handle;
} ip6_hbh_shared_view_observation_t;

static ip6_hbh_shared_view_observation_t ip6_hbh_shared_view_callbacks[4];
static ip6_hbh_shared_view_observation_t ip6_hbh_shared_view_traces[4];
static u8 ip6_hbh_shared_view_trace_data[4][264];
static u32 ip6_hbh_shared_view_callback_count;
static u32 ip6_hbh_shared_view_trace_count;
static adj_index_t ip6_hbh_shared_view_adj = ADJ_INDEX_INVALID;

static int
ip6_hbh_shared_view_option (vlib_buffer_t *buffer, ip6_header_t *ip,
			    ip6_hop_by_hop_option_t *option)
{
  ip6_hbh_shared_view_observation_t *observation;

  CLIB_UNUSED (ip6_header_t * ip0) = ip;
  CLIB_UNUSED (ip6_hop_by_hop_option_t * option0) = option;
  if (ip6_hbh_shared_view_callback_count == ARRAY_LEN (ip6_hbh_shared_view_callbacks))
    return -1;

  observation = &ip6_hbh_shared_view_callbacks[ip6_hbh_shared_view_callback_count++];
  observation->flow_id = buffer->flow_id;
  observation->opaque2 = buffer->opaque2[0];
  observation->adj_index = vnet_buffer (buffer)->ip.adj_index[VLIB_TX];
  observation->current_config_index = buffer->current_config_index;
  observation->trace_handle = buffer->trace_handle;
  return 0;
}

static void *
ip6_hbh_shared_view_add_trace (struct vlib_main_t *vm, struct vlib_node_runtime_t *runtime,
			       struct vlib_buffer_t *buffer, u32 n_data_bytes)
{
  ip6_hbh_shared_view_observation_t *observation;
  vlib_buffer_t *buffer0 = (void *) buffer;

  CLIB_UNUSED (vlib_main_t * vm0) = (void *) vm;
  CLIB_UNUSED (vlib_node_runtime_t * runtime0) = (void *) runtime;
  ASSERT (n_data_bytes <= sizeof (ip6_hbh_shared_view_trace_data[0]));
  ASSERT (ip6_hbh_shared_view_trace_count < ARRAY_LEN (ip6_hbh_shared_view_traces));
  observation = &ip6_hbh_shared_view_traces[ip6_hbh_shared_view_trace_count++];
  observation->flow_id = buffer0->flow_id;
  observation->opaque2 = buffer0->opaque2[0];
  observation->adj_index = vnet_buffer (buffer0)->ip.adj_index[VLIB_TX];
  observation->current_config_index = buffer0->current_config_index;
  observation->trace_handle = buffer0->trace_handle;
  return ip6_hbh_shared_view_trace_data[ip6_hbh_shared_view_trace_count - 1];
}

static void
ip6_hbh_shared_view_clear_pending_frames (vlib_main_t *vm, u32 pending_len)
{
  vlib_pending_frame_t *pending;
  u32 i;

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
}

static int
ip6_hbh_shared_view_dispatch (vlib_main_t *vm, u32 *buffer_indices, u32 n_buffers,
			      u32 *forwarded_indices, u32 *forwarded_runtime_indices,
			      u32 max_forwarded, u32 *n_forwarded)
{
  vlib_node_t *node;
  vlib_node_runtime_t *runtime;
  vlib_pending_frame_t *pending;
  vlib_frame_t *frame;
  u32 pending_len;
  u32 i;
  int ret = -1;

  node = vlib_get_node_by_name (vm, (u8 *) "ip6-hop-by-hop");
  if (node == 0 || n_buffers > VLIB_FRAME_SIZE)
    return -1;
  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  if (frame == 0)
    return -1;

  pending_len = vec_len (vm->node_main.pending_frames);
  *n_forwarded = 0;
  clib_memcpy_fast (vlib_frame_vector_args (frame), buffer_indices,
		    n_buffers * sizeof (buffer_indices[0]));
  frame->n_vectors = n_buffers;
  runtime->function (vm, runtime, frame);

  for (i = pending_len; i < vec_len (vm->node_main.pending_frames); i++)
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
  ip6_hbh_shared_view_clear_pending_frames (vm, pending_len);
  vlib_frame_free (vm, frame);
  return ret;
}

static adj_index_t
ip6_hbh_shared_view_get_adj (void)
{
  ip_adjacency_t *adj;

  if (ip6_hbh_shared_view_adj != ADJ_INDEX_INVALID)
    return ip6_hbh_shared_view_adj;
  adj = adj_alloc (FIB_PROTOCOL_IP6);
  clib_memset (&adj->rewrite_header, 0, sizeof (adj->rewrite_header));
  adj->rewrite_header.max_l3_packet_bytes = ~0;
  adj->lookup_next_index = IP_LOOKUP_NEXT_REWRITE;
  ip6_hbh_shared_view_adj = adj_get_index (adj);
  return ip6_hbh_shared_view_adj;
}

static void
ip6_hbh_shared_view_init_packet (vlib_buffer_t *buffer)
{
  ip6_hop_by_hop_header_t *hbh;
  ip6_hop_by_hop_option_t *option;
  ip6_header_t *ip;
  u8 *pad;

  buffer->current_length = sizeof (*ip) + 8;
  ip = vlib_buffer_get_current (buffer);
  clib_memset (ip, 0, buffer->current_length);
  ip->protocol = IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS;
  ip->payload_length = clib_host_to_net_u16 (8);
  ip->hop_limit = 64;
  hbh = (ip6_hop_by_hop_header_t *) (ip + 1);
  hbh->protocol = IP_PROTOCOL_UDP;
  hbh->length = 0;
  option = (ip6_hop_by_hop_option_t *) (hbh + 1);
  option->type = IP6_HBH_SHARED_VIEW_OPTION;
  option->length = 0;
  pad = (u8 *) (option + 1);
  clib_memset (pad, 0, 4);
}

static void
ip6_hbh_shared_view_init_descriptor (vlib_buffer_t *buffer, adj_index_t adj_index)
{
  buffer->flow_id = IP6_HBH_SHARED_VIEW_FLOW_ID;
  buffer->current_config_index = IP6_HBH_SHARED_VIEW_CONFIG;
  buffer->opaque2[0] = IP6_HBH_SHARED_VIEW_OPAQUE2;
  buffer->flags |= VLIB_BUFFER_IS_TRACED;
  buffer->trace_handle = 0x12345678;
  vnet_buffer (buffer)->ip.adj_index[VLIB_TX] = adj_index;
}

static int
ip6_hbh_shared_view_observation_is_valid (ip6_hbh_shared_view_observation_t *observation,
					  adj_index_t adj_index)
{
  return observation->flow_id == IP6_HBH_SHARED_VIEW_FLOW_ID &&
	 observation->opaque2 == IP6_HBH_SHARED_VIEW_OPAQUE2 &&
	 observation->adj_index == adj_index &&
	 observation->current_config_index == IP6_HBH_SHARED_VIEW_CONFIG &&
	 observation->trace_handle == 0x12345678;
}

static int
ip6_hbh_shared_view_success_test (vlib_main_t *vm, u32 n_packets)
{
  vlib_add_trace_callback_t *saved_add_trace_callback = 0;
  vlib_buffer_t *root;
  vlib_buffer_t *forwarded;
  vlib_node_t *hbh_node = 0;
  vlib_node_t *rewrite_node;
  vlib_node_runtime_t *runtime;
  adj_index_t adj_index;
  u32 buffers[8];
  u32 descriptor_indices[4] = { ~0, ~0, ~0, ~0 };
  u32 forwarded_indices[4] = { ~0, ~0, ~0, ~0 };
  u32 forwarded_runtime_indices[4] = { ~0, ~0, ~0, ~0 };
  u32 n_alloc;
  u32 n_forwarded = 0;
  u32 saved_flags = 0;
  u8 runtime_trace_enabled = 0;
  u8 trace_callback_replaced = 0;
  u32 i;
  int ret = 0;

  if (n_packets > ARRAY_LEN (descriptor_indices))
    return 0;
  n_alloc = vlib_buffer_alloc (vm, buffers, n_packets * 2);
  if (n_alloc != n_packets * 2)
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }
  adj_index = ip6_hbh_shared_view_get_adj ();
  for (i = 0; i < n_packets; i++)
    {
      root = vlib_get_buffer (vm, buffers[2 * i]);
      ip6_hbh_shared_view_init_packet (root);
      descriptor_indices[i] = buffers[2 * i + 1];
      IP6_HBH_SHARED_VIEW_TEST (
	vlib_buffer_shared_view_attach (vm, descriptor_indices[i], buffers[2 * i]) == 0,
	"attach IPv6 HBH shared-view descriptor");
      IP6_HBH_SHARED_VIEW_TEST (vlib_get_buffer (vm, descriptor_indices[i])->current_length == 0,
				"use headerless IPv6 HBH descriptor");
      ip6_hbh_shared_view_init_descriptor (vlib_get_buffer (vm, descriptor_indices[i]), adj_index);
    }

  hbh_node = vlib_get_node_by_name (vm, (u8 *) "ip6-hop-by-hop");
  rewrite_node = vlib_get_node_by_name (vm, (u8 *) "ip6-rewrite");
  IP6_HBH_SHARED_VIEW_TEST (hbh_node && rewrite_node, "find IPv6 HBH continuation nodes");
  runtime = vlib_node_get_runtime (vm, hbh_node->index);
  saved_flags = runtime->flags;
  runtime->flags |= VLIB_NODE_FLAG_TRACE;
  runtime_trace_enabled = 1;
  ip6_hbh_shared_view_callback_count = 0;
  ip6_hbh_shared_view_trace_count = 0;
  clib_memset (ip6_hbh_shared_view_callbacks, 0, sizeof (ip6_hbh_shared_view_callbacks));
  clib_memset (ip6_hbh_shared_view_traces, 0, sizeof (ip6_hbh_shared_view_traces));
  clib_memset (ip6_hbh_shared_view_trace_data, 0, sizeof (ip6_hbh_shared_view_trace_data));
  saved_add_trace_callback = vm->trace_main.add_trace_callback;
  vm->trace_main.add_trace_callback = ip6_hbh_shared_view_add_trace;
  trace_callback_replaced = 1;
  IP6_HBH_SHARED_VIEW_TEST (
    ip6_hbh_shared_view_dispatch (vm, descriptor_indices, n_packets, forwarded_indices,
				  forwarded_runtime_indices, ARRAY_LEN (forwarded_indices),
				  &n_forwarded) == 0,
    "dispatch IPv6 HBH shared-view descriptors");
  vm->trace_main.add_trace_callback = saved_add_trace_callback;
  trace_callback_replaced = 0;
  runtime->flags = saved_flags;
  runtime_trace_enabled = 0;

  IP6_HBH_SHARED_VIEW_TEST (n_forwarded == n_packets,
			    "forward every IPv6 HBH shared-view descriptor");
  IP6_HBH_SHARED_VIEW_TEST (ip6_hbh_shared_view_callback_count == n_packets,
			    "deliver every non-IOAM option callback");
  IP6_HBH_SHARED_VIEW_TEST (ip6_hbh_shared_view_trace_count == n_packets,
			    "preserve descriptor trace state through COW");
  for (i = 0; i < n_packets; i++)
    {
      forwarded = vlib_get_buffer (vm, forwarded_indices[i]);
      IP6_HBH_SHARED_VIEW_TEST (forwarded_indices[i] != descriptor_indices[i],
				"replace the IPv6 HBH frame slot");
      IP6_HBH_SHARED_VIEW_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
				"forward an ordinary IPv6 HBH replacement");
      IP6_HBH_SHARED_VIEW_TEST (forwarded_runtime_indices[i] == rewrite_node->runtime_index,
				"continue non-IOAM HBH traffic to rewrite");
      IP6_HBH_SHARED_VIEW_TEST (
	ip6_hbh_shared_view_observation_is_valid (&ip6_hbh_shared_view_callbacks[i], adj_index),
	"preserve descriptor metadata for the option callback");
      IP6_HBH_SHARED_VIEW_TEST (
	ip6_hbh_shared_view_observation_is_valid (&ip6_hbh_shared_view_traces[i], adj_index),
	"preserve descriptor metadata for the HBH trace");
      IP6_HBH_SHARED_VIEW_TEST (forwarded->flow_id == IP6_HBH_SHARED_VIEW_FLOW_ID &&
				  forwarded->opaque2[0] == IP6_HBH_SHARED_VIEW_OPAQUE2 &&
				  forwarded->current_config_index == IP6_HBH_SHARED_VIEW_CONFIG &&
				  vnet_buffer (forwarded)->ip.adj_index[VLIB_TX] == adj_index,
				"preserve descriptor metadata for forwarding");
    }
  ((ip6_header_t *) vlib_buffer_get_current (vlib_get_buffer (vm, forwarded_indices[0])))
    ->hop_limit = 1;
  IP6_HBH_SHARED_VIEW_TEST (
    ((ip6_header_t *) vlib_buffer_get_current (vlib_get_buffer (vm, buffers[0])))->hop_limit == 64,
    "leave the canonical IPv6 HBH root unchanged");
  ret = 1;

done:
  if (trace_callback_replaced)
    vm->trace_main.add_trace_callback = saved_add_trace_callback;
  if (runtime_trace_enabled && hbh_node)
    vlib_node_get_runtime (vm, hbh_node->index)->flags = saved_flags;
  for (i = 0; i < n_packets; i++)
    {
      if (forwarded_indices[i] != ~0)
	vlib_buffer_free_one (vm, forwarded_indices[i]);
      else if (descriptor_indices[i] != ~0)
	vlib_buffer_free_one (vm, descriptor_indices[i]);
      vlib_buffer_free_one (vm, buffers[2 * i]);
    }
  return ret;
}

static int
ip6_hbh_shared_view_mixed_failure_test (vlib_main_t *vm)
{
  vlib_add_trace_callback_t *saved_add_trace_callback = 0;
  vlib_buffer_t *descriptor;
  vlib_node_t *drop_node = 0;
  vlib_node_t *hbh_node = 0;
  vlib_node_t *rewrite_node = 0;
  vlib_node_runtime_t *runtime;
  adj_index_t adj_index;
  u32 buffers[8];
  u32 descriptor_indices[4];
  u32 forwarded_indices[4] = { ~0, ~0, ~0, ~0 };
  u32 forwarded_runtime_indices[4] = { ~0, ~0, ~0, ~0 };
  u32 descriptor_next = 0;
  u32 n_alloc;
  u32 n_forwarded = 0;
  u32 saved_flags = 0;
  u8 runtime_trace_enabled = 0;
  u8 trace_callback_replaced = 0;
  u8 dispatched = 0;
  u8 saw_failed_descriptor = 0;
  u8 saw_valid_peer = 0;
  u32 i;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }
  adj_index = ip6_hbh_shared_view_get_adj ();
  for (i = 0; i < ARRAY_LEN (descriptor_indices); i++)
    {
      ip6_hbh_shared_view_init_packet (vlib_get_buffer (vm, buffers[2 * i]));
      descriptor_indices[i] = buffers[2 * i + 1];
      IP6_HBH_SHARED_VIEW_TEST (
	vlib_buffer_shared_view_attach (vm, descriptor_indices[i], buffers[2 * i]) == 0,
	"attach mixed IPv6 HBH shared-view descriptor");
      ip6_hbh_shared_view_init_descriptor (vlib_get_buffer (vm, descriptor_indices[i]), adj_index);
    }
  descriptor = vlib_get_buffer (vm, descriptor_indices[0]);
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = descriptor_indices[0];
  vlib_get_buffer (vm, descriptor_indices[1])->opaque2[1] = IP6_HBH_SHARED_VIEW_DUAL_PEER;

  hbh_node = vlib_get_node_by_name (vm, (u8 *) "ip6-hop-by-hop");
  rewrite_node = vlib_get_node_by_name (vm, (u8 *) "ip6-rewrite");
  drop_node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  IP6_HBH_SHARED_VIEW_TEST (hbh_node && rewrite_node && drop_node,
			    "find mixed IPv6 HBH continuation nodes");
  runtime = vlib_node_get_runtime (vm, hbh_node->index);
  saved_flags = runtime->flags;
  runtime->flags |= VLIB_NODE_FLAG_TRACE;
  runtime_trace_enabled = 1;
  ip6_hbh_shared_view_callback_count = 0;
  ip6_hbh_shared_view_trace_count = 0;
  clib_memset (ip6_hbh_shared_view_callbacks, 0, sizeof (ip6_hbh_shared_view_callbacks));
  clib_memset (ip6_hbh_shared_view_traces, 0, sizeof (ip6_hbh_shared_view_traces));
  clib_memset (ip6_hbh_shared_view_trace_data, 0, sizeof (ip6_hbh_shared_view_trace_data));
  saved_add_trace_callback = vm->trace_main.add_trace_callback;
  vm->trace_main.add_trace_callback = ip6_hbh_shared_view_add_trace;
  trace_callback_replaced = 1;
  IP6_HBH_SHARED_VIEW_TEST (
    ip6_hbh_shared_view_dispatch (vm, descriptor_indices, ARRAY_LEN (descriptor_indices),
				  forwarded_indices, forwarded_runtime_indices,
				  ARRAY_LEN (forwarded_indices), &n_forwarded) == 0,
    "dispatch mixed IPv6 HBH shared-view descriptors");
  dispatched = 1;
  vm->trace_main.add_trace_callback = saved_add_trace_callback;
  trace_callback_replaced = 0;
  runtime->flags = saved_flags;
  runtime_trace_enabled = 0;
  descriptor->next_buffer = descriptor_next;

  IP6_HBH_SHARED_VIEW_TEST (n_forwarded == ARRAY_LEN (forwarded_indices),
			    "forward every mixed IPv6 HBH descriptor");
  IP6_HBH_SHARED_VIEW_TEST (ip6_hbh_shared_view_callback_count == 3,
			    "call every valid mixed-frame option handler");
  IP6_HBH_SHARED_VIEW_TEST (ip6_hbh_shared_view_trace_count == 3,
			    "trace every valid mixed-frame descriptor");
  IP6_HBH_SHARED_VIEW_TEST (
    ip6_hbh_shared_view_observation_is_valid (&ip6_hbh_shared_view_callbacks[0], adj_index) &&
      ip6_hbh_shared_view_observation_is_valid (&ip6_hbh_shared_view_traces[0], adj_index),
    "preserve metadata for the valid dual peer");
  for (i = 0; i < n_forwarded; i++)
    {
      descriptor = vlib_get_buffer (vm, forwarded_indices[i]);
      if (forwarded_indices[i] == descriptor_indices[0])
	{
	  IP6_HBH_SHARED_VIEW_TEST (forwarded_runtime_indices[i] == drop_node->runtime_index,
				    "drop only the malformed dual descriptor");
	  IP6_HBH_SHARED_VIEW_TEST (descriptor->error ==
				      vlib_node_get_runtime (vm, hbh_node->index)
					->errors[IP6_HBH_SHARED_VIEW_ERROR_NO_BUFFERS],
				    "account the malformed dual descriptor as no buffers");
	  saw_failed_descriptor = 1;
	}
      else if (descriptor->opaque2[1] == IP6_HBH_SHARED_VIEW_DUAL_PEER)
	{
	  IP6_HBH_SHARED_VIEW_TEST (forwarded_runtime_indices[i] == rewrite_node->runtime_index,
				    "continue the valid dual peer after the failed COW");
	  saw_valid_peer = 1;
	}
    }
  IP6_HBH_SHARED_VIEW_TEST (saw_failed_descriptor,
			    "retain the malformed dual descriptor for error-drop");
  IP6_HBH_SHARED_VIEW_TEST (saw_valid_peer, "identify the valid dual peer after the failed COW");
  ret = 1;

done:
  if (trace_callback_replaced)
    vm->trace_main.add_trace_callback = saved_add_trace_callback;
  if (runtime_trace_enabled && hbh_node)
    vlib_node_get_runtime (vm, hbh_node->index)->flags = saved_flags;
  if (descriptor_next)
    vlib_get_buffer (vm, descriptor_indices[0])->next_buffer = descriptor_next;
  if (dispatched)
    {
      for (i = 0; i < n_forwarded; i++)
	vlib_buffer_free_one (vm, forwarded_indices[i]);
    }
  else
    {
      for (i = 0; i < ARRAY_LEN (descriptor_indices); i++)
	vlib_buffer_free_one (vm, descriptor_indices[i]);
    }
  for (i = 0; i < ARRAY_LEN (descriptor_indices); i++)
    {
      vlib_buffer_free_one (vm, buffers[2 * i]);
    }
  return ret;
}

static int
ip6_hbh_shared_view_failure_test (vlib_main_t *vm)
{
  vlib_buffer_t *descriptor = 0;
  vlib_node_t *drop_node;
  vlib_node_t *hbh_node;
  u32 buffers[2];
  u32 descriptor_next = 0;
  u32 forwarded_index = ~0;
  u32 forwarded_runtime_index = ~0;
  u32 n_alloc;
  u32 n_forwarded = 0;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }
  ip6_hbh_shared_view_init_packet (vlib_get_buffer (vm, buffers[0]));
  IP6_HBH_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			    "attach malformed IPv6 HBH shared-view descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  ip6_hbh_shared_view_init_descriptor (descriptor, ip6_hbh_shared_view_get_adj ());
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  IP6_HBH_SHARED_VIEW_TEST (ip6_hbh_shared_view_dispatch (vm, &buffers[1], 1, &forwarded_index,
							  &forwarded_runtime_index, 1,
							  &n_forwarded) == 0,
			    "dispatch malformed IPv6 HBH shared-view descriptor");
  descriptor->next_buffer = descriptor_next;
  drop_node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  hbh_node = vlib_get_node_by_name (vm, (u8 *) "ip6-hop-by-hop");
  IP6_HBH_SHARED_VIEW_TEST (drop_node && hbh_node, "find IPv6 HBH COW-failure route");
  IP6_HBH_SHARED_VIEW_TEST (n_forwarded == 1 && forwarded_index == buffers[1],
			    "retain malformed IPv6 HBH descriptor after COW failure");
  IP6_HBH_SHARED_VIEW_TEST (forwarded_runtime_index == drop_node->runtime_index,
			    "send IPv6 HBH COW failure to drop");
  IP6_HBH_SHARED_VIEW_TEST (
    descriptor->error ==
      vlib_node_get_runtime (vm, hbh_node->index)->errors[IP6_HBH_SHARED_VIEW_ERROR_NO_BUFFERS],
    "account IPv6 HBH COW failure as no buffers");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_ip6_hbh_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  int registered;

  CLIB_UNUSED (unformat_input_t * input0) = input;
  CLIB_UNUSED (vlib_cli_command_t * cmd0) = cmd;
  registered =
    ip6_hbh_register_option (IP6_HBH_SHARED_VIEW_OPTION, ip6_hbh_shared_view_option, 0) == 0;
  if (!registered)
    return clib_error_return (0, "cannot register IPv6 HBH shared-view option");
  if (!ip6_hbh_shared_view_success_test (vm, 4) || !ip6_hbh_shared_view_success_test (vm, 1) ||
      !ip6_hbh_shared_view_mixed_failure_test (vm) || !ip6_hbh_shared_view_failure_test (vm))
    {
      ip6_hbh_unregister_option (IP6_HBH_SHARED_VIEW_OPTION);
      return clib_error_return (0, "IPv6 HBH shared-view test failed");
    }
  ip6_hbh_unregister_option (IP6_HBH_SHARED_VIEW_OPTION);
  return 0;
}

VLIB_CLI_COMMAND (test_ip6_hbh_shared_view_command, static) = {
  .path = "test ip6-hbh-shared-view",
  .short_help = "test ip6-hbh-shared-view",
  .function = test_ip6_hbh_shared_view_fn,
};
