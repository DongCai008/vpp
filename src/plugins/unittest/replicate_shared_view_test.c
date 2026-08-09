/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/dpo/replicate_dpo.h>

#define REPLICATE_SHARED_VIEW_TEST(_cond, _comment)                                                \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	{                                                                                          \
	  fformat (stderr, "FAIL:%d: %s\\n", __LINE__, _comment);                                  \
	  goto done;                                                                               \
	}                                                                                          \
    }                                                                                              \
  while (0)

typedef struct
{
  u32 node_index;
  index_t dpo_index;
} replicate_shared_view_trace_t;

static replicate_shared_view_trace_t replicate_shared_view_traces[2];
static u8 replicate_shared_view_trace_data[2][sizeof (replicate_shared_view_trace_t)];
static u32 replicate_shared_view_trace_count;

VLIB_NODE_FN (replicate_shared_view_bucket0_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) { return frame->n_vectors; }

VLIB_REGISTER_NODE (replicate_shared_view_bucket0_node) = {
  .name = "replicate-shared-view-bucket-0",
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (replicate_shared_view_bucket1_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) { return frame->n_vectors; }

VLIB_REGISTER_NODE (replicate_shared_view_bucket1_node) = {
  .name = "replicate-shared-view-bucket-1",
  .vector_size = sizeof (u32),
};

static void *
replicate_shared_view_add_trace (struct vlib_main_t *vm, struct vlib_node_runtime_t *runtime,
				 struct vlib_buffer_t *buffer, u32 n_data_bytes)
{
  replicate_shared_view_trace_t *trace;
  vlib_buffer_t *buffer0 = (void *) buffer;
  vlib_node_runtime_t *node = (void *) runtime;

  CLIB_UNUSED (vlib_main_t * vm0) = (void *) vm;
  ASSERT (n_data_bytes == sizeof (replicate_shared_view_trace_t));
  ASSERT (replicate_shared_view_trace_count < ARRAY_LEN (replicate_shared_view_traces));
  trace = &replicate_shared_view_traces[replicate_shared_view_trace_count];
  trace->node_index = node->node_index;
  trace->dpo_index = vnet_buffer (buffer0)->ip.adj_index[VLIB_TX];
  return replicate_shared_view_trace_data[replicate_shared_view_trace_count++];
}

static void
replicate_shared_view_clear_pending (vlib_main_t *vm, u32 pending_len)
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
replicate_shared_view_dispatch (vlib_main_t *vm, const char *node_name, u32 buffer_index,
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

  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  if (node == 0)
    return -1;
  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  if (frame == 0)
    return -1;

  pending_len = vec_len (vm->node_main.pending_frames);
  *n_forwarded = 0;
  ((u32 *) vlib_frame_vector_args (frame))[0] = buffer_index;
  frame->n_vectors = 1;
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
  replicate_shared_view_clear_pending (vm, pending_len);
  vlib_frame_free (vm, frame);
  return ret;
}

static index_t
replicate_shared_view_create (vlib_main_t *vm, const char *node_name, dpo_proto_t proto,
			      u32 *bucket0_next, u32 *bucket1_next)
{
  dpo_id_t drop = DPO_INVALID;
  dpo_id_t *buckets;
  index_t repi;
  vlib_node_t *node;

  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  if (node == 0)
    return INDEX_INVALID;
  repi = replicate_create (2, proto);
  dpo_set (&drop, DPO_DROP, proto, proto);
  replicate_set_bucket (repi, 0, &drop);
  replicate_set_bucket (repi, 1, &drop);
  dpo_reset (&drop);

  buckets = replicate_get (repi)->rep_buckets_inline;
  *bucket0_next = vlib_node_add_next (vm, node->index, replicate_shared_view_bucket0_node.index);
  *bucket1_next = vlib_node_add_next (vm, node->index, replicate_shared_view_bucket1_node.index);
  buckets[0].dpoi_next_node = *bucket0_next;
  buckets[1].dpoi_next_node = *bucket1_next;
  buckets[0].dpoi_index = 0x5100;
  buckets[1].dpoi_index = 0x5101;
  return repi;
}

static void
replicate_shared_view_destroy (index_t repi, dpo_proto_t proto)
{
  dpo_id_t dpo = DPO_INVALID;

  dpo_set (&dpo, DPO_REPLICATE, proto, repi);
  dpo_reset (&dpo);
}

static int
replicate_shared_view_success_test (vlib_main_t *vm, const char *node_name, dpo_proto_t proto)
{
  vlib_add_trace_callback_t *saved_add_trace_callback = 0;
  vlib_buffer_t *root;
  vlib_buffer_t *forwarded;
  vlib_node_t *bucket0_node;
  vlib_node_t *bucket1_node;
  index_t repi = INDEX_INVALID;
  u32 buffers[2];
  u32 forwarded_indices[2] = { ~0, ~0 };
  u32 forwarded_runtime_indices[2] = { ~0, ~0 };
  u32 bucket0_next;
  u32 bucket1_next;
  u32 n_alloc;
  u32 n_forwarded = 0;
  u8 saw_bucket0 = 0;
  u8 saw_bucket1 = 0;
  u32 i;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }
  repi = replicate_shared_view_create (vm, node_name, proto, &bucket0_next, &bucket1_next);
  REPLICATE_SHARED_VIEW_TEST (repi != INDEX_INVALID, "create replicate DPO");
  root = vlib_get_buffer (vm, buffers[0]);
  root->current_length = 1;
  root->data[0] = 0x5a;
  root->flags |= VLIB_BUFFER_IS_TRACED;
  REPLICATE_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			      "attach replicate shared-view descriptor");
  REPLICATE_SHARED_VIEW_TEST (vlib_get_buffer (vm, buffers[1])->current_length == 0,
			      "use headerless replicate descriptor");
  vnet_buffer (vlib_get_buffer (vm, buffers[1]))->ip.adj_index[VLIB_TX] = repi;
  vlib_get_buffer (vm, buffers[1])->flags |= VLIB_BUFFER_IS_TRACED;

  replicate_shared_view_trace_count = 0;
  clib_memset (replicate_shared_view_traces, 0, sizeof (replicate_shared_view_traces));
  saved_add_trace_callback = vm->trace_main.add_trace_callback;
  vm->trace_main.add_trace_callback = replicate_shared_view_add_trace;
  REPLICATE_SHARED_VIEW_TEST (
    replicate_shared_view_dispatch (vm, node_name, buffers[1], forwarded_indices,
				    forwarded_runtime_indices, ARRAY_LEN (forwarded_indices),
				    &n_forwarded) == 0,
    "dispatch replicate shared-view descriptor");
  vm->trace_main.add_trace_callback = saved_add_trace_callback;

  bucket0_node = vlib_get_node_by_name (vm, (u8 *) "replicate-shared-view-bucket-0");
  bucket1_node = vlib_get_node_by_name (vm, (u8 *) "replicate-shared-view-bucket-1");
  REPLICATE_SHARED_VIEW_TEST (bucket0_node && bucket1_node, "find bucket nodes");
  REPLICATE_SHARED_VIEW_TEST (n_forwarded == 2, "replicate both DPO buckets");
  for (i = 0; i < n_forwarded; i++)
    {
      forwarded = vlib_get_buffer (vm, forwarded_indices[i]);
      REPLICATE_SHARED_VIEW_TEST (forwarded_indices[i] != buffers[1],
				  "replace replicate descriptor input slot");
      REPLICATE_SHARED_VIEW_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
				  "forward ordinary replicate bucket");
      if (forwarded_runtime_indices[i] == bucket0_node->runtime_index)
	{
	  REPLICATE_SHARED_VIEW_TEST (vnet_buffer (forwarded)->ip.adj_index[VLIB_TX] == 0x5100,
				      "preserve bucket-zero DPO metadata");
	  saw_bucket0 = 1;
	}
      else if (forwarded_runtime_indices[i] == bucket1_node->runtime_index)
	{
	  REPLICATE_SHARED_VIEW_TEST (vnet_buffer (forwarded)->ip.adj_index[VLIB_TX] == 0x5101,
				      "preserve bucket-one DPO metadata");
	  saw_bucket1 = 1;
	}
      else
	REPLICATE_SHARED_VIEW_TEST (0, "route each bucket through its DPO edge");
      ((u8 *) vlib_buffer_get_current (forwarded))[0] = 0xa0 + i;
    }
  REPLICATE_SHARED_VIEW_TEST (saw_bucket0 && saw_bucket1, "route every replicate bucket");
  REPLICATE_SHARED_VIEW_TEST (root->data[0] == 0x5a, "leave canonical replicate root unchanged");
  REPLICATE_SHARED_VIEW_TEST (replicate_shared_view_trace_count == 2,
			      "trace every replicate bucket");
  for (i = 0; i < replicate_shared_view_trace_count; i++)
    REPLICATE_SHARED_VIEW_TEST (replicate_shared_view_traces[i].node_index ==
				    vlib_get_node_by_name (vm, (u8 *) node_name)->index &&
				  (replicate_shared_view_traces[i].dpo_index == 0x5100 ||
				   replicate_shared_view_traces[i].dpo_index == 0x5101),
				"preserve replicate DPO trace metadata");
  ret = 1;

done:
  if (vm->trace_main.add_trace_callback == replicate_shared_view_add_trace)
    vm->trace_main.add_trace_callback = saved_add_trace_callback;
  for (i = 0; i < n_forwarded; i++)
    vlib_buffer_free_one (vm, forwarded_indices[i]);
  if (!n_forwarded)
    vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  if (repi != INDEX_INVALID)
    replicate_shared_view_destroy (repi, proto);
  return ret;
}

static int
replicate_shared_view_failure_test (vlib_main_t *vm, const char *node_name, dpo_proto_t proto)
{
  vlib_buffer_t *descriptor = 0;
  vlib_node_t *drop_node;
  vlib_node_t *node;
  index_t repi = INDEX_INVALID;
  u32 buffers[2];
  u32 forwarded_indices[1] = { ~0 };
  u32 forwarded_runtime_indices[1] = { ~0 };
  u32 bucket0_next;
  u32 bucket1_next;
  u32 descriptor_next = 0;
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
  repi = replicate_shared_view_create (vm, node_name, proto, &bucket0_next, &bucket1_next);
  REPLICATE_SHARED_VIEW_TEST (repi != INDEX_INVALID, "create failure replicate DPO");
  vlib_get_buffer (vm, buffers[0])->current_length = 1;
  REPLICATE_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			      "attach malformed replicate descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  vnet_buffer (descriptor)->ip.adj_index[VLIB_TX] = repi;
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  REPLICATE_SHARED_VIEW_TEST (
    replicate_shared_view_dispatch (vm, node_name, buffers[1], forwarded_indices,
				    forwarded_runtime_indices, ARRAY_LEN (forwarded_indices),
				    &n_forwarded) == 0,
    "dispatch malformed replicate descriptor");
  descriptor->next_buffer = descriptor_next;
  REPLICATE_SHARED_VIEW_TEST (n_forwarded == 1 && forwarded_indices[0] == buffers[1],
			      "retain replicate descriptor after COW failure");
  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  drop_node = vlib_get_node_by_name (vm, (u8 *) (proto == DPO_PROTO_IP4 ? "ip4-drop" :
						 proto == DPO_PROTO_IP6 ? "ip6-drop" :
									  "mpls-drop"));
  REPLICATE_SHARED_VIEW_TEST (node && drop_node, "find replicate COW failure route");
  REPLICATE_SHARED_VIEW_TEST (forwarded_runtime_indices[0] == drop_node->runtime_index,
			      "send replicate COW failure to family drop");
  REPLICATE_SHARED_VIEW_TEST (
    descriptor->error == vlib_node_get_runtime (vm, node->index)->errors[1] &&
      descriptor->error != vlib_node_get_runtime (vm, node->index)->errors[0],
    "account replicate COW failure separately from clone allocation failure");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  vlib_buffer_free_one (vm, n_forwarded ? forwarded_indices[0] : buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  if (repi != INDEX_INVALID)
    replicate_shared_view_destroy (repi, proto);
  return ret;
}

static clib_error_t *
test_replicate_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!replicate_shared_view_success_test (vm, "ip4-replicate", DPO_PROTO_IP4) ||
      !replicate_shared_view_success_test (vm, "ip6-replicate", DPO_PROTO_IP6) ||
      !replicate_shared_view_success_test (vm, "mpls-replicate", DPO_PROTO_MPLS) ||
      !replicate_shared_view_failure_test (vm, "ip4-replicate", DPO_PROTO_IP4) ||
      !replicate_shared_view_failure_test (vm, "ip6-replicate", DPO_PROTO_IP6) ||
      !replicate_shared_view_failure_test (vm, "mpls-replicate", DPO_PROTO_MPLS))
    return clib_error_return (0, "replicate shared-view test failed");
  return 0;
}

VLIB_CLI_COMMAND (test_replicate_shared_view_command, static) = {
  .path = "test replicate-shared-view",
  .short_help = "test replicate-shared-view",
  .function = test_replicate_shared_view_fn,
};
