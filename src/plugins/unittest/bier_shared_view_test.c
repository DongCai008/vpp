/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/bier/bier_bit_string.h>
#include <vnet/bier/bier_fmask.h>
#include <vnet/bier/bier_hdr_inlines.h>
#include <vnet/bier/bier_table.h>

#define BIER_SHARED_VIEW_TEST(_cond, _comment)                                                     \
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
  index_t bti;
  index_t bfmi;
} bier_shared_view_trace_t;

typedef struct
{
  index_t bti;
  index_t bfmis[2];
} bier_shared_view_topology_t;

static bier_shared_view_trace_t bier_shared_view_traces[2];
static u32 bier_shared_view_trace_count;

static void *
bier_shared_view_add_trace (struct vlib_main_t *vm, struct vlib_node_runtime_t *runtime,
			    struct vlib_buffer_t *buffer, u32 n_data_bytes)
{
  bier_shared_view_trace_t *trace;
  vlib_node_runtime_t *node = (void *) runtime;

  CLIB_UNUSED (vlib_main_t * vm0) = (void *) vm;
  CLIB_UNUSED (vlib_buffer_t * buffer0) = (void *) buffer;
  ASSERT (n_data_bytes == sizeof (bier_shared_view_trace_t));
  ASSERT (bier_shared_view_trace_count < ARRAY_LEN (bier_shared_view_traces));
  trace = &bier_shared_view_traces[bier_shared_view_trace_count];
  trace->node_index = node->node_index;
  bier_shared_view_trace_count++;
  return trace;
}

static void
bier_shared_view_clear_pending (vlib_main_t *vm, u32 pending_len)
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
bier_shared_view_dispatch (vlib_main_t *vm, u32 buffer_index, u32 *forwarded_indices,
			   u32 *forwarded_runtime_indices, u32 max_forwarded, u32 *n_forwarded)
{
  vlib_node_t *node;
  vlib_node_runtime_t *runtime;
  vlib_pending_frame_t *pending;
  vlib_frame_t *frame;
  u32 pending_len;
  u32 i;
  int ret = -1;

  node = vlib_get_node_by_name (vm, (u8 *) "bier-lookup");
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
  bier_shared_view_clear_pending (vm, pending_len);
  vlib_frame_free (vm, frame);
  return ret;
}

static int
bier_shared_view_topology_create (bier_shared_view_topology_t *topology)
{
  bier_table_t *bt;
  bier_fmask_t *bfm;
  u32 i;

  pool_get_zero (bier_table_pool, bt);
  topology->bti = bt - bier_table_pool;
  bt->bt_id.bti_hdr_len = BIER_HDR_LEN_64;
  bt->bt_id.bti_ecmp = 0;
  vec_validate_init_empty (bt->bt_fmasks, bier_hdr_len_id_to_num_bits (BIER_HDR_LEN_64) - 1,
			   INDEX_INVALID);

  for (i = 0; i < ARRAY_LEN (topology->bfmis); i++)
    {
      pool_get_zero (bier_fmask_pool, bfm);
      topology->bfmis[i] = bfm - bier_fmask_pool;
      bfm->bfm_bits.bfmb_input_reset_string.bbs_len =
	bier_hdr_len_id_to_num_bytes (BIER_HDR_LEN_64);
      vec_validate (bfm->bfm_bits.bfmb_input_reset_string.bbs_buckets,
		    bfm->bfm_bits.bfmb_input_reset_string.bbs_len - 1);
      bt->bt_fmasks[BIER_BP_TO_INDEX (i + 1)] = topology->bfmis[i];
    }
  return 0;
}

static void
bier_shared_view_topology_destroy (bier_shared_view_topology_t *topology)
{
  bier_table_t *bt;
  bier_fmask_t *bfm;
  u32 i;

  for (i = 0; i < ARRAY_LEN (topology->bfmis); i++)
    {
      bfm = bier_fmask_get (topology->bfmis[i]);
      vec_free (bfm->bfm_bits.bfmb_input_reset_string.bbs_buckets);
      pool_put (bier_fmask_pool, bfm);
    }
  bt = bier_table_get (topology->bti);
  vec_free (bt->bt_fmasks);
  pool_put (bier_table_pool, bt);
}

static void
bier_shared_view_init_header (vlib_buffer_t *buffer)
{
  bier_bit_string_t bbs;
  bier_hdr_t *bh;

  buffer->current_length = sizeof (*bh) + bier_hdr_len_id_to_num_bytes (BIER_HDR_LEN_64);
  bh = vlib_buffer_get_current (buffer);
  clib_memset (bh, 0, buffer->current_length);
  bier_hdr_init (bh, BIER_HDR_VERSION_1, BIER_HDR_PROTO_IPV4, BIER_HDR_LEN_64, 0, 0);
  bier_bit_string_init_from_hdr (bh, &bbs);
  bier_bit_string_set_bit (&bbs, 1);
  bier_bit_string_set_bit (&bbs, 2);
}

static int
bier_shared_view_success_test (vlib_main_t *vm)
{
  vlib_add_trace_callback_t *saved_add_trace_callback = 0;
  bier_shared_view_topology_t topology;
  vlib_buffer_t *root;
  vlib_buffer_t *forwarded;
  vlib_node_t *lookup_node;
  vlib_node_t *output_node;
  u32 buffers[2];
  u32 forwarded_indices[2] = { ~0, ~0 };
  u32 forwarded_runtime_indices[2] = { ~0, ~0 };
  u32 n_alloc;
  u32 n_forwarded = 0;
  u8 saw_fmask[2] = {};
  u8 root_first_byte;
  u32 i;
  int ret = 0;

  clib_memset (&topology, 0, sizeof (topology));
  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }
  BIER_SHARED_VIEW_TEST (bier_shared_view_topology_create (&topology) == 0,
			 "create BIER forwarding masks");
  root = vlib_get_buffer (vm, buffers[0]);
  bier_shared_view_init_header (root);
  root_first_byte = ((u8 *) vlib_buffer_get_current (root))[0];
  root->flags |= VLIB_BUFFER_IS_TRACED;
  BIER_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			 "attach BIER shared-view descriptor");
  BIER_SHARED_VIEW_TEST (vlib_get_buffer (vm, buffers[1])->current_length == 0,
			 "use headerless BIER descriptor");
  vnet_buffer (vlib_get_buffer (vm, buffers[1]))->ip.adj_index[VLIB_TX] = topology.bti;

  bier_shared_view_trace_count = 0;
  clib_memset (bier_shared_view_traces, 0, sizeof (bier_shared_view_traces));
  saved_add_trace_callback = vm->trace_main.add_trace_callback;
  vm->trace_main.add_trace_callback = bier_shared_view_add_trace;
  BIER_SHARED_VIEW_TEST (
    bier_shared_view_dispatch (vm, buffers[1], forwarded_indices, forwarded_runtime_indices,
			       ARRAY_LEN (forwarded_indices), &n_forwarded) == 0,
    "dispatch BIER shared-view descriptor");
  vm->trace_main.add_trace_callback = saved_add_trace_callback;

  lookup_node = vlib_get_node_by_name (vm, (u8 *) "bier-lookup");
  output_node = vlib_get_node_by_name (vm, (u8 *) "bier-output");
  BIER_SHARED_VIEW_TEST (lookup_node && output_node, "find BIER forwarding nodes");
  BIER_SHARED_VIEW_TEST (n_forwarded == ARRAY_LEN (forwarded_indices),
			 "forward every BIER forwarding mask");
  for (i = 0; i < n_forwarded; i++)
    {
      forwarded = vlib_get_buffer (vm, forwarded_indices[i]);
      BIER_SHARED_VIEW_TEST (forwarded_indices[i] != buffers[1],
			     "replace BIER descriptor before cloning");
      BIER_SHARED_VIEW_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
			     "forward ordinary BIER clone");
      BIER_SHARED_VIEW_TEST (forwarded_runtime_indices[i] == output_node->runtime_index,
			     "route every clone to BIER output");
      if (vnet_buffer (forwarded)->ip.adj_index[VLIB_TX] == topology.bfmis[0])
	saw_fmask[0] = 1;
      else if (vnet_buffer (forwarded)->ip.adj_index[VLIB_TX] == topology.bfmis[1])
	saw_fmask[1] = 1;
      else
	BIER_SHARED_VIEW_TEST (0, "preserve a forwarding-mask adjacency per clone");
      ((u8 *) vlib_buffer_get_current (forwarded))[0] = 0xa0 + i;
    }
  BIER_SHARED_VIEW_TEST (saw_fmask[0] && saw_fmask[1],
			 "retain both BIER forwarding-mask adjacencies");
  BIER_SHARED_VIEW_TEST (((u8 *) vlib_buffer_get_current (root))[0] == root_first_byte,
			 "leave the canonical BIER root unchanged");
  BIER_SHARED_VIEW_TEST (bier_shared_view_trace_count == ARRAY_LEN (forwarded_indices),
			 "trace every BIER clone");
  for (i = 0; i < bier_shared_view_trace_count; i++)
    BIER_SHARED_VIEW_TEST (bier_shared_view_traces[i].node_index == lookup_node->index &&
			     bier_shared_view_traces[i].bti == topology.bti &&
			     (bier_shared_view_traces[i].bfmi == topology.bfmis[0] ||
			      bier_shared_view_traces[i].bfmi == topology.bfmis[1]),
			   "preserve BIER table and forwarding-mask trace metadata");
  ret = 1;

done:
  if (vm->trace_main.add_trace_callback == bier_shared_view_add_trace)
    vm->trace_main.add_trace_callback = saved_add_trace_callback;
  for (i = 0; i < n_forwarded; i++)
    vlib_buffer_free_one (vm, forwarded_indices[i]);
  if (!n_forwarded)
    vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  bier_shared_view_topology_destroy (&topology);
  return ret;
}

static int
bier_shared_view_failure_test (vlib_main_t *vm)
{
  bier_shared_view_topology_t topology;
  vlib_buffer_t *descriptor = 0;
  vlib_buffer_t *root;
  vlib_node_t *drop_node;
  vlib_node_t *lookup_node;
  vlib_node_runtime_t *lookup_runtime;
  u32 buffers[2];
  u32 forwarded_indices[1] = { ~0 };
  u32 forwarded_runtime_indices[1] = { ~0 };
  u32 saved_next = 0;
  u64 cow_fail_before;
  u32 n_alloc;
  u32 n_forwarded = 0;
  int ret = 0;

  clib_memset (&topology, 0, sizeof (topology));
  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }
  BIER_SHARED_VIEW_TEST (bier_shared_view_topology_create (&topology) == 0,
			 "create BIER COW failure topology");
  root = vlib_get_buffer (vm, buffers[0]);
  bier_shared_view_init_header (root);
  BIER_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			 "attach malformed BIER descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  vnet_buffer (descriptor)->ip.adj_index[VLIB_TX] = topology.bti;
  saved_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  lookup_node = vlib_get_node_by_name (vm, (u8 *) "bier-lookup");
  drop_node = vlib_get_node_by_name (vm, (u8 *) "bier-drop");
  BIER_SHARED_VIEW_TEST (lookup_node && drop_node, "find BIER COW failure route");
  lookup_runtime = vlib_node_get_runtime (vm, lookup_node->index);
  cow_fail_before = vm->error_main.counters[lookup_node->error_heap_index + 3];
  BIER_SHARED_VIEW_TEST (
    bier_shared_view_dispatch (vm, buffers[1], forwarded_indices, forwarded_runtime_indices,
			       ARRAY_LEN (forwarded_indices), &n_forwarded) == 0,
    "dispatch malformed BIER descriptor");
  descriptor->next_buffer = saved_next;
  BIER_SHARED_VIEW_TEST (n_forwarded == 1 && forwarded_indices[0] == buffers[1],
			 "retain BIER descriptor after COW failure");
  BIER_SHARED_VIEW_TEST (forwarded_runtime_indices[0] == drop_node->runtime_index,
			 "send BIER COW failure to BIER drop");
  BIER_SHARED_VIEW_TEST (descriptor->error == lookup_runtime->errors[3] &&
			   descriptor->error != lookup_runtime->errors[2],
			 "account BIER COW failure separately from clone allocation failure");
  BIER_SHARED_VIEW_TEST (vm->error_main.counters[lookup_node->error_heap_index + 3] ==
			   cow_fail_before + 1,
			 "increment the BIER COW failure counter");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = saved_next;
  vlib_buffer_free_one (vm, n_forwarded ? forwarded_indices[0] : buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  bier_shared_view_topology_destroy (&topology);
  return ret;
}

static clib_error_t *
test_bier_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!bier_shared_view_success_test (vm) || !bier_shared_view_failure_test (vm))
    return clib_error_return (0, "BIER shared-view test failed");
  return 0;
}

VLIB_CLI_COMMAND (test_bier_shared_view_command, static) = {
  .path = "test bier-shared-view",
  .short_help = "test bier-shared-view",
  .function = test_bier_shared_view_fn,
};
