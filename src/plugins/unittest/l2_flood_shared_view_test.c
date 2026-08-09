/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/l2/l2_bvi.h>
#include <vnet/l2/l2_input.h>

#define L2FLOOD_SHARED_VIEW_TEST(_cond, _comment)                                                  \
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
  u8 src[6];
  u8 dst[6];
  u32 sw_if_index;
  u16 bd_index;
} l2flood_shared_view_trace_t;

typedef struct
{
  u32 old_bd_configs_len;
  u32 bd_index;
  u32 bvi_sw_if_index;
} l2flood_shared_view_topology_t;

/* Keep this in lockstep with foreach_l2flood_error in l2_flood.c. */
typedef enum
{
  L2FLOOD_SHARED_VIEW_ERROR_L2FLOOD,
  L2FLOOD_SHARED_VIEW_ERROR_COW_FAIL,
  L2FLOOD_SHARED_VIEW_ERROR_REPL_FAIL,
  L2FLOOD_SHARED_VIEW_ERROR_NO_MEMBERS,
  L2FLOOD_SHARED_VIEW_ERROR_BVI_BAD_MAC,
} l2flood_shared_view_error_t;

static l2flood_shared_view_trace_t l2flood_shared_view_traces[2];
static u32 l2flood_shared_view_trace_nodes[2];
static u32 l2flood_shared_view_trace_count;

static void *
l2flood_shared_view_add_trace (struct vlib_main_t *vm, struct vlib_node_runtime_t *runtime,
			       struct vlib_buffer_t *buffer, u32 n_data_bytes)
{
  vlib_node_runtime_t *node = (void *) runtime;

  CLIB_UNUSED (vlib_main_t * vm0) = (void *) vm;
  CLIB_UNUSED (vlib_buffer_t * buffer0) = (void *) buffer;
  ASSERT (n_data_bytes == sizeof (l2flood_shared_view_traces[0]));
  ASSERT (l2flood_shared_view_trace_count < ARRAY_LEN (l2flood_shared_view_traces));
  l2flood_shared_view_trace_nodes[l2flood_shared_view_trace_count] = node->node_index;
  return &l2flood_shared_view_traces[l2flood_shared_view_trace_count++];
}

static void
l2flood_shared_view_clear_pending (vlib_main_t *vm, u32 pending_len)
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
l2flood_shared_view_dispatch (vlib_main_t *vm, u32 buffer_index, u32 *forwarded_indices,
			      u32 *forwarded_runtime_indices, u32 max_forwarded, u32 *n_forwarded)
{
  vlib_node_t *node;
  vlib_node_runtime_t *runtime;
  vlib_pending_frame_t *pending;
  vlib_frame_t *frame;
  u32 pending_len;
  u32 i;
  int ret = -1;

  node = vlib_get_node_by_name (vm, (u8 *) "l2-flood");
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
  l2flood_shared_view_clear_pending (vm, pending_len);
  vlib_frame_free (vm, frame);
  return ret;
}

static int
l2flood_shared_view_run_error_drop (vlib_main_t *vm, u32 buffer_index)
{
  vlib_node_t *node;
  vlib_node_runtime_t *runtime;
  vlib_frame_t *frame;

  node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  if (node == 0)
    return -1;
  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  if (frame == 0)
    return -1;
  ((u32 *) vlib_frame_vector_args (frame))[0] = buffer_index;
  frame->n_vectors = 1;
  runtime->function (vm, runtime, frame);
  vlib_frame_free (vm, frame);
  return 0;
}

static int
l2flood_shared_view_topology_create (l2flood_shared_view_topology_t *topology)
{
  l2_bridge_domain_t *bd;

  topology->old_bd_configs_len = vec_len (l2input_main.bd_configs);
  topology->bd_index = topology->old_bd_configs_len;
  topology->bvi_sw_if_index = ~0;
  if (topology->bd_index > (u16) ~0)
    return -1;
  vec_validate (l2input_main.bd_configs, topology->bd_index);
  bd = vec_elt_at_index (l2input_main.bd_configs, topology->bd_index);
  clib_memset (bd, 0, sizeof (*bd));
  return 0;
}

static void
l2flood_shared_view_topology_destroy (l2flood_shared_view_topology_t *topology)
{
  l2_bridge_domain_t *bd;

  if (topology->bd_index < vec_len (l2input_main.bd_configs))
    {
      bd = vec_elt_at_index (l2input_main.bd_configs, topology->bd_index);
      vec_free (bd->members);
      clib_memset (bd, 0, sizeof (*bd));
      vec_set_len (l2input_main.bd_configs, topology->old_bd_configs_len);
    }
  if (topology->bvi_sw_if_index != ~0)
    l2_bvi_delete (topology->bvi_sw_if_index);
}

static void
l2flood_shared_view_set_members (l2flood_shared_view_topology_t *topology,
				 l2_flood_member_t *members, u32 n_members)
{
  l2_bridge_domain_t *bd;

  bd = vec_elt_at_index (l2input_main.bd_configs, topology->bd_index);
  vec_free (bd->members);
  bd->members = 0;
  if (n_members)
    vec_add (bd->members, members, n_members);
  bd->flood_count = n_members;
}

static void
l2flood_shared_view_init_packet (vlib_buffer_t *buffer, l2flood_shared_view_topology_t *topology)
{
  ethernet_header_t *ethernet;

  buffer->current_length = sizeof (*ethernet) + 1;
  ethernet = vlib_buffer_get_current (buffer);
  clib_memset (ethernet, 0, buffer->current_length);
  ethernet->dst_address[0] = 0x02;
  ethernet->src_address[0] = 0x0a;
  ethernet->type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4);
  vnet_buffer (buffer)->l2.bd_index = topology->bd_index ? 0 : 1;
  vnet_buffer (buffer)->l2.shg = 0;
  vnet_buffer (buffer)->l2.l2_len = sizeof (*ethernet);
  vnet_buffer (buffer)->sw_if_index[VLIB_RX] = 0x7003;
}

static void
l2flood_shared_view_init_descriptor (vlib_buffer_t *buffer,
				     l2flood_shared_view_topology_t *topology)
{
  vnet_buffer (buffer)->l2.bd_index = topology->bd_index;
  vnet_buffer (buffer)->l2.shg = 7;
  vnet_buffer (buffer)->sw_if_index[VLIB_RX] = 0x7001;
}

static int
l2flood_shared_view_no_members_test (vlib_main_t *vm)
{
  l2flood_shared_view_topology_t topology;
  vlib_buffer_t *root;
  vlib_buffer_t *forwarded;
  vlib_node_t *drop_node;
  vlib_node_t *flood_node;
  u32 buffers[2];
  u32 forwarded_indices[1] = { ~0 };
  u32 forwarded_runtime_indices[1] = { ~0 };
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
  L2FLOOD_SHARED_VIEW_TEST (l2flood_shared_view_topology_create (&topology) == 0,
			    "create empty L2 flood topology");
  root = vlib_get_buffer (vm, buffers[0]);
  l2flood_shared_view_init_packet (root, &topology);
  L2FLOOD_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			    "attach no-member L2 flood descriptor");
  forwarded = vlib_get_buffer (vm, buffers[1]);
  l2flood_shared_view_init_descriptor (forwarded, &topology);
  L2FLOOD_SHARED_VIEW_TEST (
    l2flood_shared_view_dispatch (vm, buffers[1], forwarded_indices, forwarded_runtime_indices,
				  ARRAY_LEN (forwarded_indices), &n_forwarded) == 0,
    "dispatch no-member L2 flood descriptor");
  flood_node = vlib_get_node_by_name (vm, (u8 *) "l2-flood");
  drop_node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  L2FLOOD_SHARED_VIEW_TEST (flood_node && drop_node, "find no-member L2 flood route");
  L2FLOOD_SHARED_VIEW_TEST (n_forwarded == 1 && forwarded_indices[0] != buffers[1],
			    "replace no-member L2 flood descriptor");
  L2FLOOD_SHARED_VIEW_TEST (forwarded_runtime_indices[0] == drop_node->runtime_index,
			    "send no-member L2 flood copy to drop");
  forwarded = vlib_get_buffer (vm, forwarded_indices[0]);
  L2FLOOD_SHARED_VIEW_TEST (
    forwarded->error ==
      vlib_node_get_runtime (vm, flood_node->index)->errors[L2FLOOD_SHARED_VIEW_ERROR_NO_MEMBERS],
    "preserve no-member accounting after COW");
  L2FLOOD_SHARED_VIEW_TEST (vnet_buffer (forwarded)->l2.bd_index == topology.bd_index &&
			      vnet_buffer (forwarded)->l2.shg == 7 &&
			      vnet_buffer (forwarded)->sw_if_index[VLIB_RX] == 0x7001,
			    "restore no-member descriptor metadata after COW");
  ((u8 *) vlib_buffer_get_current (forwarded))[0] = 0xaf;
  L2FLOOD_SHARED_VIEW_TEST (((u8 *) vlib_buffer_get_current (root))[0] == 0x02,
			    "leave no-member canonical root unchanged");
  ret = 1;

done:
  if (n_forwarded)
    vlib_buffer_free_one (vm, forwarded_indices[0]);
  else
    vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  l2flood_shared_view_topology_destroy (&topology);
  return ret;
}

static int
l2flood_shared_view_single_member_test (vlib_main_t *vm)
{
  l2flood_shared_view_topology_t topology;
  l2_flood_member_t member = {};
  vlib_buffer_t *root;
  vlib_buffer_t *forwarded;
  vlib_node_t *output_node;
  u32 buffers[2];
  u32 forwarded_indices[1] = { ~0 };
  u32 forwarded_runtime_indices[1] = { ~0 };
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
  L2FLOOD_SHARED_VIEW_TEST (l2flood_shared_view_topology_create (&topology) == 0,
			    "create one-member L2 flood topology");
  member.sw_if_index = 0x7002;
  l2flood_shared_view_set_members (&topology, &member, 1);
  root = vlib_get_buffer (vm, buffers[0]);
  l2flood_shared_view_init_packet (root, &topology);
  L2FLOOD_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			    "attach one-member L2 flood descriptor");
  forwarded = vlib_get_buffer (vm, buffers[1]);
  l2flood_shared_view_init_descriptor (forwarded, &topology);
  L2FLOOD_SHARED_VIEW_TEST (
    l2flood_shared_view_dispatch (vm, buffers[1], forwarded_indices, forwarded_runtime_indices,
				  ARRAY_LEN (forwarded_indices), &n_forwarded) == 0,
    "dispatch one-member L2 flood descriptor");
  output_node = vlib_get_node_by_name (vm, (u8 *) "l2-output");
  L2FLOOD_SHARED_VIEW_TEST (output_node, "find one-member L2 flood output");
  L2FLOOD_SHARED_VIEW_TEST (n_forwarded == 1 && forwarded_indices[0] != buffers[1],
			    "replace one-member L2 flood descriptor");
  L2FLOOD_SHARED_VIEW_TEST (forwarded_runtime_indices[0] == output_node->runtime_index,
			    "send one-member L2 flood copy to output");
  forwarded = vlib_get_buffer (vm, forwarded_indices[0]);
  L2FLOOD_SHARED_VIEW_TEST (!vlib_buffer_shared_view_is_shared (forwarded) &&
			      vnet_buffer (forwarded)->sw_if_index[VLIB_TX] == member.sw_if_index,
			    "forward one-member copy with TX metadata");
  L2FLOOD_SHARED_VIEW_TEST (vnet_buffer (forwarded)->l2.bd_index == topology.bd_index &&
			      vnet_buffer (forwarded)->l2.shg == 7 &&
			      vnet_buffer (forwarded)->sw_if_index[VLIB_RX] == 0x7001,
			    "restore one-member descriptor metadata after COW");
  ((u8 *) vlib_buffer_get_current (forwarded))[0] = 0xbe;
  L2FLOOD_SHARED_VIEW_TEST (((u8 *) vlib_buffer_get_current (root))[0] == 0x02,
			    "leave one-member canonical root unchanged");
  ret = 1;

done:
  if (n_forwarded)
    vlib_buffer_free_one (vm, forwarded_indices[0]);
  else
    vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  l2flood_shared_view_topology_destroy (&topology);
  return ret;
}

static int
l2flood_shared_view_members_test (vlib_main_t *vm)
{
  vlib_add_trace_callback_t *saved_add_trace_callback = 0;
  l2flood_shared_view_topology_t topology;
  l2_flood_member_t members[2] = {};
  mac_address_t bvi_mac;
  vlib_buffer_t *root;
  vlib_buffer_t *forwarded;
  vlib_node_t *drop_node;
  vlib_node_t *flood_node;
  vlib_node_t *output_node;
  u32 buffers[2];
  u32 forwarded_indices[2] = { ~0, ~0 };
  u32 forwarded_runtime_indices[2] = { ~0, ~0 };
  u32 n_alloc;
  u32 n_forwarded = 0;
  u8 saw_output = 0;
  u8 saw_bvi = 0;
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
  L2FLOOD_SHARED_VIEW_TEST (l2flood_shared_view_topology_create (&topology) == 0,
			    "create L2 flood member topology");
  mac_address_set_zero (&bvi_mac);
  L2FLOOD_SHARED_VIEW_TEST (l2_bvi_create (~0, &bvi_mac, &topology.bvi_sw_if_index) == 0,
			    "create L2 flood BVI member");
  members[0].sw_if_index = topology.bvi_sw_if_index;
  members[0].flags = L2_FLOOD_MEMBER_BVI;
  members[1].sw_if_index = 0x7002;
  l2flood_shared_view_set_members (&topology, members, ARRAY_LEN (members));

  root = vlib_get_buffer (vm, buffers[0]);
  l2flood_shared_view_init_packet (root, &topology);
  root->flags |= VLIB_BUFFER_IS_TRACED;
  L2FLOOD_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			    "attach member L2 flood descriptor");
  forwarded = vlib_get_buffer (vm, buffers[1]);
  l2flood_shared_view_init_descriptor (forwarded, &topology);
  forwarded->flags |= VLIB_BUFFER_IS_TRACED;

  l2flood_shared_view_trace_count = 0;
  clib_memset (l2flood_shared_view_traces, 0, sizeof (l2flood_shared_view_traces));
  clib_memset (l2flood_shared_view_trace_nodes, 0, sizeof (l2flood_shared_view_trace_nodes));
  saved_add_trace_callback = vm->trace_main.add_trace_callback;
  vm->trace_main.add_trace_callback = l2flood_shared_view_add_trace;
  L2FLOOD_SHARED_VIEW_TEST (
    l2flood_shared_view_dispatch (vm, buffers[1], forwarded_indices, forwarded_runtime_indices,
				  ARRAY_LEN (forwarded_indices), &n_forwarded) == 0,
    "dispatch multi-member L2 flood descriptor");
  vm->trace_main.add_trace_callback = saved_add_trace_callback;

  flood_node = vlib_get_node_by_name (vm, (u8 *) "l2-flood");
  output_node = vlib_get_node_by_name (vm, (u8 *) "l2-output");
  drop_node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  L2FLOOD_SHARED_VIEW_TEST (flood_node && output_node && drop_node, "find L2 flood output routes");
  L2FLOOD_SHARED_VIEW_TEST (n_forwarded == ARRAY_LEN (forwarded_indices),
			    "flood every configured member");
  for (i = 0; i < n_forwarded; i++)
    {
      forwarded = vlib_get_buffer (vm, forwarded_indices[i]);
      L2FLOOD_SHARED_VIEW_TEST (forwarded_indices[i] != buffers[1],
				"replace multi-member L2 flood descriptor");
      L2FLOOD_SHARED_VIEW_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
				"forward ordinary L2 flood clone");
      if (forwarded_runtime_indices[i] == output_node->runtime_index)
	{
	  L2FLOOD_SHARED_VIEW_TEST (vnet_buffer (forwarded)->sw_if_index[VLIB_TX] == 0x7002,
				    "preserve normal-member TX metadata");
	  L2FLOOD_SHARED_VIEW_TEST (vnet_buffer (forwarded)->l2.bd_index == topology.bd_index &&
				      vnet_buffer (forwarded)->l2.shg == 7 &&
				      vnet_buffer (forwarded)->sw_if_index[VLIB_RX] == 0x7001,
				    "restore normal-member descriptor metadata after COW");
	  saw_output = 1;
	}
      else if (forwarded_runtime_indices[i] == drop_node->runtime_index)
	{
	  L2FLOOD_SHARED_VIEW_TEST (forwarded->error ==
				      vlib_node_get_runtime (vm, flood_node->index)
					->errors[L2FLOOD_SHARED_VIEW_ERROR_BVI_BAD_MAC],
				    "process the final BVI candidate after normal replicas");
	  L2FLOOD_SHARED_VIEW_TEST (vnet_buffer (forwarded)->l2.bd_index == topology.bd_index &&
				      vnet_buffer (forwarded)->l2.shg == 7 &&
				      vnet_buffer (forwarded)->sw_if_index[VLIB_RX] == 0x7001,
				    "restore BVI descriptor metadata after COW");
	  saw_bvi = 1;
	}
      else
	L2FLOOD_SHARED_VIEW_TEST (0, "route every L2 flood member through its edge");
      ((u8 *) vlib_buffer_get_current (forwarded))[0] = 0xb0 + i;
    }
  L2FLOOD_SHARED_VIEW_TEST (saw_output && saw_bvi,
			    "keep BVI as the final distinct flood candidate");
  L2FLOOD_SHARED_VIEW_TEST (((u8 *) vlib_buffer_get_current (root))[0] == 0x02,
			    "leave multi-member canonical root unchanged");
  L2FLOOD_SHARED_VIEW_TEST (l2flood_shared_view_trace_count == ARRAY_LEN (forwarded_indices),
			    "trace every L2 flood replica");
  for (i = 0; i < l2flood_shared_view_trace_count; i++)
    L2FLOOD_SHARED_VIEW_TEST (l2flood_shared_view_trace_nodes[i] == flood_node->index &&
				l2flood_shared_view_traces[i].sw_if_index == 0x7001 &&
				l2flood_shared_view_traces[i].bd_index == topology.bd_index,
			      "preserve L2 flood trace metadata after COW");
  ret = 1;

done:
  if (vm->trace_main.add_trace_callback == l2flood_shared_view_add_trace)
    vm->trace_main.add_trace_callback = saved_add_trace_callback;
  for (i = 0; i < n_forwarded; i++)
    vlib_buffer_free_one (vm, forwarded_indices[i]);
  if (!n_forwarded)
    vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  l2flood_shared_view_topology_destroy (&topology);
  return ret;
}

static int
l2flood_shared_view_failure_test (vlib_main_t *vm)
{
  vlib_buffer_t *descriptor = 0;
  vlib_buffer_t *root;
  vlib_node_t *drop_node;
  vlib_node_t *flood_node;
  u32 buffers[2];
  u32 forwarded_indices[1] = { ~0 };
  u32 forwarded_runtime_indices[1] = { ~0 };
  u32 descriptor_next = 0;
  u64 cow_fail_before;
  u32 n_alloc;
  u32 n_forwarded = 0;
  u8 consumed_by_error_drop = 0;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }
  root = vlib_get_buffer (vm, buffers[0]);
  root->current_length = 1;
  root->data[0] = 0x5a;
  L2FLOOD_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			    "attach malformed L2 flood descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  vnet_buffer (descriptor)->l2.bd_index = 0;
  vnet_buffer (descriptor)->l2.shg = 7;
  vnet_buffer (descriptor)->sw_if_index[VLIB_RX] = 0x7001;
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  flood_node = vlib_get_node_by_name (vm, (u8 *) "l2-flood");
  drop_node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  L2FLOOD_SHARED_VIEW_TEST (flood_node && drop_node, "find L2 flood COW failure route");
  cow_fail_before =
    vm->error_main.counters[flood_node->error_heap_index + L2FLOOD_SHARED_VIEW_ERROR_COW_FAIL];
  L2FLOOD_SHARED_VIEW_TEST (
    l2flood_shared_view_dispatch (vm, buffers[1], forwarded_indices, forwarded_runtime_indices,
				  ARRAY_LEN (forwarded_indices), &n_forwarded) == 0,
    "dispatch malformed L2 flood descriptor");
  descriptor->next_buffer = descriptor_next;
  L2FLOOD_SHARED_VIEW_TEST (n_forwarded == 1 && forwarded_indices[0] == buffers[1],
			    "retain malformed L2 flood descriptor after COW failure");
  L2FLOOD_SHARED_VIEW_TEST (forwarded_runtime_indices[0] == drop_node->runtime_index,
			    "send L2 flood COW failure to drop");
  L2FLOOD_SHARED_VIEW_TEST (
    descriptor->error ==
	vlib_node_get_runtime (vm, flood_node->index)->errors[L2FLOOD_SHARED_VIEW_ERROR_COW_FAIL] &&
      descriptor->error !=
	vlib_node_get_runtime (vm, flood_node->index)->errors[L2FLOOD_SHARED_VIEW_ERROR_REPL_FAIL],
    "account L2 flood COW failure separately from replication failure");
  L2FLOOD_SHARED_VIEW_TEST (l2flood_shared_view_run_error_drop (vm, forwarded_indices[0]) == 0,
			    "run the captured L2 flood failure through error-drop");
  consumed_by_error_drop = 1;
  L2FLOOD_SHARED_VIEW_TEST (
    vm->error_main.counters[flood_node->error_heap_index + L2FLOOD_SHARED_VIEW_ERROR_COW_FAIL] ==
      cow_fail_before + 1,
    "increment the L2 flood COW failure counter");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  if (!consumed_by_error_drop)
    vlib_buffer_free_one (vm, n_forwarded ? forwarded_indices[0] : buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_l2flood_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!l2flood_shared_view_no_members_test (vm) || !l2flood_shared_view_single_member_test (vm) ||
      !l2flood_shared_view_members_test (vm) || !l2flood_shared_view_failure_test (vm))
    return clib_error_return (0, "L2 flood shared-view test failed");
  return 0;
}

VLIB_CLI_COMMAND (test_l2flood_shared_view_command, static) = {
  .path = "test l2-flood-shared-view",
  .short_help = "test l2-flood-shared-view",
  .function = test_l2flood_shared_view_fn,
};
