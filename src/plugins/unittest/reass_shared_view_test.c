/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vnet/udp/udp_packet.h>

#define REASS_TEST(_cond, _comment)                                                                \
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
reass_shared_view_dispatch (vlib_main_t *vm, const char *node_name, u32 descriptor_index,
			    u32 context, int with_context, u32 *forwarded_index,
			    u32 *forwarded_context)
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
  ((u32 *) vlib_frame_vector_args (frame))[0] = descriptor_index;
  if (with_context)
    ((u32 *) vlib_frame_aux_args (frame))[0] = context;
  frame->n_vectors = 1;
  runtime->function (vm, runtime, frame);

  if (vec_len (vm->node_main.pending_frames) != pending_len + 1)
    goto done;
  pending = vec_elt_at_index (vm->node_main.pending_frames, pending_len);
  if (pending->frame->n_vectors != 1)
    goto done;
  *forwarded_index = ((u32 *) vlib_frame_vector_args (pending->frame))[0];
  if (forwarded_context && with_context)
    *forwarded_context = ((u32 *) vlib_frame_aux_args (pending->frame))[0];
  ret = 0;

done:
  for (i = pending_len; i < vec_len (vm->node_main.pending_frames); i++)
    {
      pending = vec_elt_at_index (vm->node_main.pending_frames, i);
      if (pending->next_frame_index != VLIB_PENDING_FRAME_NO_NEXT_FRAME)
	{
	  vlib_next_frame_t *next_frame =
	    vec_elt_at_index (vm->node_main.next_frames, pending->next_frame_index);
	  next_frame->flags &= ~VLIB_FRAME_PENDING;
	}
      pending->frame->frame_flags &= ~VLIB_FRAME_PENDING;
      pending->frame->n_vectors = 0;
    }
  vec_set_len (vm->node_main.pending_frames, pending_len);
  vlib_frame_free (vm, frame);
  return ret;
}

static int
reass_shared_view_test_node (vlib_main_t *vm, const char *node_name, int is_ip6, u32 next_index,
			     u32 error_next_index, u8 save_rewrite_length, u32 current_config_index,
			     int with_context, int check_output_context, int check_full_context)
{
  vlib_buffer_t *root;
  vlib_buffer_t *descriptor;
  vlib_buffer_t *forwarded;
  u32 buffers[2];
  u32 forwarded_index = ~0;
  u32 forwarded_context = ~0;
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
      ip6_header_t *ip = vlib_buffer_get_current (root);
      root->current_length = sizeof (*ip);
      clib_memset (ip, 0, sizeof (*ip));
      ip->protocol = IP_PROTOCOL_TCP;
    }
  else
    {
      ip4_header_t *ip = vlib_buffer_get_current (root);
      root->current_length = sizeof (*ip);
      clib_memset (ip, 0, sizeof (*ip));
      ip->length = clib_host_to_net_u16 (sizeof (*ip));
    }
  root->current_config_index = current_config_index + 1;
  vnet_buffer (root)->ip.save_rewrite_length = save_rewrite_length + 1;
  vnet_buffer (root)->ip.reass.next_index = next_index + 17;
  vnet_buffer (root)->ip.reass.error_next_index = error_next_index + 17;

  REASS_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	      "attach reassembly shared-view descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor->current_config_index = current_config_index;
  vnet_buffer (descriptor)->ip.reass.next_index = next_index;
  vnet_buffer (descriptor)->ip.reass.error_next_index = error_next_index;
  vnet_buffer (descriptor)->ip.save_rewrite_length = save_rewrite_length;

  REASS_TEST (reass_shared_view_dispatch (vm, node_name, buffers[1], 0xbeef, with_context,
					  &forwarded_index, &forwarded_context) == 0,
	      "dispatch reassembly node with headerless descriptor");
  REASS_TEST (forwarded_index != buffers[1], "replace descriptor in forwarded reassembly frame");
  forwarded = vlib_get_buffer (vm, forwarded_index);
  REASS_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
	      "forward ordinary replacement after reassembly COW");
  REASS_TEST (vnet_buffer (root)->ip.save_rewrite_length == (save_rewrite_length + 1),
	      "leave canonical root rewrite context unchanged");
  if (check_output_context)
    {
      REASS_TEST (forwarded->current_config_index == current_config_index,
		  "preserve descriptor feature configuration");
      REASS_TEST (vnet_buffer (forwarded)->ip.save_rewrite_length == save_rewrite_length,
		  "preserve descriptor rewrite length");
    }
  if (check_full_context)
    {
      REASS_TEST (vnet_buffer (forwarded)->ip.reass.next_index == next_index,
		  "preserve custom full next index");
      REASS_TEST (vnet_buffer (forwarded)->ip.reass.error_next_index == error_next_index,
		  "preserve custom full error next index");
    }
  if (!is_ip6 && !with_context && !check_output_context && !check_full_context)
    REASS_TEST (vnet_buffer (forwarded)->ip.reass.next_index == next_index,
		"preserve custom IPv4 next index");
  if (is_ip6 && !with_context && !check_output_context && !check_full_context)
    REASS_TEST (vnet_buffer (forwarded)->ip.reass.error_next_index == error_next_index,
		"preserve custom IPv6 error next index");
  if (with_context)
    {
      REASS_TEST (vnet_buffer (forwarded)->ip.reass.next_index == next_index,
		  "preserve shallow custom-context next index");
      REASS_TEST (forwarded_context == 0xbeef, "preserve shallow custom-context aux forwarding");
    }
  ret = 1;

done:
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
reass_shared_view_test (vlib_main_t *vm)
{
  return reass_shared_view_test_node (vm, "ip4-full-reassembly-custom", 0, 1, 1, 0, 0, 0, 0, 1) &&
	 reass_shared_view_test_node (vm, "ip6-full-reassembly-custom", 1, 1, 1, 0, 0, 0, 0, 1) &&
	 reass_shared_view_test_node (vm, "ip4-sv-reassembly-custom-next", 0, 1, 1, 0, 0, 0, 0,
				      0) &&
	 reass_shared_view_test_node (vm, "ip6-sv-reassembly-custom-context", 1, 1, 1, 0, 0, 1, 0,
				      0) &&
	 reass_shared_view_test_node (vm, "ip4-sv-reassembly-output-feature", 0, 0, 0, 0, 0, 0, 1,
				      0) &&
	 reass_shared_view_test_node (vm, "ip6-sv-reassembly-output-feature", 1, 0, 0, 0, 0, 0, 1,
				      0);
}

static clib_error_t *
test_reass_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!reass_shared_view_test (vm))
    return clib_error_return (0, "reassembly shared-view test failed");
  return 0;
}

VLIB_CLI_COMMAND (test_reass_shared_view_command, static) = {
  .path = "test reass-shared-view",
  .short_help = "test reass-shared-view",
  .function = test_reass_shared_view_fn,
};

typedef struct
{
  u32 seed_buffer_index;
  u32 root_buffer_index;
  u32 descriptor_buffer_index;
  u32 forwarded_buffer_index;
  u32 generation;
  u32 cleanup_generation;
  u32 context;
  u32 custom_next_index;
  u32 worker_thread_index;
  u32 armed;
  u32 seed_collected;
  u32 worker_injected;
  u32 result_collected;
  u32 cleanup_requested;
  u32 worker_cleaned;
  u32 worker_failed;
  u32 root_ref_count;
} reass_shared_view_worker_test_t;

static reass_shared_view_worker_test_t reass_shared_view_worker_test;
static u32 reass_shared_view_worker_sequence;

static uword reass_shared_view_worker_collect (vlib_main_t *vm, vlib_node_runtime_t *node,
					       vlib_frame_t *frame);

VLIB_REGISTER_NODE (reass_shared_view_worker_collect_node) = {
  .function = reass_shared_view_worker_collect,
  .name = "reass-shared-view-worker-collect",
  .vector_size = sizeof (u32),
  .aux_size = sizeof (u32),
};

static void
reass_shared_view_worker_init_fragment (vlib_buffer_t *b, u16 fragment_id, u16 fragment_offset,
					bool more_fragments)
{
  ip4_header_t *ip = vlib_buffer_get_current (b);
  udp_header_t *udp = (udp_header_t *) (ip + 1);

  clib_memset (ip, 0, sizeof (*ip) + sizeof (*udp));
  b->current_length = sizeof (*ip) + sizeof (*udp);
  ip->ip_version_and_header_length = IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
  ip->length = clib_host_to_net_u16 (b->current_length);
  ip->fragment_id = clib_host_to_net_u16 (fragment_id);
  ip->flags_and_fragment_offset =
    clib_host_to_net_u16 (fragment_offset | (more_fragments ? IP4_HEADER_FLAG_MORE_FRAGMENTS : 0));
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = clib_host_to_net_u32 (0x0a000001);
  ip->dst_address.as_u32 = clib_host_to_net_u32 (0x0a000002);
  udp->src_port = clib_host_to_net_u16 (1234);
  udp->dst_port = clib_host_to_net_u16 (4321);
  udp->length = clib_host_to_net_u16 (sizeof (*udp));
  ip->checksum = ip4_header_checksum (ip);
}

static uword
reass_shared_view_worker_seed (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  reass_shared_view_worker_test_t *test = &reass_shared_view_worker_test;
  vlib_buffer_t *b;
  u32 bi;
  u32 *to_next, *to_next_aux;
  u32 n_left_to_next;

  if (vm->thread_index != 0)
    goto done;

  if (!clib_atomic_load_acq_n (&test->armed))
    goto done;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_atomic_store_rel_n (&test->worker_failed, 1);
      goto done;
    }

  b = vlib_get_buffer (vm, bi);
  b->flow_id = clib_atomic_load_acq_n (&test->generation);
  reass_shared_view_worker_init_fragment (b, test->context, 0, true);
  vnet_buffer (b)->ip.reass.next_index = test->custom_next_index;
  test->seed_buffer_index = bi;

  vlib_get_next_frame_with_aux_safe (vm, node, 0, to_next, to_next_aux, n_left_to_next);
  if (PREDICT_FALSE (to_next_aux == 0))
    {
      vlib_buffer_free_one (vm, bi);
      test->seed_buffer_index = VLIB_BUFFER_INVALID_INDEX;
      clib_atomic_store_rel_n (&test->worker_failed, 1);
      goto done;
    }
  to_next[0] = bi;
  to_next_aux[0] = test->context;
  vlib_put_next_frame (vm, node, 0, n_left_to_next - 1);

done:
  vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_DISABLED);
  return 0;
}

VLIB_REGISTER_NODE (reass_shared_view_worker_seed_node) = {
  .function = reass_shared_view_worker_seed,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "reass-shared-view-worker-seed",
  .state = VLIB_NODE_STATE_DISABLED,
  .vector_size = sizeof (u32),
  .aux_size = sizeof (u32),
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip4-sv-reassembly-custom-context",
  },
};

static uword
reass_shared_view_worker_input (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  reass_shared_view_worker_test_t *test = &reass_shared_view_worker_test;
  vlib_buffer_t *root;
  u32 buffers[2];
  u32 n_alloc;
  u32 *to_next, *to_next_aux;
  u32 n_left_to_next;

  if (vm->thread_index != test->worker_thread_index)
    goto done;

  if (clib_atomic_load_acq_n (&test->cleanup_requested))
    {
      const u32 generation = clib_atomic_load_acq_n (&test->generation);
      const u32 cleanup_generation = clib_atomic_load_acq_n (&test->cleanup_generation);
      const u32 root_buffer_index = clib_atomic_load_acq_n (&test->root_buffer_index);

      if (cleanup_generation == generation && root_buffer_index != VLIB_BUFFER_INVALID_INDEX)
	{
	  root = vlib_get_buffer (vm, root_buffer_index);
	  clib_atomic_store_rel_n (&test->root_ref_count, root->ref_count);
	  vlib_buffer_free_one (vm, root_buffer_index);
	}
      clib_atomic_store_rel_n (&test->worker_cleaned, 1);
      goto done;
    }

  if (!clib_atomic_load_acq_n (&test->armed))
    goto done;

  if (!clib_atomic_load_acq_n (&test->seed_collected))
    {
      clib_atomic_store_rel_n (&test->worker_failed, 1);
      goto done;
    }

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      clib_atomic_store_rel_n (&test->worker_failed, 1);
      goto done;
    }

  root = vlib_get_buffer (vm, buffers[0]);
  root->flow_id = clib_atomic_load_acq_n (&test->generation);
  reass_shared_view_worker_init_fragment (root, test->context, 1, false);
  if (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]))
    {
      vlib_buffer_free_one (vm, buffers[1]);
      vlib_buffer_free_one (vm, buffers[0]);
      clib_atomic_store_rel_n (&test->worker_failed, 1);
      goto done;
    }
  vnet_buffer (vlib_get_buffer (vm, buffers[1]))->ip.reass.next_index = test->custom_next_index;
  clib_atomic_store_rel_n (&test->root_buffer_index, buffers[0]);
  clib_atomic_store_rel_n (&test->descriptor_buffer_index, buffers[1]);

  vlib_get_next_frame_with_aux_safe (vm, node, 0, to_next, to_next_aux, n_left_to_next);
  if (PREDICT_FALSE (to_next_aux == 0))
    {
      vlib_buffer_free_one (vm, buffers[1]);
      vlib_buffer_free_one (vm, buffers[0]);
      clib_atomic_store_rel_n (&test->root_buffer_index, VLIB_BUFFER_INVALID_INDEX);
      clib_atomic_store_rel_n (&test->descriptor_buffer_index, VLIB_BUFFER_INVALID_INDEX);
      clib_atomic_store_rel_n (&test->worker_failed, 1);
      goto done;
    }
  to_next[0] = buffers[1];
  to_next_aux[0] = test->context;
  clib_atomic_store_rel_n (&test->worker_injected, 1);
  vlib_put_next_frame (vm, node, 0, n_left_to_next - 1);

done:
  vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_DISABLED);
  return 0;
}

VLIB_REGISTER_NODE (reass_shared_view_worker_input_node) = {
  .function = reass_shared_view_worker_input,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "reass-shared-view-worker-input",
  .state = VLIB_NODE_STATE_DISABLED,
  .vector_size = sizeof (u32),
  .aux_size = sizeof (u32),
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip4-sv-reassembly-custom-context",
  },
};

static uword
reass_shared_view_worker_collect (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  reass_shared_view_worker_test_t *test = &reass_shared_view_worker_test;
  u32 *from = vlib_frame_vector_args (frame);
  u32 i;

  for (i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      const u32 generation = clib_atomic_load_acq_n (&test->generation);

      if (!clib_atomic_load_acq_n (&test->armed) || b->flow_id != generation)
	{
	  vlib_buffer_free_one (vm, from[i]);
	  continue;
	}

      if (vm->thread_index != 0)
	clib_atomic_store_rel_n (&test->worker_failed, 1);

      if (from[i] == test->seed_buffer_index)
	clib_atomic_store_rel_n (&test->seed_collected, 1);
      else
	{
	  const u32 descriptor_buffer_index =
	    clib_atomic_load_acq_n (&test->descriptor_buffer_index);

	  test->forwarded_buffer_index = from[i];
	  if (from[i] == descriptor_buffer_index || vlib_buffer_shared_view_is_shared (b))
	    clib_atomic_store_rel_n (&test->worker_failed, 1);
	  clib_atomic_store_rel_n (&test->result_collected, 1);
	}
      vlib_buffer_free_one (vm, from[i]);
    }

  return frame->n_vectors;
}

static int
reass_shared_view_worker_wait (vlib_main_t *vm, u32 *flag)
{
  f64 deadline = vlib_time_now (vm) + 1.0;

  while (!clib_atomic_load_acq_n (flag) && vlib_time_now (vm) < deadline)
    vlib_process_suspend (vm, 1e-4);
  return clib_atomic_load_acq_n (flag);
}

static void
reass_shared_view_worker_enable (vlib_main_t *vm, u32 node_index, u32 thread_index)
{
  vlib_worker_thread_barrier_sync (vm);
  foreach_vlib_main ()
    {
      if (this_vlib_main->thread_index == thread_index)
	vlib_node_set_state (this_vlib_main, node_index, VLIB_NODE_STATE_POLLING);
    }
  vlib_worker_thread_barrier_release (vm);
}

static void
reass_shared_view_worker_disarm (vlib_main_t *vm)
{
  reass_shared_view_worker_test_t *test = &reass_shared_view_worker_test;

  vlib_worker_thread_barrier_sync (vm);
  clib_atomic_store_rel_n (&test->armed, 0);
  foreach_vlib_main ()
    {
      if (this_vlib_main->thread_index == 0)
	vlib_node_set_state (this_vlib_main, reass_shared_view_worker_seed_node.index,
			     VLIB_NODE_STATE_DISABLED);
      if (this_vlib_main->thread_index == test->worker_thread_index)
	vlib_node_set_state (this_vlib_main, reass_shared_view_worker_input_node.index,
			     VLIB_NODE_STATE_DISABLED);
    }
  vlib_worker_thread_barrier_release (vm);
}

static int
reass_shared_view_worker_cleanup (vlib_main_t *vm)
{
  reass_shared_view_worker_test_t *test = &reass_shared_view_worker_test;
  const u32 generation = clib_atomic_load_acq_n (&test->generation);

  if (generation == 0 ||
      clib_atomic_load_acq_n (&test->root_buffer_index) == VLIB_BUFFER_INVALID_INDEX ||
      clib_atomic_load_acq_n (&test->worker_cleaned))
    return 1;

  clib_atomic_store_rel_n (&test->worker_cleaned, 0);
  clib_atomic_store_rel_n (&test->cleanup_generation, generation);
  clib_atomic_store_rel_n (&test->cleanup_requested, 1);
  reass_shared_view_worker_enable (vm, reass_shared_view_worker_input_node.index,
				   test->worker_thread_index);
  return reass_shared_view_worker_wait (vm, &test->worker_cleaned);
}

static int
reass_shared_view_worker_retire (vlib_main_t *vm)
{
  reass_shared_view_worker_disarm (vm);
  return reass_shared_view_worker_cleanup (vm);
}

static clib_error_t *
test_reass_shared_view_cross_worker (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  reass_shared_view_worker_test_t *test = &reass_shared_view_worker_test;

  if (vlib_num_workers () == 0)
    {
      vlib_cli_output (vm, "Test requires at least one worker, skipping");
      return 0;
    }

  if (!reass_shared_view_worker_retire (vm))
    return clib_error_return (0, "could not retire the previous reassembly worker test");

  clib_memset (test, 0, sizeof (*test));
  test->seed_buffer_index = VLIB_BUFFER_INVALID_INDEX;
  clib_atomic_store_rel_n (&test->root_buffer_index, VLIB_BUFFER_INVALID_INDEX);
  clib_atomic_store_rel_n (&test->descriptor_buffer_index, VLIB_BUFFER_INVALID_INDEX);
  test->forwarded_buffer_index = VLIB_BUFFER_INVALID_INDEX;
  test->worker_thread_index = 1;
  clib_atomic_store_rel_n (&test->generation, ++reass_shared_view_worker_sequence);
  test->context = 0x6a5a0000 | (reass_shared_view_worker_sequence & 0xffff);
  test->custom_next_index =
    ip4_sv_reass_custom_context_register_next_node (reass_shared_view_worker_collect_node.index);
  clib_atomic_store_rel_n (&test->armed, 1);

  reass_shared_view_worker_enable (vm, reass_shared_view_worker_seed_node.index, 0);
  if (!reass_shared_view_worker_wait (vm, &test->seed_collected))
    goto failed;

  reass_shared_view_worker_enable (vm, reass_shared_view_worker_input_node.index,
				   test->worker_thread_index);
  if (!reass_shared_view_worker_wait (vm, &test->result_collected))
    goto failed;

  reass_shared_view_worker_disarm (vm);
  if (!reass_shared_view_worker_cleanup (vm))
    goto failed;

  if (clib_atomic_load_acq_n (&test->worker_failed) ||
      !clib_atomic_load_acq_n (&test->worker_injected) ||
      test->forwarded_buffer_index == clib_atomic_load_acq_n (&test->descriptor_buffer_index) ||
      clib_atomic_load_acq_n (&test->root_ref_count) != 1)
    goto failed;

  return 0;

failed:
  reass_shared_view_worker_retire (vm);
  return clib_error_return (0, "cross-worker reassembly shared-view test failed");
}

VLIB_CLI_COMMAND (test_reass_shared_view_cross_worker_command, static) = {
  .path = "test reass-shared-view-cross-worker",
  .short_help = "test reass-shared-view-cross-worker",
  .function = test_reass_shared_view_cross_worker,
  .is_mp_safe = 1,
};
