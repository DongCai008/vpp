/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>

typedef struct
{
  u32 owner_ready;
  u32 release_descriptor;
  u32 owner_done;
  u32 owner_failed;
  u32 owner_thread_index;
  u32 descriptor_index;
  u32 root_ref_count;
  u32 tail_ref_count;
} buffer_shared_view_worker_test_t;

static buffer_shared_view_worker_test_t buffer_shared_view_worker_test;

static uword
buffer_shared_view_worker_input (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  buffer_shared_view_worker_test_t *test = &buffer_shared_view_worker_test;
  vlib_buffer_t *root;
  vlib_buffer_t *tail;
  u32 buffers[3];
  u32 n_alloc;

  if (vm->thread_index != test->owner_thread_index)
    {
      clib_atomic_store_rel_n (&test->owner_failed, 1);
      goto done;
    }

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      clib_atomic_store_rel_n (&test->owner_failed, 1);
      goto done;
    }

  root = vlib_get_buffer (vm, buffers[0]);
  tail = vlib_get_buffer (vm, buffers[1]);
  root->current_length = 16;
  root->next_buffer = buffers[1];
  root->flags |= VLIB_BUFFER_NEXT_PRESENT;
  tail->current_length = 8;

  if (vlib_buffer_shared_view_attach (vm, buffers[2], buffers[0]))
    {
      vlib_buffer_free_one (vm, buffers[2]);
      vlib_buffer_free_one (vm, buffers[0]);
      clib_atomic_store_rel_n (&test->owner_failed, 1);
      goto done;
    }

  test->descriptor_index = buffers[2];
  if (root->ref_count != 2 || tail->ref_count != 2)
    clib_atomic_store_rel_n (&test->owner_failed, 1);

  clib_atomic_store_rel_n (&test->owner_ready, 1);
  while (!clib_atomic_load_acq_n (&test->release_descriptor))
    CLIB_PAUSE ();

  test->root_ref_count = root->ref_count;
  test->tail_ref_count = tail->ref_count;
  if (test->root_ref_count != 1 || test->tail_ref_count != 1)
    clib_atomic_store_rel_n (&test->owner_failed, 1);

  vlib_buffer_free_one (vm, buffers[0]);
  clib_atomic_store_rel_n (&test->owner_done, 1);

done:
  vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_DISABLED);
  if (!clib_atomic_load_acq_n (&test->owner_ready))
    clib_atomic_store_rel_n (&test->owner_ready, 1);
  return 0;
}

VLIB_REGISTER_NODE (buffer_shared_view_worker_input_node) = {
  .function = buffer_shared_view_worker_input,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "buffer-shared-view-worker-input",
  .state = VLIB_NODE_STATE_DISABLED,
};

static clib_error_t *
test_buffer_shared_view_cross_worker_release (vlib_main_t *vm, unformat_input_t *input,
					      vlib_cli_command_t *cmd)
{
  buffer_shared_view_worker_test_t *test = &buffer_shared_view_worker_test;
  f64 deadline;

  if (vlib_num_workers () == 0)
    {
      vlib_cli_output (vm, "Test requires at least one worker, skipping");
      return 0;
    }

  clib_memset (test, 0, sizeof (*test));
  test->owner_thread_index = 1;
  test->descriptor_index = VLIB_BUFFER_INVALID_INDEX;

  vlib_worker_thread_barrier_sync (vm);
  foreach_vlib_main ()
    {
      if (this_vlib_main->thread_index == test->owner_thread_index)
	vlib_node_set_state (this_vlib_main, buffer_shared_view_worker_input_node.index,
			     VLIB_NODE_STATE_POLLING);
    }
  vlib_worker_thread_barrier_release (vm);

  deadline = vlib_time_now (vm) + 1.0;
  while (!clib_atomic_load_acq_n (&test->owner_ready) && vlib_time_now (vm) < deadline)
    vlib_process_suspend (vm, 1e-4);

  if (!clib_atomic_load_acq_n (&test->owner_ready) ||
      test->descriptor_index == VLIB_BUFFER_INVALID_INDEX)
    return clib_error_return (0, "worker did not create a shared view");

  vlib_buffer_free_one (vm, test->descriptor_index);
  clib_atomic_store_rel_n (&test->release_descriptor, 1);

  deadline = vlib_time_now (vm) + 1.0;
  while (!clib_atomic_load_acq_n (&test->owner_done) && vlib_time_now (vm) < deadline)
    vlib_process_suspend (vm, 1e-4);

  if (!clib_atomic_load_acq_n (&test->owner_done) || clib_atomic_load_acq_n (&test->owner_failed) ||
      test->root_ref_count != 1 || test->tail_ref_count != 1)
    return clib_error_return (0, "cross-worker free did not release the shared root chain");

  return 0;
}

VLIB_CLI_COMMAND (test_buffer_shared_view_cross_worker_release_command, static) = {
  .path = "test buffer-shared-view-cross-worker-release",
  .short_help = "test buffer-shared-view-cross-worker-release",
  .function = test_buffer_shared_view_cross_worker_release,
  .is_mp_safe = 1,
};
