/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>

#define WG_TEST(_cond, _comment)                                                                   \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	{                                                                                          \
	  fformat (stderr, "FAIL:%d: %s\n", __LINE__, _comment);                                   \
	  goto done;                                                                               \
	}                                                                                          \
    }                                                                                              \
  while (0)

static int
wg_shared_view_dispatch (vlib_main_t *vm, u32 descriptor_index, u32 *forwarded_index)
{
  vlib_node_t *node;
  vlib_node_runtime_t *runtime;
  vlib_pending_frame_t *pending;
  vlib_frame_t *frame;
  u32 pending_len;
  u32 i;
  int ret = -1;

  node = vlib_get_node_by_name (vm, (u8 *) "wg4-input");
  if (node == 0)
    return -1;

  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  if (frame == 0)
    return -1;

  pending_len = vec_len (vm->node_main.pending_frames);
  ((u32 *) vlib_frame_vector_args (frame))[0] = descriptor_index;
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

static int
wg_shared_view_test (vlib_main_t *vm)
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
  root->current_length = sizeof (u32);
  root->error = 0xfeed;
  *(u32 *) vlib_buffer_get_current (root) = 0;

  WG_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	   "attach WireGuard shared-view descriptor");
  WG_TEST (wg_shared_view_dispatch (vm, buffers[1], &forwarded_index) == 0,
	   "dispatch WireGuard input with headerless descriptor");
  WG_TEST (forwarded_index != buffers[1], "replace descriptor in WireGuard frame slot");

  forwarded = vlib_get_buffer (vm, forwarded_index);
  WG_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
	   "forward ordinary replacement after WireGuard COW");
  WG_TEST (*(u32 *) vlib_buffer_get_current (forwarded) == 0,
	   "read WireGuard header through replacement");
  WG_TEST (forwarded->error != root->error, "preserve WireGuard error disposition");

  *(u32 *) vlib_buffer_get_current (forwarded) = 1;
  WG_TEST (*(u32 *) vlib_buffer_get_current (root) == 0,
	   "WireGuard input replacement leaves canonical root unchanged");

  ret = 1;
done:
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_wg_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!wg_shared_view_test (vm))
    return clib_error_return (0, "WireGuard shared-view test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_wg_shared_view_command, static) = {
  .path = "test wireguard-shared-view",
  .short_help = "test wireguard-shared-view",
  .function = test_wg_shared_view_fn,
};
