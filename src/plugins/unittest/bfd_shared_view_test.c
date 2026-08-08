/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/bfd/bfd.api_enum.h>

#define BFD_TEST(_cond, _comment)                                                                  \
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
bfd_shared_view_dispatch (vlib_main_t *vm, const char *node_name, u32 buffer_index,
			  u32 *forwarded_index)
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

static int
bfd_shared_view_success_test (vlib_main_t *vm, const char *node_name, u32 expected_error)
{
  vlib_buffer_t *root;
  vlib_buffer_t *forwarded;
  vlib_node_t *node;
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
  root->current_length = 1;
  ((u8 *) vlib_buffer_get_current (root))[0] = 0x5a;
  BFD_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	    "attach BFD shared-view descriptor");
  BFD_TEST (vlib_get_buffer (vm, buffers[1])->current_length == 0, "use headerless BFD descriptor");
  BFD_TEST (bfd_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index) == 0,
	    "dispatch BFD shared-view descriptor");
  BFD_TEST (forwarded_index != buffers[1], "replace BFD descriptor frame slot");
  forwarded = vlib_get_buffer (vm, forwarded_index);
  BFD_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
	    "forward ordinary replacement after BFD COW");
  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  BFD_TEST (node != 0, "find BFD input node");
  BFD_TEST (forwarded->error == vlib_node_get_runtime (vm, node->index)->errors[expected_error],
	    "preserve BFD packet disposition after COW");
  ((u8 *) vlib_buffer_get_current (forwarded))[0] = 0xa5;
  BFD_TEST (((u8 *) vlib_buffer_get_current (root))[0] == 0x5a,
	    "BFD replacement leaves canonical root unchanged");
  ret = 1;

done:
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
bfd_shared_view_failure_test (vlib_main_t *vm, const char *node_name)
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
  root->current_length = 1;
  BFD_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	    "attach malformed BFD descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  BFD_TEST (bfd_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index) == 0,
	    "dispatch BFD COW-failure descriptor");
  descriptor->next_buffer = descriptor_next;
  BFD_TEST (forwarded_index == buffers[1], "retain BFD input after COW failure");
  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  BFD_TEST (node != 0, "find BFD COW-failure node");
  BFD_TEST (descriptor->error ==
	      vlib_node_get_runtime (vm, node->index)->errors[BFD_UDP_ERROR_NO_BUFFERS],
	    "send BFD COW failure to no-buffers drop");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_bfd_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!bfd_shared_view_success_test (vm, "bfd-udp4-input", BFD_UDP_ERROR_BAD) ||
      !bfd_shared_view_success_test (vm, "bfd-udp6-input", BFD_UDP_ERROR_BAD) ||
      !bfd_shared_view_success_test (vm, "bfd-udp-echo4-input", BFD_UDP_ERROR_NONE) ||
      !bfd_shared_view_success_test (vm, "bfd-udp-echo6-input", BFD_UDP_ERROR_NONE) ||
      !bfd_shared_view_failure_test (vm, "bfd-udp4-input") ||
      !bfd_shared_view_failure_test (vm, "bfd-udp6-input") ||
      !bfd_shared_view_failure_test (vm, "bfd-udp-echo4-input") ||
      !bfd_shared_view_failure_test (vm, "bfd-udp-echo6-input"))
    return clib_error_return (0, "BFD shared-view test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_bfd_shared_view_command, static) = {
  .path = "test bfd-shared-view",
  .short_help = "test bfd-shared-view",
  .function = test_bfd_shared_view_fn,
};
