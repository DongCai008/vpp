/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/punt.h>

#define PUNT_SHARED_VIEW_TEST_N_INPUTS 5

#define PUNT_SHARED_VIEW_TEST(_cond, _comment)                                                     \
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
  vlib_punt_hdl_t owner;
  vlib_punt_hdl_t client0;
  vlib_punt_hdl_t client1;
  vlib_punt_reason_t reason;
  vlib_punt_reason_t single_reason;
  u8 initialized;
} punt_shared_view_test_main_t;

typedef struct
{
  u32 node_index;
  vlib_punt_reason_t reason;
} punt_shared_view_trace_t;

static punt_shared_view_test_main_t punt_shared_view_test_main;
static punt_shared_view_trace_t punt_shared_view_traces[PUNT_SHARED_VIEW_TEST_N_INPUTS * 2];
static vlib_punt_reason_t punt_shared_view_trace_data[PUNT_SHARED_VIEW_TEST_N_INPUTS * 2];
static u32 punt_shared_view_trace_count;

VLIB_NODE_FN (punt_shared_view_client0_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (punt_shared_view_client0_node) = {
  .name = "punt-shared-view-client-0",
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (punt_shared_view_client1_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (punt_shared_view_client1_node) = {
  .name = "punt-shared-view-client-1",
  .vector_size = sizeof (u32),
};

static void *
punt_shared_view_add_trace (struct vlib_main_t *vm, struct vlib_node_runtime_t *runtime,
			    struct vlib_buffer_t *buffer, u32 n_data_bytes)
{
  vlib_node_runtime_t *node = (void *) runtime;
  vlib_buffer_t *buffer0 = (void *) buffer;
  punt_shared_view_trace_t *trace;

  CLIB_UNUSED (vlib_main_t * vm0) = (void *) vm;
  ASSERT (n_data_bytes == sizeof (punt_shared_view_trace_data[0]));
  ASSERT (punt_shared_view_trace_count < ARRAY_LEN (punt_shared_view_traces));
  trace = &punt_shared_view_traces[punt_shared_view_trace_count++];
  trace->node_index = node->node_index;
  trace->reason = buffer0->punt_reason;
  return &punt_shared_view_trace_data[punt_shared_view_trace_count - 1];
}

static void
punt_shared_view_clear_pending_frames (vlib_main_t *vm, u32 pending_len)
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
punt_shared_view_dispatch (vlib_main_t *vm, u32 *buffer_indices, u32 n_buffers,
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

  node = vlib_get_node_by_name (vm, (u8 *) "punt-dispatch");
  if (node == 0)
    return -1;
  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  if (frame == 0 || n_buffers > VLIB_FRAME_SIZE)
    return -1;

  pending_len = vec_len (vm->node_main.pending_frames);
  *n_forwarded = 0;
  clib_memcpy_fast (vlib_frame_vector_args (frame), buffer_indices,
		    n_buffers * sizeof (buffer_indices[0]));
  frame->n_vectors = n_buffers;
  runtime->function (vm, runtime, frame);

  for (i = pending_len; i < vec_len (vm->node_main.pending_frames); i++)
    {
      pending = vec_elt_at_index (vm->node_main.pending_frames, i);
      u32 *from = vlib_frame_vector_args (pending->frame);
      u32 j;

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
  punt_shared_view_clear_pending_frames (vm, pending_len);
  vlib_frame_free (vm, frame);
  return ret;
}

static int
punt_shared_view_setup (void)
{
  punt_shared_view_test_main_t *tm = &punt_shared_view_test_main;

  if (tm->initialized)
    return 0;

  tm->owner = vlib_punt_client_register ("punt-shared-view-owner");
  tm->client0 = vlib_punt_client_register ("punt-shared-view-client-0");
  tm->client1 = vlib_punt_client_register ("punt-shared-view-client-1");
  if (tm->owner < 0 || tm->client0 < 0 || tm->client1 < 0 ||
      vlib_punt_reason_alloc (tm->owner, "shared-view", 0, 0, &tm->reason, 0, 0) ||
      vlib_punt_reason_alloc (tm->owner, "shared-view-single", 0, 0, &tm->single_reason, 0, 0) ||
      vlib_punt_register (tm->client0, tm->reason, "punt-shared-view-client-0") ||
      vlib_punt_register (tm->client1, tm->reason, "punt-shared-view-client-1") ||
      vlib_punt_register (tm->client0, tm->single_reason, "punt-shared-view-client-0"))
    return -1;

  tm->initialized = 1;
  return 0;
}

static int
punt_shared_view_success_test (vlib_main_t *vm)
{
  punt_shared_view_test_main_t *tm = &punt_shared_view_test_main;
  vlib_add_trace_callback_t *saved_add_trace_callback;
  vlib_buffer_t *root;
  vlib_buffer_t *forwarded;
  vlib_node_t *client0_node;
  vlib_node_t *client1_node;
  vlib_node_t *punt_node;
  u32 buffers[PUNT_SHARED_VIEW_TEST_N_INPUTS * 2];
  u32 descriptor_indices[PUNT_SHARED_VIEW_TEST_N_INPUTS];
  u32 root_indices[PUNT_SHARED_VIEW_TEST_N_INPUTS];
  u32 forwarded_indices[PUNT_SHARED_VIEW_TEST_N_INPUTS * 2];
  u32 forwarded_runtime_indices[PUNT_SHARED_VIEW_TEST_N_INPUTS * 2];
  u32 n_forwarded = 0;
  u32 n_alloc;
  u8 saw_client0[PUNT_SHARED_VIEW_TEST_N_INPUTS] = {};
  u8 saw_client1[PUNT_SHARED_VIEW_TEST_N_INPUTS] = {};
  u8 n_client_frames[PUNT_SHARED_VIEW_TEST_N_INPUTS] = {};
  u8 dispatched = 0;
  u32 i;
  int ret = 0;

  clib_memset (forwarded_indices, ~0, sizeof (forwarded_indices));
  clib_memset (forwarded_runtime_indices, ~0, sizeof (forwarded_runtime_indices));
  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }
  for (i = 0; i < PUNT_SHARED_VIEW_TEST_N_INPUTS; i++)
    {
      root_indices[i] = buffers[2 * i];
      descriptor_indices[i] = buffers[2 * i + 1];
    }
  for (i = 0; i < PUNT_SHARED_VIEW_TEST_N_INPUTS; i++)
    {
      root = vlib_get_buffer (vm, root_indices[i]);
      root->current_length = 1;
      root->data[0] = 0x50 + i;
      root->flags |= VLIB_BUFFER_IS_TRACED;
      PUNT_SHARED_VIEW_TEST (
	vlib_buffer_shared_view_attach (vm, descriptor_indices[i], root_indices[i]) == 0,
	"attach punt shared-view descriptor");
      PUNT_SHARED_VIEW_TEST (vlib_get_buffer (vm, descriptor_indices[i])->current_length == 0,
			     "use headerless punt descriptor");
      vlib_get_buffer (vm, descriptor_indices[i])->punt_reason = tm->reason;
      vlib_get_buffer (vm, descriptor_indices[i])->flags |= VLIB_BUFFER_IS_TRACED;
    }

  punt_shared_view_trace_count = 0;
  clib_memset (punt_shared_view_traces, 0, sizeof (punt_shared_view_traces));
  clib_memset (punt_shared_view_trace_data, 0, sizeof (punt_shared_view_trace_data));
  saved_add_trace_callback = vm->trace_main.add_trace_callback;
  vm->trace_main.add_trace_callback = punt_shared_view_add_trace;

  PUNT_SHARED_VIEW_TEST (
    punt_shared_view_dispatch (vm, descriptor_indices, ARRAY_LEN (descriptor_indices),
			       forwarded_indices, forwarded_runtime_indices,
			       ARRAY_LEN (forwarded_indices), &n_forwarded) == 0,
    "dispatch punt shared-view descriptor");
  dispatched = 1;
  vm->trace_main.add_trace_callback = saved_add_trace_callback;

  punt_node = vlib_get_node_by_name (vm, (u8 *) "punt-dispatch");
  client0_node = vlib_get_node_by_name (vm, (u8 *) "punt-shared-view-client-0");
  client1_node = vlib_get_node_by_name (vm, (u8 *) "punt-shared-view-client-1");
  PUNT_SHARED_VIEW_TEST (punt_node && client0_node && client1_node, "find punt test nodes");

  PUNT_SHARED_VIEW_TEST (n_forwarded == ARRAY_LEN (forwarded_indices),
			 "dispatch every original and replica punt frame");
  for (i = 0; i < n_forwarded; i++)
    {
      u32 source;

      forwarded = vlib_get_buffer (vm, forwarded_indices[i]);
      source = ((u8 *) vlib_buffer_get_current (forwarded))[0] - 0x50;
      PUNT_SHARED_VIEW_TEST (source < PUNT_SHARED_VIEW_TEST_N_INPUTS,
			     "preserve punt packet identity after COW");
      PUNT_SHARED_VIEW_TEST (forwarded_runtime_indices[i] == client0_node->runtime_index ||
			       forwarded_runtime_indices[i] == client1_node->runtime_index,
			     "dispatch punt frame to registered client");
      PUNT_SHARED_VIEW_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
			     "dispatch ordinary punt replacement");
      PUNT_SHARED_VIEW_TEST (forwarded->punt_reason == tm->reason,
			     "preserve punt reason for every client");
      saw_client0[source] |= forwarded_runtime_indices[i] == client0_node->runtime_index;
      saw_client1[source] |= forwarded_runtime_indices[i] == client1_node->runtime_index;
      n_client_frames[source]++;
      ((u8 *) vlib_buffer_get_current (forwarded))[0] = 0xa0 + i;
    }
  for (i = 0; i < PUNT_SHARED_VIEW_TEST_N_INPUTS; i++)
    {
      root = vlib_get_buffer (vm, root_indices[i]);
      PUNT_SHARED_VIEW_TEST (saw_client0[i] && saw_client1[i] && n_client_frames[i] == 2,
			     "dispatch original and replica to both clients");
      PUNT_SHARED_VIEW_TEST (root->data[0] == 0x50 + i,
			     "leave every punt canonical root unchanged");
    }

  PUNT_SHARED_VIEW_TEST (punt_shared_view_trace_count == ARRAY_LEN (forwarded_indices),
			 "trace every original and replica punt frame");
  for (i = 0; i < punt_shared_view_trace_count; i++)
    PUNT_SHARED_VIEW_TEST (punt_shared_view_traces[i].node_index == punt_node->index &&
			     punt_shared_view_traces[i].reason == tm->reason,
			   "preserve punt reason in trace metadata");
  ret = 1;

done:
  if (vm->trace_main.add_trace_callback == punt_shared_view_add_trace)
    vm->trace_main.add_trace_callback = saved_add_trace_callback;
  for (i = 0; i < n_forwarded; i++)
    vlib_buffer_free_one (vm, forwarded_indices[i]);
  if (!dispatched)
    for (i = 0; i < PUNT_SHARED_VIEW_TEST_N_INPUTS; i++)
      vlib_buffer_free_one (vm, descriptor_indices[i]);
  for (i = 0; i < PUNT_SHARED_VIEW_TEST_N_INPUTS; i++)
    vlib_buffer_free_one (vm, root_indices[i]);
  return ret;
}

static int
punt_shared_view_original_slot_test (vlib_main_t *vm)
{
  punt_shared_view_test_main_t *tm = &punt_shared_view_test_main;
  vlib_buffer_t *descriptor = 0;
  vlib_buffer_t *forwarded;
  vlib_buffer_t *root;
  u32 buffers[2];
  u32 forwarded_indices[1] = { ~0 };
  u32 forwarded_runtime_indices[1] = { ~0 };
  u32 n_forwarded = 0;
  u32 n_alloc;
  u32 original_index;
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
  PUNT_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			 "attach original-slot punt descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor->punt_reason = tm->single_reason;

  PUNT_SHARED_VIEW_TEST (
    punt_shared_view_dispatch (vm, &buffers[1], 1, forwarded_indices, forwarded_runtime_indices,
			       ARRAY_LEN (forwarded_indices), &n_forwarded) == 0,
    "dispatch original-slot punt descriptor");
  PUNT_SHARED_VIEW_TEST (n_forwarded == 1, "dispatch exactly one original-slot punt frame");

  /* The single-client reason has no clone that could reuse the descriptor. */
  original_index = forwarded_indices[0];
  forwarded = vlib_get_buffer (vm, original_index);
  PUNT_SHARED_VIEW_TEST (original_index != buffers[1] &&
			   !vlib_buffer_shared_view_is_shared (forwarded),
			 "replace original-slot punt descriptor");
  PUNT_SHARED_VIEW_TEST (forwarded->punt_reason == tm->single_reason,
			 "preserve original-slot punt reason");
  ((u8 *) vlib_buffer_get_current (forwarded))[0] = 0xa5;
  PUNT_SHARED_VIEW_TEST (root->data[0] == 0x5a, "leave original-slot root unchanged");
  ret = 1;

done:
  if (n_forwarded)
    vlib_buffer_free_one (vm, forwarded_indices[0]);
  else
    vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
punt_shared_view_failure_test (vlib_main_t *vm)
{
  punt_shared_view_test_main_t *tm = &punt_shared_view_test_main;
  vlib_buffer_t *descriptor = 0;
  vlib_buffer_t *root;
  vlib_node_t *node;
  vlib_node_runtime_t *runtime;
  u32 buffers[2];
  u32 descriptor_next = 0;
  u32 forwarded_indices[2] = { ~0, ~0 };
  u32 forwarded_runtime_indices[2] = { ~0, ~0 };
  u32 n_forwarded = 0;
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
  root->data[0] = 0x5a;
  PUNT_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			 "attach malformed punt descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor->punt_reason = tm->reason;
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];

  PUNT_SHARED_VIEW_TEST (
    punt_shared_view_dispatch (vm, &buffers[1], 1, forwarded_indices, forwarded_runtime_indices,
			       ARRAY_LEN (forwarded_indices), &n_forwarded) == 0,
    "dispatch malformed punt descriptor");
  descriptor->next_buffer = descriptor_next;

  node = vlib_get_node_by_name (vm, (u8 *) "punt-dispatch");
  runtime = vlib_node_get_runtime (vm, node->index);
  PUNT_SHARED_VIEW_TEST (n_forwarded == 1 && forwarded_indices[0] == buffers[1],
			 "retain punt descriptor after COW failure");
  PUNT_SHARED_VIEW_TEST (forwarded_runtime_indices[0] ==
			   vlib_node_runtime_get_next_frame (vm, runtime, 0)->node_runtime_index,
			 "send punt COW failure to drop");
  PUNT_SHARED_VIEW_TEST (descriptor->error == runtime->errors[node->n_errors - 1],
			 "account punt COW failure separately from replication");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  if (n_forwarded)
    vlib_buffer_free_one (vm, forwarded_indices[0]);
  else
    vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
punt_shared_view_helper_test (vlib_main_t *vm)
{
  vlib_buffer_t *buffer = 0;
  vlib_buffer_t *descriptor = 0;
  vlib_buffer_t *root;
  u32 buffers[2];
  u32 buffer_index = ~0;
  u32 copy_index;
  u32 descriptor_next = 0;
  u32 n_alloc = 0;
  u8 restore_next = 0;
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
  PUNT_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			 "attach pointer helper descriptor");

  buffer_index = buffers[1];
  descriptor = buffer = vlib_get_buffer (vm, buffer_index);
  PUNT_SHARED_VIEW_TEST (
    vlib_buffer_shared_view_make_writable_and_get (vm, &buffer_index, &buffer) == 0,
    "make pointer helper descriptor writable");
  PUNT_SHARED_VIEW_TEST (buffer_index != buffers[1] &&
			   buffer == vlib_get_buffer (vm, buffer_index) && buffer != descriptor &&
			   !vlib_buffer_shared_view_is_shared (buffer),
			 "reload ordinary pointer helper replacement");
  PUNT_SHARED_VIEW_TEST (((u8 *) vlib_buffer_get_current (buffer))[0] == 0x5a,
			 "preserve pointer helper payload");
  copy_index = buffer_index;
  descriptor = buffer;
  PUNT_SHARED_VIEW_TEST (
    vlib_buffer_shared_view_make_writable_and_get (vm, &buffer_index, &buffer) == 0 &&
      buffer_index == copy_index && buffer == descriptor,
    "retain ordinary pointer helper outputs");
  vlib_buffer_free_one (vm, buffer_index);
  vlib_buffer_free_one (vm, buffers[0]);
  n_alloc = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return ret;
    }

  root = vlib_get_buffer (vm, buffers[0]);
  root->current_length = 1;
  PUNT_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			 "attach malformed pointer helper descriptor");
  buffer_index = buffers[1];
  descriptor = buffer = vlib_get_buffer (vm, buffer_index);
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffer_index;
  restore_next = 1;
  PUNT_SHARED_VIEW_TEST (
    vlib_buffer_shared_view_make_writable_and_get (vm, &buffer_index, &buffer) != 0 &&
      buffer_index == buffers[1] && buffer == descriptor,
    "preserve pointer helper input on malformed COW failure");
  descriptor->next_buffer = descriptor_next;
  restore_next = 0;
  vlib_buffer_free_one (vm, buffers[1]);
  vlib_buffer_free_one (vm, buffers[0]);
  return 1;

done:
  if (n_alloc == ARRAY_LEN (buffers))
    {
      if (restore_next)
	descriptor->next_buffer = descriptor_next;
      if (buffer_index != ~0)
	vlib_buffer_free_one (vm, buffer_index);
      else
	vlib_buffer_free_one (vm, buffers[1]);
      vlib_buffer_free_one (vm, buffers[0]);
    }
  return ret;
}

static clib_error_t *
test_punt_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (punt_shared_view_setup () || !punt_shared_view_success_test (vm) ||
      !punt_shared_view_original_slot_test (vm) || !punt_shared_view_failure_test (vm) ||
      !punt_shared_view_helper_test (vm))
    return clib_error_return (0, "punt shared-view test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_punt_shared_view_command, static) = {
  .path = "test punt-shared-view",
  .short_help = "test punt-shared-view",
  .function = test_punt_shared_view_fn,
};
