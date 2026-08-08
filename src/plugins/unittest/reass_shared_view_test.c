/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>

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
