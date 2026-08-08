/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <dhcp/dhcp_proxy.h>

#define DHCP_TEST(_cond, _comment)                                                                 \
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
dhcp_shared_view_dispatch (vlib_main_t *vm, const char *node_name, u32 buffer_index,
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
dhcp_shared_view_success_test (vlib_main_t *vm, const char *node_name, int is_dhcp4_client)
{
  vlib_buffer_t *forwarded;
  vlib_buffer_t *root;
  dhcp_header_t *header;
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
  root->current_length = is_dhcp4_client ? sizeof (*header) + 1 : 1;
  clib_memset (vlib_buffer_get_current (root), 0, root->current_length);
  ((u8 *) vlib_buffer_get_current (root))[0] = 0x5a;
  if (is_dhcp4_client)
    {
      header = vlib_buffer_get_current (root);
      header->options[0].option = DHCP_PACKET_OPTION_END;
    }

  DHCP_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	     "attach DHCP shared-view descriptor");
  DHCP_TEST (dhcp_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index) == 0,
	     "dispatch DHCP shared-view descriptor");
  DHCP_TEST (forwarded_index != buffers[1], "replace DHCP descriptor frame slot");
  forwarded = vlib_get_buffer (vm, forwarded_index);
  DHCP_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
	     "forward ordinary DHCP replacement after COW");
  ((u8 *) forwarded->data)[0] = 0xa5;
  DHCP_TEST (((u8 *) root->data)[0] == 0x5a, "DHCP replacement leaves canonical root unchanged");
  ret = 1;

done:
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
dhcp_shared_view_failure_test (vlib_main_t *vm, const char *node_name, u32 error_index)
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
  DHCP_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	     "attach malformed DHCP shared-view descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  DHCP_TEST (dhcp_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index) == 0,
	     "dispatch DHCP COW-failure descriptor");
  descriptor->next_buffer = descriptor_next;
  DHCP_TEST (forwarded_index == buffers[1], "retain DHCP input after COW failure");
  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  DHCP_TEST (node != 0, "find DHCP COW-failure node");
  DHCP_TEST (descriptor->error == vlib_node_get_runtime (vm, node->index)->errors[error_index],
	     "send DHCP COW failure to allocation-failure drop");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_dhcp_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!dhcp_shared_view_success_test (vm, "dhcp-proxy-to-server", 0) ||
      !dhcp_shared_view_success_test (vm, "dhcp-proxy-to-client", 1) ||
      !dhcp_shared_view_success_test (vm, "dhcpv6-proxy-to-server", 0) ||
      !dhcp_shared_view_success_test (vm, "dhcpv6-proxy-to-client", 0) ||
      !dhcp_shared_view_failure_test (vm, "dhcp-proxy-to-server", DHCP_PROXY_ERROR_ALLOC_FAIL) ||
      !dhcp_shared_view_failure_test (vm, "dhcp-proxy-to-client", DHCP_PROXY_ERROR_ALLOC_FAIL) ||
      !dhcp_shared_view_failure_test (vm, "dhcpv6-proxy-to-server",
				      DHCPV6_PROXY_ERROR_ALLOC_FAIL) ||
      !dhcp_shared_view_failure_test (vm, "dhcpv6-proxy-to-client", DHCPV6_PROXY_ERROR_ALLOC_FAIL))
    return clib_error_return (0, "DHCP shared-view test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_dhcp_shared_view_command, static) = {
  .path = "test dhcp-shared-view",
  .short_help = "test dhcp-shared-view",
  .function = test_dhcp_shared_view_fn,
};
