/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <map/map.h>

#define MAP_TEST(_cond, _comment)                                                                  \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	{                                                                                          \
	  fformat (stderr, "FAIL:%d: %s\\n", __LINE__, _comment);                                  \
	  goto done;                                                                               \
	}                                                                                          \
    }                                                                                              \
  while (0)

static void
map_shared_view_discard_pending (vlib_main_t *vm, u32 pending_len)
{
  vlib_pending_frame_t *pending;
  u32 i;

  for (i = pending_len; i < vec_len (vm->node_main.pending_frames); i++)
    {
      pending = vec_elt_at_index (vm->node_main.pending_frames, i);
      vlib_buffer_free (vm, vlib_frame_vector_args (pending->frame), pending->frame->n_vectors);
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

static void
map_shared_view_init_ip4 (vlib_buffer_t *buffer)
{
  ip4_header_t *ip = vlib_buffer_get_current (buffer);
  u32 i;

  clib_memset (ip, 0, 96);
  ip->ip_version_and_header_length = 0x45;
  ip->length = clib_host_to_net_u16 (96);
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = clib_host_to_net_u32 (0xc0000201);
  ip->dst_address.as_u32 = clib_host_to_net_u32 (0x0a000001);
  for (i = sizeof (*ip); i < 96; i++)
    ((u8 *) ip)[i] = i;
  ip->checksum = ip4_header_checksum (ip);
  buffer->current_length = 96;
}

static int
map_shared_view_dispatch (vlib_main_t *vm, u32 buffer_index, u32 pending_len)
{
  vlib_node_runtime_t *runtime;
  vlib_frame_t *frame;

  runtime = vlib_node_get_runtime (vm, ip4_map_node.index);
  frame = vlib_get_frame_to_node (vm, ip4_map_node.index);
  if (runtime == 0 || frame == 0)
    return -1;

  ((u32 *) vlib_frame_vector_args (frame))[0] = buffer_index;
  frame->n_vectors = 1;
  runtime->function (vm, runtime, frame);
  vlib_frame_free (vm, frame);

  return vec_len (vm->node_main.pending_frames) > pending_len ? 0 : -1;
}

static int
map_shared_view_success_test (vlib_main_t *vm)
{
  ip4_address_t ip4_prefix = { .as_u32 = clib_host_to_net_u32 (0x0a000000) };
  ip6_address_t ip6_prefix = { .as_u64 = { clib_host_to_net_u64 (0x20010db800000000), 0 } };
  ip6_address_t ip6_src = { .as_u64 = { clib_host_to_net_u64 (0x20010db800000001), 0 } };
  vlib_pending_frame_t *pending;
  vlib_buffer_t *root;
  ip4_header_t *ip;
  u32 buffers[2];
  u32 domain_index = ~0;
  u32 pending_len = vec_len (vm->node_main.pending_frames);
  u32 i;
  u32 n_alloc;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }

  MAP_TEST (map_create_domain (&ip4_prefix, 8, &ip6_prefix, 32, &ip6_src, 128, 0, 0, 0,
			       &domain_index, 80, 0, 0) == 0,
	    "create MAP domain");
  root = vlib_get_buffer (vm, buffers[0]);
  map_shared_view_init_ip4 (root);
  MAP_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	    "attach MAP shared-view descriptor");
  MAP_TEST (vlib_get_buffer (vm, buffers[1])->current_length == 0,
	    "use headerless descriptor for MAP node");
  MAP_TEST (map_shared_view_dispatch (vm, buffers[1], pending_len) == 0,
	    "dispatch MAP shared-view descriptor");

  for (i = pending_len; i < vec_len (vm->node_main.pending_frames); i++)
    {
      u32 j;

      pending = vec_elt_at_index (vm->node_main.pending_frames, i);
      for (j = 0; j < pending->frame->n_vectors; j++)
	MAP_TEST (!vlib_buffer_shared_view_is_shared (
		    vlib_get_buffer (vm, ((u32 *) vlib_frame_vector_args (pending->frame))[j])),
		  "forward ordinary MAP fragments after shared-view COW");
    }

  ip = vlib_buffer_get_current (root);
  MAP_TEST (root->current_length == 96 && ip->ttl == 64, "leave canonical MAP root unchanged");
  ret = 1;

done:
  map_shared_view_discard_pending (vm, pending_len);
  if (domain_index != ~0)
    map_delete_domain (domain_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
map_shared_view_failure_test (vlib_main_t *vm)
{
  vlib_buffer_t *descriptor;
  vlib_node_t *node;
  vlib_pending_frame_t *pending;
  u32 buffers[2];
  u32 pending_len = vec_len (vm->node_main.pending_frames);
  u32 n_alloc;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }

  map_shared_view_init_ip4 (vlib_get_buffer (vm, buffers[0]));
  MAP_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	    "attach malformed MAP descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor->next_buffer = ~0;
  MAP_TEST (map_shared_view_dispatch (vm, buffers[1], pending_len) == 0,
	    "dispatch malformed MAP descriptor");
  pending = vec_elt_at_index (vm->node_main.pending_frames, pending_len);
  node = vlib_get_node_by_name (vm, (u8 *) "ip4-map");
  MAP_TEST (pending->frame->n_vectors == 1 &&
	      ((u32 *) vlib_frame_vector_args (pending->frame))[0] == buffers[1] && node != 0 &&
	      descriptor->error ==
		vlib_node_get_runtime (vm, node->index)->errors[MAP_ERROR_NO_BUFFERS],
	    "drop retained descriptor with MAP no-buffer error");
  descriptor->next_buffer = buffers[0];
  ret = 1;

done:
  map_shared_view_discard_pending (vm, pending_len);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_map_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!map_shared_view_success_test (vm) || !map_shared_view_failure_test (vm))
    return clib_error_return (0, "MAP shared-view test failed");
  return 0;
}

VLIB_CLI_COMMAND (test_map_shared_view_command, static) = {
  .path = "test map-shared-view",
  .short_help = "test map-shared-view",
  .function = test_map_shared_view_fn,
};
