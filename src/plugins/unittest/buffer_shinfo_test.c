/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/buffer_shinfo.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/tcp/tcp_packet.h>

#define SHINFO_TEST(_cond, _fmt, _args...)                                                         \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	return clib_error_return (0, _fmt, ##_args);                                               \
    }                                                                                              \
  while (0)

static clib_error_t *
buffer_shinfo_cow_test (vlib_main_t *vm)
{
  vlib_buffer_t *copy, *descriptor, *root, *root_view, *tail;
  vnet_buffer_shinfo_t shinfo;
  u32 buffers[2];
  u32 descriptor_cow;
  u32 descriptor_index;
  u32 root_cow;
  u32 root_view_index;
  u32 saved_next;
  u32 i;

  if (vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers)) != ARRAY_LEN (buffers))
    return clib_error_return (0, "COW buffer allocation failed");

  root = vlib_get_buffer (vm, buffers[0]);
  tail = vlib_get_buffer (vm, buffers[1]);
  root->current_data = 0;
  root->current_length = 64;
  root->next_buffer = buffers[1];
  root->total_length_not_including_first_buffer = 11;
  root->flags |= (VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_IS_IP4);
  vnet_buffer (root)->sw_if_index[VLIB_RX] = 123;
  vnet_buffer (root)->sw_if_index[VLIB_TX] = 456;
  tail->current_data = 7;
  tail->current_length = 11;
  for (i = 0; i < root->current_length; i++)
    root->data[i] = i;
  for (i = 0; i < tail->current_length; i++)
    tail->data[tail->current_data + i] = 64 + i;

  SHINFO_TEST (vnet_buffer_shinfo_clone (vm, buffers[0], &descriptor_index) == 0,
	       "COW descriptor clone failed");
  descriptor = vlib_get_buffer (vm, descriptor_index);
  SHINFO_TEST (descriptor->next_buffer == buffers[0] && root->ref_count == 2 &&
		 tail->ref_count == 2,
	       "COW descriptor did not retain the canonical root");

  descriptor_cow = descriptor_index;
  SHINFO_TEST (vnet_buffer_shinfo_cow (vm, &descriptor_cow) == 0 &&
		 descriptor_cow != descriptor_index,
	       "descriptor COW failed");
  copy = vlib_get_buffer (vm, descriptor_cow);
  SHINFO_TEST ((copy->flags & (VNET_BUFFER_F_SHARED_ROOT | VNET_BUFFER_F_SHARED_DESCRIPTOR)) == 0 &&
		 (copy->flags & VNET_BUFFER_F_IS_IP4) &&
		 vnet_buffer (copy)->sw_if_index[VLIB_RX] == 123 &&
		 vnet_buffer (copy)->sw_if_index[VLIB_TX] == 456,
	       "descriptor COW did not preserve root metadata");
  SHINFO_TEST (copy->current_data == root->current_data &&
		 copy->current_length == root->current_length &&
		 (copy->flags & VLIB_BUFFER_NEXT_PRESENT) &&
		 clib_memcmp (vlib_buffer_get_current (copy), vlib_buffer_get_current (root),
			      root->current_length) == 0,
	       "descriptor COW root data or topology is wrong");
  copy = vlib_get_buffer (vm, copy->next_buffer);
  SHINFO_TEST ((copy->flags & (VNET_BUFFER_F_SHARED_ROOT | VNET_BUFFER_F_SHARED_DESCRIPTOR)) == 0 &&
		 copy->current_data == tail->current_data &&
		 copy->current_length == tail->current_length &&
		 (copy->flags & VLIB_BUFFER_NEXT_PRESENT) == 0 &&
		 clib_memcmp (vlib_buffer_get_current (copy), vlib_buffer_get_current (tail),
			      tail->current_length) == 0,
	       "descriptor COW tail data or topology is wrong");
  SHINFO_TEST (vnet_buffer_shinfo_get (vm, descriptor_cow, &shinfo) == 0 &&
		 shinfo.root_buffer_index == descriptor_cow && shinfo.data_bytes == 75 &&
		 shinfo.span_count == 2 && root->ref_count == 1 && tail->ref_count == 1,
	       "descriptor COW did not release exactly one native reference");

  copy = vlib_get_buffer (vm, descriptor_cow);
  SHINFO_TEST (vnet_buffer_shinfo_cow (vm, &descriptor_cow) == 0 &&
		 descriptor_cow == vlib_get_buffer_index (vm, copy) && copy->ref_count == 1,
	       "repeated descriptor COW was not a no-op");

  SHINFO_TEST (vnet_buffer_shinfo_clone (vm, buffers[0], &root_view_index) == 0,
	       "COW root view clone failed");
  root_view = vlib_get_buffer (vm, root_view_index);
  SHINFO_TEST (root->ref_count == 2 && tail->ref_count == 2,
	       "COW root view did not retain the canonical root");

  saved_next = root_view->next_buffer;
  root_view->next_buffer = buffers[1];
  i = root_view_index;
  SHINFO_TEST (vnet_buffer_shinfo_cow (vm, &i) != 0 && i == root_view_index &&
		 root->ref_count == 2 && tail->ref_count == 2,
	       "failed COW changed a descriptor or its native references");
  root_view->next_buffer = saved_next;

  root_cow = buffers[0];
  SHINFO_TEST (vnet_buffer_shinfo_cow (vm, &root_cow) == 0 && root_cow != buffers[0],
	       "root COW failed");
  SHINFO_TEST (root_view->next_buffer == buffers[0] && root->ref_count == 1 && tail->ref_count == 1,
	       "root COW did not release exactly one native reference");
  copy = vlib_get_buffer (vm, root_cow);
  SHINFO_TEST ((copy->flags & (VNET_BUFFER_F_SHARED_ROOT | VNET_BUFFER_F_SHARED_DESCRIPTOR)) == 0 &&
		 copy->current_data == 0 && copy->current_length == 64 &&
		 (copy->flags & VLIB_BUFFER_NEXT_PRESENT) &&
		 clib_memcmp (vlib_buffer_get_current (copy),
			      vlib_buffer_get_current (vlib_get_buffer (vm, descriptor_cow)),
			      64) == 0,
	       "root COW data or shared state is wrong");
  copy = vlib_get_buffer (vm, copy->next_buffer);
  SHINFO_TEST ((copy->flags & (VNET_BUFFER_F_SHARED_ROOT | VNET_BUFFER_F_SHARED_DESCRIPTOR)) == 0 &&
		 copy->current_data == 7 && copy->current_length == 11 &&
		 (copy->flags & VLIB_BUFFER_NEXT_PRESENT) == 0,
	       "root COW topology is wrong");

  copy = vlib_get_buffer (vm, root_cow);
  SHINFO_TEST (vnet_buffer_shinfo_cow (vm, &root_cow) == 0 &&
		 root_cow == vlib_get_buffer_index (vm, copy) && copy->ref_count == 1,
	       "repeated root COW was not a no-op");

  vlib_buffer_free_one (vm, descriptor_cow);
  vlib_buffer_free_one (vm, root_cow);
  vlib_buffer_free_one (vm, root_view_index);
  return 0;
}

static clib_error_t *
buffer_shinfo_test (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vnet_buffer_shinfo_span_t span;
  vnet_buffer_shinfo_t shinfo;
  ip4_header_t *ip4;
  vlib_buffer_t *root, *tail;
  u32 buffers[2];
  u32 clones[VLIB_BUFFER_MAX_CLONE - 1];
  u32 invalid_index = 0xdecafbad;
  u32 saved_next, saved_flags;
  u8 saved_pool;
  u32 n_clones = 0;

  clib_error_t *error;

  error = buffer_shinfo_cow_test (vm);
  if (error)
    return error;

  if (vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers)) != ARRAY_LEN (buffers))
    return clib_error_return (0, "buffer allocation failed");

  root = vlib_get_buffer (vm, buffers[0]);
  tail = vlib_get_buffer (vm, buffers[1]);
  root->current_data = 0;
  root->current_length = 1280;
  root->next_buffer = buffers[1];
  root->total_length_not_including_first_buffer = 20;
  root->flags |= VLIB_BUFFER_NEXT_PRESENT;
  tail->current_data = 3;
  tail->current_length = 20;

  SHINFO_TEST (vnet_buffer_shinfo_get (vm, buffers[0], &shinfo) == 0, "root query failed");
  SHINFO_TEST (shinfo.root_buffer_index == buffers[0] && shinfo.data_bytes == 1300 &&
		 shinfo.span_count == 2 && shinfo.chain_buffers == 2 && shinfo.gso_enabled == 0 &&
		 shinfo.gso_type == VNET_BUFFER_SHINFO_GSO_TYPE_NONE && shinfo.gso_size == 0 &&
		 shinfo.gso_l4_header_size == 0,
	       "root aggregate is wrong");
  SHINFO_TEST (vnet_buffer_shinfo_get_span (vm, buffers[0], 1, &span) == 0 &&
		 span.buffer_index == buffers[1] && span.data_offset == 3 && span.length == 20,
	       "root span is wrong");
  SHINFO_TEST (vnet_buffer_shinfo_get_span (vm, buffers[0], 2, &span) != 0,
	       "out-of-range span was accepted");

  saved_next = root->next_buffer;
  root->next_buffer = invalid_index;
  SHINFO_TEST (vnet_buffer_shinfo_get (vm, buffers[0], &shinfo) != 0,
	       "invalid next index was accepted");
  root->next_buffer = saved_next;

  saved_flags = tail->flags;
  tail->flags |= VLIB_BUFFER_NEXT_PRESENT;
  tail->next_buffer = buffers[0];
  SHINFO_TEST (vnet_buffer_shinfo_get (vm, buffers[0], &shinfo) != 0, "cycle was accepted");
  tail->flags = saved_flags;

  tail->current_length = 0;
  SHINFO_TEST (vnet_buffer_shinfo_get (vm, buffers[0], &shinfo) != 0,
	       "zero-length segment was accepted");
  tail->current_length = 20;

  tail->current_data = vlib_get_buffer_pool (vm, tail->buffer_pool_index)->data_size;
  tail->current_length = 1;
  SHINFO_TEST (vnet_buffer_shinfo_get (vm, buffers[0], &shinfo) != 0,
	       "out-of-range segment was accepted");
  tail->current_data = 3;
  tail->current_length = 20;

  saved_pool = tail->buffer_pool_index;
  tail->buffer_pool_index = ~0;
  SHINFO_TEST (vnet_buffer_shinfo_get (vm, buffers[0], &shinfo) != 0, "invalid pool was accepted");
  tail->buffer_pool_index = saved_pool;

  clib_memset (root->data, 0, root->current_length);
  ip4 = (ip4_header_t *) root->data;
  ip4->ip_version_and_header_length = IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
  ip4->protocol = IP_PROTOCOL_TCP;
  root->flags |= (VNET_BUFFER_F_GSO | VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_OFFLOAD |
		  VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
  vnet_buffer (root)->oflags = VNET_BUFFER_OFFLOAD_F_TCP_CKSUM;
  vnet_buffer (root)->l3_hdr_offset = 0;
  vnet_buffer (root)->l4_hdr_offset = sizeof (*ip4);
  vnet_buffer2 (root)->gso_size = 1200;
  vnet_buffer2 (root)->gso_l4_hdr_sz = sizeof (tcp_header_t);
  SHINFO_TEST (vnet_buffer_shinfo_get (vm, buffers[0], &shinfo) == 0 && shinfo.gso_enabled &&
		 shinfo.gso_type == VNET_BUFFER_SHINFO_GSO_TYPE_TCP4 && shinfo.gso_size == 1200 &&
		 shinfo.gso_l4_header_size == 20,
	       "GSO root query is wrong");

  root->flags |= VNET_BUFFER_F_IS_IP6;
  SHINFO_TEST (vnet_buffer_shinfo_get (vm, buffers[0], &shinfo) != 0,
	       "dual-family GSO was accepted");
  root->flags &= ~VNET_BUFFER_F_IS_IP6;

  invalid_index = 0xdecafbad;
  SHINFO_TEST (vnet_buffer_shinfo_clone (vm, buffers[0], &invalid_index) != 0 &&
		 invalid_index == 0xdecafbad && root->ref_count == 1 && tail->ref_count == 1 &&
		 (root->flags & VNET_BUFFER_F_SHARED_ROOT) == 0,
	       "GSO clone changed root state or published a descriptor");
  root->flags &= ~(VNET_BUFFER_F_GSO | VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		   VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
  vnet_buffer (root)->l3_hdr_offset = 0;
  vnet_buffer (root)->l4_hdr_offset = 0;
  vnet_buffer2 (root)->gso_size = 0;
  vnet_buffer2 (root)->gso_l4_hdr_sz = 0;

  invalid_index = 0xdecafbad;
  SHINFO_TEST (vnet_buffer_shinfo_clone (vm, buffers[0], &invalid_index) != 0 &&
		 invalid_index == 0xdecafbad && root->ref_count == 1 && tail->ref_count == 1 &&
		 (root->flags & VNET_BUFFER_F_SHARED_ROOT) == 0,
	       "checksum-offload clone changed root state or published a descriptor");
  root->flags &= ~VNET_BUFFER_F_OFFLOAD;
  vnet_buffer (root)->oflags = 0;

  SHINFO_TEST (vnet_buffer_shinfo_clone (vm, buffers[0], &clones[n_clones]) == 0,
	       "root clone failed");
  n_clones++;
  SHINFO_TEST (vnet_buffer_shinfo_clone (vm, clones[0], &clones[n_clones]) == 0,
	       "clone-of-clone failed");
  n_clones++;
  SHINFO_TEST (vlib_get_buffer (vm, clones[0])->next_buffer == buffers[0] &&
		 vlib_get_buffer (vm, clones[1])->next_buffer == buffers[0] &&
		 (vlib_get_buffer (vm, clones[0])->flags & VNET_BUFFER_F_SHARED_DESCRIPTOR) &&
		 (vlib_get_buffer (vm, clones[0])->flags & VNET_BUFFER_F_SHARED_ROOT) == 0 &&
		 (root->flags & VNET_BUFFER_F_SHARED_ROOT),
	       "clone root resolution is wrong");
  SHINFO_TEST (vnet_buffer_shinfo_get (vm, clones[1], &shinfo) == 0 &&
		 shinfo.root_buffer_index == buffers[0] && shinfo.data_bytes == 1300 &&
		 (vlib_get_buffer (vm, clones[1])->flags & VNET_BUFFER_F_GSO) == 0 &&
		 vnet_buffer2 (vlib_get_buffer (vm, clones[1]))->gso_size == 0,
	       "clone query or GSO rejection is wrong");
  SHINFO_TEST (root->ref_count == 3 && tail->ref_count == 3, "clone native references are wrong");

  saved_next = vlib_get_buffer (vm, clones[0])->next_buffer;
  vlib_get_buffer (vm, clones[0])->next_buffer = buffers[1];
  SHINFO_TEST (vnet_buffer_shinfo_get (vm, clones[0], &shinfo) != 0,
	       "descriptor-to-nonroot link was accepted");
  vlib_get_buffer (vm, clones[0])->next_buffer = saved_next;

  while (n_clones < ARRAY_LEN (clones))
    {
      SHINFO_TEST (vnet_buffer_shinfo_clone (vm, clones[0], &clones[n_clones]) == 0,
		   "clone capacity was reached early");
      n_clones++;
    }
  SHINFO_TEST (root->ref_count == VLIB_BUFFER_MAX_CLONE && tail->ref_count == VLIB_BUFFER_MAX_CLONE,
	       "clone capacity has the wrong native reference count");
  SHINFO_TEST (vnet_buffer_shinfo_clone (vm, clones[0], &invalid_index) != 0 &&
		 invalid_index == 0xdecafbad,
	       "capacity failure changed the output or was accepted");

  vlib_buffer_free_one (vm, clones[0]);
  SHINFO_TEST (root->ref_count == VLIB_BUFFER_MAX_CLONE - 1 &&
		 tail->ref_count == VLIB_BUFFER_MAX_CLONE - 1,
	       "clone-first release is wrong");
  vlib_buffer_free_one (vm, buffers[0]);
  SHINFO_TEST (root->ref_count == VLIB_BUFFER_MAX_CLONE - 2 &&
		 tail->ref_count == VLIB_BUFFER_MAX_CLONE - 2,
	       "root release is wrong");
  vlib_buffer_free_one (vm, clones[1]);
  SHINFO_TEST (root->ref_count == VLIB_BUFFER_MAX_CLONE - 3 &&
		 tail->ref_count == VLIB_BUFFER_MAX_CLONE - 3,
	       "interleaved release is wrong");
  for (u32 i = 2; i < n_clones; i++)
    vlib_buffer_free_one (vm, clones[i]);

  return 0;
}

VLIB_CLI_COMMAND (test_buffer_shinfo_command, static) = {
  .path = "test buffer-shinfo",
  .short_help = "test buffer-shinfo",
  .function = buffer_shinfo_test,
};
