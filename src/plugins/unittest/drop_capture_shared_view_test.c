/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/buffer_fault_injector.h>
#include <vlib/vlib.h>
#include <vnet/buffer_shinfo.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/interface_output.h>
#include <vppinfra/pcap.h>

#define DROP_CAPTURE_TEST(_cond, _comment)                                                         \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	{                                                                                          \
	  error = clib_error_return (0, _comment);                                                 \
	  goto done;                                                                               \
	}                                                                                          \
    }                                                                                              \
  while (0)

static void
drop_capture_shared_view_clear_pending (vlib_main_t *vm, u32 pending_len)
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

static int
drop_capture_shared_view_dispatch (vlib_main_t *vm, u32 buffer_index, u32 *pending_len)
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

  *pending_len = vec_len (vm->node_main.pending_frames);
  ((u32 *) vlib_frame_vector_args (frame))[0] = buffer_index;
  frame->n_vectors = 1;
  runtime->function (vm, runtime, frame);
  vlib_frame_free (vm, frame);
  return 0;
}

static int
drop_capture_shared_view_test_case (vlib_main_t *vm, int fail_allocation)
{
  vnet_pcap_t saved_pcap;
  vnet_pcap_t *pp = &vnet_get_main ()->pcap;
  vlib_node_t *error_node;
  vlib_node_runtime_t *error_runtime;
  vlib_buffer_t *root, *tail, *descriptor;
  ethernet_header_t *ethernet;
  pcap_packet_header_t *pcap_header;
  u8 expected[sizeof (*ethernet) + 20];
  u8 root_snapshot[8];
  u8 tail_snapshot[sizeof (expected) - sizeof (root_snapshot)];
  u8 *suffix;
  u32 buffers[2];
  u32 descriptor_index = ~0;
  u32 pending_len = 0;
  u32 error_index;
  uword suffix_len;
  i16 root_current_data;
  u16 root_current_length;
  clib_error_t *error = 0;
  int pcap_configured = 0;

  error_node = vlib_get_node_by_name (vm, (u8 *) "mpcap-unittest");
  if (error_node == 0)
    return -1;
  error_runtime = vlib_node_get_runtime (vm, error_node->index);
  if (vec_len (error_runtime->errors) == 0)
    return -1;
  error_index = error_runtime->errors[0];

  if (vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers)) != ARRAY_LEN (buffers))
    return -1;

  root = vlib_get_buffer (vm, buffers[0]);
  tail = vlib_get_buffer (vm, buffers[1]);
  root->current_data = 14;
  root->current_length = 4;
  root->next_buffer = buffers[1];
  root->total_length_not_including_first_buffer = sizeof (expected) - 8;
  root->flags |= VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_L2_HDR_OFFSET_VALID;
  vnet_buffer (root)->l2_hdr_offset = 10;
  tail->current_data = 3;
  tail->current_length = root->total_length_not_including_first_buffer;

  ethernet = (void *) expected;
  ethernet->type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4);
  clib_memset (ethernet->src_address, 0x11, sizeof (ethernet->src_address));
  clib_memset (ethernet->dst_address, 0x22, sizeof (ethernet->dst_address));
  clib_memset (ethernet + 1, 0x33, sizeof (expected) - sizeof (*ethernet));
  clib_memcpy_fast (root->data + vnet_buffer (root)->l2_hdr_offset, expected,
		    sizeof (root_snapshot));
  clib_memcpy_fast (vlib_buffer_get_current (tail), expected + sizeof (root_snapshot),
		    sizeof (tail_snapshot));

  DROP_CAPTURE_TEST (vnet_buffer_shinfo_clone (vm, buffers[0], &descriptor_index) == 0,
		     "headerless descriptor clone failed");
  descriptor = vlib_get_buffer (vm, descriptor_index);
  descriptor->error = error_index;
  root_current_data = root->current_data;
  root_current_length = root->current_length;
  clib_memcpy_fast (root_snapshot, root->data + vnet_buffer (root)->l2_hdr_offset,
		    sizeof (root_snapshot));
  clib_memcpy_fast (tail_snapshot, vlib_buffer_get_current (tail), sizeof (tail_snapshot));

  saved_pcap = *pp;
  clib_memset (pp, 0, sizeof (*pp));
  pp->pcap_main.n_packets_to_capture = 1;
  pp->pcap_error_index = ~0;
  pp->max_bytes_per_pkt = 128;
  pp->pcap_drop_enable = 1;
  pcap_configured = 1;

  if (fail_allocation)
    DROP_CAPTURE_TEST (vlib_buffer_alloc_fault_injector_set (vm, 1) == 0,
		       "enable drop capture allocation failure");
  DROP_CAPTURE_TEST (drop_capture_shared_view_dispatch (vm, descriptor_index, &pending_len) == 0,
		     "dispatch headerless descriptor to error-drop");
  if (fail_allocation)
    vlib_buffer_alloc_fault_injector_set (vm, 0);

  DROP_CAPTURE_TEST (root->current_data == root_current_data &&
		       root->current_length == root_current_length &&
		       descriptor->current_data == 0 && descriptor->current_length == 0 &&
		       descriptor->next_buffer == buffers[0],
		     "drop capture changed descriptor or canonical root cursors");
  DROP_CAPTURE_TEST (
    clib_memcmp (root_snapshot, root->data + vnet_buffer (root)->l2_hdr_offset,
		 sizeof (root_snapshot)) == 0 &&
      clib_memcmp (tail_snapshot, vlib_buffer_get_current (tail), sizeof (tail_snapshot)) == 0,
    "drop capture changed canonical packet bytes");

  if (fail_allocation)
    {
      DROP_CAPTURE_TEST (pp->pcap_main.n_packets_captured == 0 && pp->pcap_main.pcap_data == 0,
			 "failed temporary capture published a packet");
      goto done;
    }

  suffix_len = vec_len (error_node->name) + 2 +
	       clib_strnlen (vm->error_main.counters_heap[error_index].name, 128);
  DROP_CAPTURE_TEST (pp->pcap_main.n_packets_captured == 1, "shared descriptor was not captured");
  DROP_CAPTURE_TEST (vec_len (pp->pcap_main.pcap_data) ==
		       sizeof (*pcap_header) + sizeof (expected) + suffix_len,
		     "drop capture record has an unexpected size");
  pcap_header = (void *) pp->pcap_main.pcap_data;
  DROP_CAPTURE_TEST (pcap_header->n_packet_bytes_stored_in_file == sizeof (expected) + suffix_len &&
		       pcap_header->n_bytes_in_packet == sizeof (expected) + suffix_len,
		     "drop capture did not retain the complete temporary packet");
  DROP_CAPTURE_TEST (clib_memcmp (pcap_header->data, expected, sizeof (expected)) == 0,
		     "drop capture did not retain the L2 prefix and logical tail");
  suffix = pcap_header->data + sizeof (expected);
  DROP_CAPTURE_TEST (clib_memcmp (suffix, error_node->name, vec_len (error_node->name)) == 0 &&
		       clib_memcmp (suffix + vec_len (error_node->name), ": ", 2) == 0 &&
		       clib_memcmp (suffix + vec_len (error_node->name) + 2,
				    vm->error_main.counters_heap[error_index].name,
				    suffix_len - vec_len (error_node->name) - 2) == 0,
		     "drop capture did not append the error suffix to its temporary chain");

done:
  vlib_buffer_alloc_fault_injector_set (vm, 0);
  if (pending_len < vec_len (vm->node_main.pending_frames))
    drop_capture_shared_view_clear_pending (vm, pending_len);
  else if (descriptor_index != ~0)
    vlib_buffer_free_one (vm, descriptor_index);
  vlib_buffer_free_one (vm, buffers[0]);
  if (pcap_configured)
    {
      vec_free (pp->pcap_main.pcap_data);
      *pp = saved_pcap;
    }
  return error == 0 ? 0 : -1;
}

static clib_error_t *
drop_capture_shared_view_test (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  int fault_injector_available;

  fault_injector_available = vlib_buffer_alloc_fault_injector_set (vm, 0) == 0;
  if (drop_capture_shared_view_test_case (vm, 0))
    return clib_error_return (0, "drop capture shared-view success test failed");
  if (fault_injector_available && drop_capture_shared_view_test_case (vm, 1))
    return clib_error_return (0, "drop capture shared-view failure test failed");
  if (fault_injector_available)
    vlib_buffer_alloc_fault_injector_set (vm, 0);
  return 0;
}

VLIB_CLI_COMMAND (test_drop_capture_shared_view_command, static) = {
  .path = "test drop-capture-shared-view",
  .short_help = "test drop-capture-shared-view",
  .function = drop_capture_shared_view_test,
};
