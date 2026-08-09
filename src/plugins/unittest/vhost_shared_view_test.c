/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vlib/buffer_fault_injector.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>

#define VHOST_SHARED_VIEW_TEST(_cond, _comment)                                                    \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	{                                                                                          \
	  fformat (stderr, "FAIL:%d: %s\\n", __LINE__, _comment);                                  \
	  goto done;                                                                               \
	}                                                                                          \
    }                                                                                              \
  while (0)

/* Mirrors the private vhost-user TX error ordering. */
enum
{
  VHOST_SHARED_VIEW_TEST_ERROR_COW_FAILED = 5,
};

static void
vhost_shared_view_set_offload (vlib_buffer_t *buffer)
{
  buffer->flags |= VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
		   VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
  vnet_buffer (buffer)->l2_hdr_offset = 0;
  vnet_buffer (buffer)->l3_hdr_offset = sizeof (ethernet_header_t);
  vnet_buffer (buffer)->l4_hdr_offset = sizeof (ethernet_header_t) + sizeof (ip4_header_t);
  vnet_buffer_offload_flags_set (buffer,
				 VNET_BUFFER_OFFLOAD_F_IP_CKSUM | VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);
}

static void
vhost_shared_view_init_packet (vlib_buffer_t *buffer)
{
  ethernet_header_t *eth;
  ip4_header_t *ip;
  udp_header_t *udp;

  buffer->current_length = sizeof (*eth) + sizeof (*ip) + sizeof (*udp);
  clib_memset (vlib_buffer_get_current (buffer), 0, buffer->current_length);
  eth = vlib_buffer_get_current (buffer);
  eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4);
  ip = (ip4_header_t *) (eth + 1);
  ip->ip_version_and_header_length = 0x45;
  ip->length = clib_host_to_net_u16 (sizeof (*ip) + sizeof (*udp));
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = clib_host_to_net_u32 (0x0a000001);
  ip->dst_address.as_u32 = clib_host_to_net_u32 (0x0a000002);
  ip->checksum = ip4_header_checksum (ip);
  udp = (udp_header_t *) (ip + 1);
  udp->src_port = clib_host_to_net_u16 (10000);
  udp->dst_port = clib_host_to_net_u16 (10001);
  udp->length = clib_host_to_net_u16 (sizeof (*udp));

  vhost_shared_view_set_offload (buffer);
}

static int
vhost_shared_view_dispatch (vlib_main_t *vm, u32 node_index, u32 buffer_index)
{
  vlib_node_t *node = vlib_get_node (vm, node_index);
  vlib_node_runtime_t *runtime;
  vlib_frame_t *frame;
  vnet_hw_if_tx_frame_t *tx_frame;

  if (node == 0)
    return -1;
  runtime = vlib_node_get_runtime (vm, node->index);
  frame = vlib_get_frame_to_node (vm, node->index);
  if (frame == 0)
    return -1;

  ((u32 *) vlib_frame_vector_args (frame))[0] = buffer_index;
  tx_frame = vlib_frame_scalar_args (frame);
  clib_memset (tx_frame, 0, sizeof (*tx_frame));
  frame->n_vectors = 1;
  runtime->function (vm, runtime, frame);
  vlib_frame_free (vm, frame);
  return 0;
}

static clib_error_t *
test_vhost_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi;
  vlib_node_t *node;
  vlib_buffer_t *root;
  udp_header_t *udp;
  u32 buffers[2];
  u32 sw_if_index = ~0;
  u32 n_alloc = 0;
  u8 root_data[sizeof (ethernet_header_t) + sizeof (ip4_header_t) + sizeof (udp_header_t)];
  u64 cow_fail_before;
  u64 drop_before;
  u16 root_udp_checksum;
  u8 descriptor_owned = 0;
  u8 fault = 0;
  int ret = 0;

  if (!unformat (input, "sw_if_index %u", &sw_if_index))
    return clib_error_return (0, "sw_if_index is required");
  if (unformat (input, "fault"))
    fault = 1;
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input");
  if (fault && vlib_buffer_alloc_fault_injector_set (vm, 0))
    return clib_error_return (0, "fault injector unavailable");

  hi = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);
  VHOST_SHARED_VIEW_TEST (hi != 0, "find vhost-user hardware interface");
  node = vlib_get_node (vm, hi->tx_node_index);
  VHOST_SHARED_VIEW_TEST (node != 0, "find vhost-user TX node");

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return clib_error_return (0, "allocate vhost-user shared-view buffers");
    }
  root = vlib_get_buffer (vm, buffers[0]);
  vhost_shared_view_init_packet (root);
  VHOST_SHARED_VIEW_TEST (root->current_length == sizeof (root_data),
			  "initialize vhost-user root packet");
  clib_memcpy_fast (root_data, vlib_buffer_get_current (root), sizeof (root_data));
  udp =
    (udp_header_t *) ((ip4_header_t *) ((ethernet_header_t *) vlib_buffer_get_current (root) + 1) +
		      1);
  root_udp_checksum = udp->checksum;

  VHOST_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			  "attach vhost-user shared-view descriptor");
  descriptor_owned = 1;
  vhost_shared_view_set_offload (vlib_get_buffer (vm, buffers[1]));
  VHOST_SHARED_VIEW_TEST (vlib_buffer_shared_view_is_shared (vlib_get_buffer (vm, buffers[1])),
			  "retain vhost-user shared-view descriptor");
  if (fault)
    {
      cow_fail_before =
	vm->error_main.counters[node->error_heap_index + VHOST_SHARED_VIEW_TEST_ERROR_COW_FAILED];
      drop_before = vlib_get_simple_counter (
	vnm->interface_main.sw_if_counters + VNET_INTERFACE_COUNTER_DROP, sw_if_index);
      VHOST_SHARED_VIEW_TEST (vlib_buffer_alloc_fault_injector_set (vm, 1) == 0,
			      "arm vhost-user shared-view COW allocation failure");
    }
  VHOST_SHARED_VIEW_TEST (vhost_shared_view_dispatch (vm, hi->tx_node_index, buffers[1]) == 0,
			  "dispatch vhost-user shared-view descriptor through TX node");
  descriptor_owned = 0;
  vlib_buffer_alloc_fault_injector_set (vm, 0);

  udp =
    (udp_header_t *) ((ip4_header_t *) ((ethernet_header_t *) vlib_buffer_get_current (root) + 1) +
		      1);
  if (fault)
    {
      VHOST_SHARED_VIEW_TEST (root->ref_count == 1 && vlib_buffer_shared_view_is_shared (root),
			      "retain canonical root after vhost-user COW allocation failure");
      VHOST_SHARED_VIEW_TEST (
	udp->checksum == root_udp_checksum &&
	  clib_memcmp (root_data, vlib_buffer_get_current (root), sizeof (root_data)) == 0,
	"leave canonical root bytes unchanged after vhost-user COW failure");
      VHOST_SHARED_VIEW_TEST (
	vm->error_main.counters[node->error_heap_index + VHOST_SHARED_VIEW_TEST_ERROR_COW_FAILED] ==
	  cow_fail_before + 1,
	"increment the vhost-user COW failure counter exactly once");
      VHOST_SHARED_VIEW_TEST (
	vlib_get_simple_counter (vnm->interface_main.sw_if_counters + VNET_INTERFACE_COUNTER_DROP,
				 sw_if_index) == drop_before + 1,
	"increment the vhost-user interface drop counter exactly once");
    }
  else
    VHOST_SHARED_VIEW_TEST (udp->checksum == root_udp_checksum,
			    "leave canonical vhost-user root unchanged after TX COW");
  ret = 1;

done:
  vlib_buffer_alloc_fault_injector_set (vm, 0);
  if (n_alloc == ARRAY_LEN (buffers))
    {
      if (descriptor_owned)
	vlib_buffer_free_one (vm, buffers[1]);
      vlib_buffer_free_one (vm, buffers[0]);
    }
  return ret ? 0 : clib_error_return (0, "vhost-user shared-view test failed");
}

VLIB_CLI_COMMAND (test_vhost_shared_view_command, static) = {
  .path = "test vhost-shared-view",
  .short_help = "test vhost-shared-view sw_if_index <index>",
  .function = test_vhost_shared_view_fn,
};
