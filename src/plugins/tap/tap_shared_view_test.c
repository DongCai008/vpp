/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#include <sys/socket.h>
#include <net/if.h>
#include <netpacket/packet.h>

#include <vlib/vlib.h>
#include <vlib/buffer_fault_injector.h>
#include <vnet/buffer_shinfo.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <tap/internal.h>

#define TAP_SHARED_VIEW_TEST(_cond, _comment)                                                      \
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
tap_shared_view_init_packet (vlib_buffer_t *buffer)
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
}

static int
tap_shared_view_open_peer (tap_if_t *tif)
{
  struct sockaddr_ll sll = {
    .sll_family = AF_PACKET,
    .sll_protocol = clib_host_to_net_u16 (ETHERNET_TYPE_IP4),
    .sll_ifindex = tif->ifindex,
  };
  struct timeval timeout = { .tv_usec = 200000 };
  int fd;

  fd = socket (AF_PACKET, SOCK_RAW, clib_host_to_net_u16 (ETHERNET_TYPE_IP4));
  if (fd < 0)
    return -1;
  if (bind (fd, (struct sockaddr *) &sll, sizeof (sll)) ||
      setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof (timeout)))
    {
      close (fd);
      return -1;
    }
  return fd;
}

static int
tap_shared_view_dispatch (vlib_main_t *vm, u32 node_index, u32 *buffer_index, u16 n_buffers)
{
  vlib_node_t *node = vlib_get_node (vm, node_index);
  vlib_node_runtime_t *runtime;
  vlib_frame_t *frame;
  vnet_hw_if_tx_frame_t *tx_frame;

  if (node == 0 || (frame = vlib_get_frame_to_node (vm, node->index)) == 0)
    return -1;

  runtime = vlib_node_get_runtime (vm, node->index);
  if (n_buffers)
    ((u32 *) vlib_frame_vector_args (frame))[0] = *buffer_index;
  tx_frame = vlib_frame_scalar_args (frame);
  clib_memset (tx_frame, 0, sizeof (*tx_frame));
  frame->n_vectors = n_buffers;
  runtime->function (vm, runtime, frame);
  if (n_buffers)
    *buffer_index = ((u32 *) vlib_frame_vector_args (frame))[0];
  vlib_frame_free (vm, frame);
  return 0;
}

static clib_error_t *
test_tap_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  tap_create_if_args_t args = {
    .id = ~0,
    .num_rx_queues = 1,
    .num_tx_queues = 1,
    .tap_flags = TAP_FLAG_GSO | TAP_FLAG_GRO_COALESCE | TAP_FLAG_CSUM_OFFLOAD,
  };
  tap_if_t *tif = 0;
  tap_txq_t *txq;
  vnet_hw_interface_t *hi;
  vlib_node_t *node;
  vlib_buffer_t *root;
  u8 root_data[sizeof (ethernet_header_t) + sizeof (ip4_header_t) + sizeof (udp_header_t)];
  u8 peer_data[sizeof (root_data)];
  u32 buffers[2];
  u32 descriptor_index = ~0;
  u32 output_index;
  u32 node_error_before;
  u64 drop_before;
  u16 avail_before;
  u16 desc_in_use_before;
  u16 last_used_before;
  ssize_t peer_len;
  int peer_fd = -1;
  u8 fault = 0;
  u8 root_owned = 0;
  clib_error_t *error = 0;

  if (unformat (input, "fault"))
    fault = 1;
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input");
  if (fault && vlib_buffer_alloc_fault_injector_set (vm, 0))
    return clib_error_return (0, "fault injector unavailable");

  tap_create_if (vm, &args);
  TAP_SHARED_VIEW_TEST (args.rv == 0, "create TAP shared-view interface");
  tif = pool_elt_at_index (tap_main.interfaces, args.id);
  txq = tap_get_tx_queue (tif, 0);
  hi = vnet_get_hw_interface (vnm, tif->hw_if_index);
  node = vlib_get_node (vm, hi->tx_node_index);
  TAP_SHARED_VIEW_TEST (node != 0, "find TAP TX node");
  peer_fd = tap_shared_view_open_peer (tif);
  TAP_SHARED_VIEW_TEST (peer_fd >= 0, "open TAP host peer socket");

  TAP_SHARED_VIEW_TEST (vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers)) == ARRAY_LEN (buffers),
			"allocate TAP shared-view buffers");
  root_owned = 1;
  root = vlib_get_buffer (vm, buffers[0]);
  tap_shared_view_init_packet (root);
  clib_memcpy_fast (root_data, vlib_buffer_get_current (root), sizeof (root_data));
  TAP_SHARED_VIEW_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
			"attach TAP shared-view descriptor");
  descriptor_index = buffers[1];
  output_index = descriptor_index;

  node_error_before = vm->error_main.counters[node->error_heap_index + TAP_TX_ERROR_COW_FAILED];
  drop_before = vlib_get_simple_counter (
    vnm->interface_main.sw_if_counters + VNET_INTERFACE_COUNTER_DROP, tif->sw_if_index);
  avail_before = txq->avail->idx;
  desc_in_use_before = txq->desc_in_use;
  last_used_before = txq->last_used_idx;
  if (fault)
    TAP_SHARED_VIEW_TEST (vlib_buffer_alloc_fault_injector_set (vm, 1) == 0,
			  "arm TAP shared-view COW allocation failure");

  TAP_SHARED_VIEW_TEST (tap_shared_view_dispatch (vm, hi->tx_node_index, &output_index, 1) == 0,
			"dispatch TAP shared-view descriptor through TX node");
  vlib_buffer_alloc_fault_injector_set (vm, 0);
  descriptor_index = ~0;

  TAP_SHARED_VIEW_TEST (
    clib_memcmp (root_data, vlib_buffer_get_current (root), sizeof (root_data)) == 0,
    "leave canonical TAP root bytes unchanged");
  if (fault)
    {
      TAP_SHARED_VIEW_TEST (root->ref_count == 1,
			    "release TAP descriptor after COW allocation failure");
      TAP_SHARED_VIEW_TEST (
	vm->error_main.counters[node->error_heap_index + TAP_TX_ERROR_COW_FAILED] ==
	  node_error_before + 1,
	"increment TAP COW failure counter exactly once");
      TAP_SHARED_VIEW_TEST (
	vlib_get_simple_counter (vnm->interface_main.sw_if_counters + VNET_INTERFACE_COUNTER_DROP,
				 tif->sw_if_index) == drop_before + 1,
	"increment TAP interface drop counter exactly once");
      TAP_SHARED_VIEW_TEST (txq->avail->idx == avail_before &&
			      txq->desc_in_use == desc_in_use_before,
			    "avoid TAP ring publication after COW allocation failure");
      peer_len = recv (peer_fd, peer_data, sizeof (peer_data), 0);
      TAP_SHARED_VIEW_TEST (peer_len < 0 && errno == EAGAIN,
			    "avoid host-peer publication after COW allocation failure");
    }
  else
    {
      TAP_SHARED_VIEW_TEST (output_index != buffers[1] && !vlib_buffer_shared_view_is_shared (
							    vlib_get_buffer (vm, output_index)),
			    "replace TAP shared-view descriptor before TX");
      peer_len = recv (peer_fd, peer_data, sizeof (peer_data), 0);
      TAP_SHARED_VIEW_TEST (peer_len == sizeof (peer_data) &&
			      clib_memcmp (peer_data, root_data, sizeof (peer_data)) == 0,
			    "publish TAP packet to host peer");
      TAP_SHARED_VIEW_TEST (tap_shared_view_dispatch (vm, hi->tx_node_index, 0, 0) == 0,
			    "reap consumed TAP TX descriptor through the device node");
      TAP_SHARED_VIEW_TEST (txq->desc_in_use == desc_in_use_before &&
			      txq->last_used_idx != last_used_before,
			    "release the TAP COW replacement before teardown");
    }

done:
  vlib_buffer_alloc_fault_injector_set (vm, 0);
  if (peer_fd >= 0)
    close (peer_fd);
  if (args.rv == 0)
    tap_delete_if (vm, args.sw_if_index);
  if (descriptor_index != ~0)
    vlib_buffer_free_one (vm, descriptor_index);
  if (root_owned)
    vlib_buffer_free_one (vm, buffers[0]);
  return error;
}

VLIB_CLI_COMMAND (test_tap_shared_view_command, static) = {
  .path = "test tap-shared-view",
  .short_help = "test tap-shared-view [fault]",
  .function = test_tap_shared_view_fn,
};
