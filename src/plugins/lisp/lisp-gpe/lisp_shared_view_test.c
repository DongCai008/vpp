/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <lisp/lisp-cp/control.h>
#include <lisp/lisp-gpe/lisp_gpe.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/l2/l2_input.h>

#define LISP_TEST(_cond, _comment)                                                                 \
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
lisp_shared_view_dispatch (vlib_main_t *vm, const char *node_name, u32 buffer_index,
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

static void
lisp_shared_view_init_packet (vlib_buffer_t *buffer, u8 is_v4)
{
  lisp_gpe_header_t *lisp;
  ip4_header_t *inner;
  u32 outer_header_bytes;

  outer_header_bytes =
    sizeof (udp_header_t) + (is_v4 ? sizeof (ip4_header_t) : sizeof (ip6_header_t));
  buffer->current_data = outer_header_bytes;
  buffer->current_length = sizeof (lisp_gpe_header_t) + sizeof (*inner);
  lisp = vlib_buffer_get_current (buffer);
  clib_memset ((u8 *) lisp - outer_header_bytes, 0, outer_header_bytes + buffer->current_length);
  lisp->flags = LISP_GPE_FLAGS_P;
  lisp->next_protocol = LISP_GPE_NEXT_PROTO_IP4;
  inner = (void *) (lisp + 1);
  inner->ip_version_and_header_length = 0x45;
}

static int
lisp_shared_view_success_test (vlib_main_t *vm, const char *node_name, u8 is_v4)
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
  lisp_shared_view_init_packet (root, is_v4);
  LISP_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	     "attach LISP shared-view descriptor");
  LISP_TEST (vlib_get_buffer (vm, buffers[1])->current_length == 0,
	     "use headerless LISP descriptor");
  LISP_TEST (lisp_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index) == 0,
	     "dispatch LISP shared-view descriptor");
  LISP_TEST (forwarded_index != buffers[1], "replace LISP descriptor frame slot");
  forwarded = vlib_get_buffer (vm, forwarded_index);
  LISP_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
	     "forward ordinary replacement after LISP COW");
  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  LISP_TEST (node != 0, "find LISP input node");
  LISP_TEST (forwarded->error ==
	       vlib_node_get_runtime (vm, node->index)->errors[LISP_GPE_ERROR_NO_TUNNEL],
	     "preserve LISP no-tunnel disposition after COW");
  ((ip4_header_t *) vlib_buffer_get_current (forwarded))->ttl = 1;

  LISP_TEST (
    ((ip4_header_t *) ((u8 *) vlib_buffer_get_current (root) + sizeof (lisp_gpe_header_t)))->ttl ==
      0,
    "LISP replacement leaves canonical root unchanged");
  ret = 1;

done:
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
lisp_shared_view_failure_test (vlib_main_t *vm, const char *node_name, u8 is_v4)
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
  lisp_shared_view_init_packet (root, is_v4);
  LISP_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	     "attach malformed LISP descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  LISP_TEST (lisp_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index) == 0,
	     "dispatch LISP COW-failure descriptor");
  descriptor->next_buffer = descriptor_next;
  LISP_TEST (forwarded_index == buffers[1], "retain LISP input after COW failure");
  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  LISP_TEST (node != 0, "find LISP COW-failure node");
  LISP_TEST (descriptor->error ==
	       vlib_node_get_runtime (vm, node->index)->errors[LISP_GPE_ERROR_NO_BUFFERS],
	     "send LISP COW failure to no-buffers drop");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
lisp_cp_shared_view_success_test (vlib_main_t *vm)
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
  ((u8 *) vlib_buffer_get_current (root))[0] = 0xff;
  LISP_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	     "attach LISP control-plane descriptor");
  LISP_TEST (lisp_shared_view_dispatch (vm, "lisp-cp-input", buffers[1], &forwarded_index) == 0,
	     "dispatch LISP control-plane descriptor");
  LISP_TEST (forwarded_index != buffers[1], "replace LISP control-plane descriptor frame slot");
  forwarded = vlib_get_buffer (vm, forwarded_index);
  LISP_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
	     "forward ordinary LISP control-plane replacement");
  node = vlib_get_node_by_name (vm, (u8 *) "lisp-cp-input");
  LISP_TEST (node != 0, "find LISP control-plane input node");
  LISP_TEST (forwarded->error ==
	       vlib_node_get_runtime (vm, node->index)->errors[LISP_CP_INPUT_ERROR_DROP],
	     "preserve LISP control-plane drop disposition after COW");
  ((u8 *) vlib_buffer_get_current (forwarded))[0] = 0;
  LISP_TEST (((u8 *) vlib_buffer_get_current (root))[0] == 0xff,
	     "LISP control-plane replacement leaves root unchanged");
  ret = 1;

done:
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
lisp_cp_shared_view_failure_test (vlib_main_t *vm)
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
  LISP_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	     "attach malformed LISP control-plane descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  LISP_TEST (lisp_shared_view_dispatch (vm, "lisp-cp-input", buffers[1], &forwarded_index) == 0,
	     "dispatch LISP control-plane COW failure");
  descriptor->next_buffer = descriptor_next;
  LISP_TEST (forwarded_index == buffers[1],
	     "retain LISP control-plane descriptor after COW failure");
  node = vlib_get_node_by_name (vm, (u8 *) "lisp-cp-input");
  LISP_TEST (node != 0, "find LISP control-plane COW-failure node");
  LISP_TEST (descriptor->error ==
	       vlib_node_get_runtime (vm, node->index)->errors[LISP_CP_INPUT_ERROR_NO_BUFFERS],
	     "send LISP control-plane COW failure to its no-buffers drop");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
lisp_lookup_shared_view_failure_test (vlib_main_t *vm, const char *node_name)
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
  LISP_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	     "attach malformed LISP lookup descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  LISP_TEST (lisp_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index) == 0,
	     "dispatch LISP lookup COW failure");
  descriptor->next_buffer = descriptor_next;
  LISP_TEST (forwarded_index == buffers[1], "retain LISP lookup descriptor after COW failure");
  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  LISP_TEST (node != 0, "find LISP lookup COW-failure node");
  LISP_TEST (descriptor->error ==
	       vlib_node_get_runtime (vm, node->index)->errors[LISP_CP_LOOKUP_ERROR_NO_BUFFERS],
	     "send LISP lookup COW failure to no-buffers drop");
  ret = 1;

done:
  if (descriptor)
    descriptor->next_buffer = descriptor_next;
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static void
lisp_lookup_init_packet (vlib_buffer_t *buffer, u16 overlay)
{
  ethernet_header_t *eth;

  if (overlay == LISP_AFI_IP)
    {
      ip4_header_t *ip = vlib_buffer_get_current (buffer);

      buffer->current_length = sizeof (*ip);
      clib_memset (ip, 0, sizeof (*ip));
      ip->ip_version_and_header_length = 0x45;
    }
  else if (overlay == LISP_AFI_IP6)
    {
      ip6_header_t *ip = vlib_buffer_get_current (buffer);

      buffer->current_length = sizeof (*ip);
      clib_memset (ip, 0, sizeof (*ip));
      ((u8 *) ip)[0] = 0x60;
    }
  else if (overlay == LISP_AFI_MAC)
    {
      ethernet_arp_header_t *arp;

      buffer->current_length = sizeof (*eth) + sizeof (*arp);
      eth = vlib_buffer_get_current (buffer);
      clib_memset (eth, 0, buffer->current_length);
      eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_ARP);
      arp = (void *) (eth + 1);
      arp->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request);
    }
  else
    {
      lisp_nsh_hdr_t *nsh;

      buffer->current_length = sizeof (*eth) + sizeof (*nsh);
      eth = vlib_buffer_get_current (buffer);
      clib_memset (eth, 0, buffer->current_length);
      eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_NSH);
      nsh = (void *) (eth + 1);
      nsh->spi_si = clib_host_to_net_u32 (1 << 8);
    }
}

static int
lisp_lookup_shared_view_success_test (vlib_main_t *vm, const char *node_name, u16 overlay)
{
  vlib_buffer_t *root;
  vlib_buffer_t *forwarded;
  u32 buffers[2];
  u32 forwarded_index = ~0;
  u32 n_alloc;
  u8 root_byte;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }

  root = vlib_get_buffer (vm, buffers[0]);
  lisp_lookup_init_packet (root, overlay);
  root_byte = ((u8 *) vlib_buffer_get_current (root))[0];
  LISP_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	     "attach LISP lookup descriptor");
  LISP_TEST (lisp_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index) == 0,
	     "dispatch LISP lookup descriptor");
  LISP_TEST (forwarded_index != buffers[1], "replace LISP lookup descriptor frame slot");
  forwarded = vlib_get_buffer (vm, forwarded_index);
  LISP_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
	     "forward ordinary LISP lookup replacement");
  ((u8 *) vlib_buffer_get_current (forwarded))[0] ^= 0xff;
  LISP_TEST (((u8 *) vlib_buffer_get_current (root))[0] == root_byte,
	     "LISP lookup replacement leaves canonical packet data unchanged");
  ret = 1;

done:
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static int
lisp_ndp_shared_view_rewrite_test (vlib_main_t *vm)
{
  const u32 bd_id = 0x7e57;
  u8 reply_mac[6] = { 0, 1, 2, 3, 4, 5 };
  const ip6_address_t target = { .as_u64 = { 0x0100000000000000, 0 } };
  ethernet_header_t *eth;
  ip6_header_t *ip;
  icmp6_neighbor_solicitation_or_advertisement_header_t *ndh;
  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *opt;
  gid_address_t key = {};
  l2_input_config_t saved_config = {};
  l2_bridge_domain_t saved_bd = {};
  vlib_buffer_t *root;
  vlib_buffer_t *forwarded;
  vlib_node_t *node;
  u32 buffers[2];
  u32 forwarded_index = ~0;
  u32 n_alloc;
  u8 added = 0;
  int ret = 0;

  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      return 0;
    }

  vec_validate (l2input_main.configs, 0);
  vec_validate (l2input_main.bd_configs, 0);
  saved_config = l2input_main.configs[0];
  saved_bd = l2input_main.bd_configs[0];
  l2input_main.configs[0].bd_index = 0;
  l2input_main.bd_configs[0].bd_id = bd_id;

  root = vlib_get_buffer (vm, buffers[0]);
  root->current_length = sizeof (*eth) + sizeof (*ip) + sizeof (*ndh) + sizeof (*opt);
  eth = vlib_buffer_get_current (root);
  clib_memset (eth, 0, root->current_length);
  eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_IP6);
  ip = (void *) (eth + 1);
  ((u8 *) ip)[0] = 0x60;
  ip->protocol = IP_PROTOCOL_ICMP6;
  ndh = ip6_next_header (ip);
  ndh->icmp.type = ICMP6_neighbor_solicitation;
  ndh->target_address = target;
  opt = (void *) (ndh + 1);
  opt->header.type = ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address;
  opt->header.n_data_u64s = 1;
  vnet_buffer (root)->sw_if_index[VLIB_RX] = 0;
  gid_address_type (&key) = GID_ADDR_NDP;
  gid_address_ndp_bd (&key) = bd_id;
  ip_address_set (&gid_address_arp_ndp_ip (&key), &target, AF_IP6);
  LISP_TEST (gid_dictionary_add_del (&vnet_lisp_cp_get_main ()->mapping_index_by_gid, &key,
				     mac_to_u64 (reply_mac), 1) == 0,
	     "add LISP NDP reply mapping");
  added = 1;
  LISP_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	     "attach LISP NDP descriptor");
  vnet_buffer (vlib_get_buffer (vm, buffers[1]))->sw_if_index[VLIB_RX] = 0;
  LISP_TEST (lisp_shared_view_dispatch (vm, "lisp-cp-lookup-l2", buffers[1], &forwarded_index) == 0,
	     "dispatch LISP NDP reply descriptor");
  forwarded = vlib_get_buffer (vm, forwarded_index);
  node = vlib_get_node_by_name (vm, (u8 *) "lisp-cp-lookup-l2");
  LISP_TEST (forwarded_index != buffers[1], "replace LISP NDP descriptor");
  LISP_TEST (forwarded->error == vlib_node_get_runtime (vm, node->index)
				   ->errors[LISP_CP_LOOKUP_ERROR_NDP_NEIGHBOR_ADVERTISEMENT_TX],
	     "send rewritten LISP NDP packet to interface output");
  LISP_TEST (((icmp6_neighbor_solicitation_or_advertisement_header_t *) ip6_next_header (
		(ip6_header_t *) (vlib_buffer_get_current (forwarded) + sizeof (*eth))))
		 ->icmp.type == ICMP6_neighbor_advertisement,
	     "rewrite NDP solicitation in replacement");
  LISP_TEST (ndh->icmp.type == ICMP6_neighbor_solicitation,
	     "leave canonical NDP solicitation unchanged");
  ret = 1;

done:
  if (added)
    gid_dictionary_add_del (&vnet_lisp_cp_get_main ()->mapping_index_by_gid, &key, 0, 0);
  l2input_main.configs[0] = saved_config;
  l2input_main.bd_configs[0] = saved_bd;
  vlib_buffer_free_one (vm, forwarded_index == ~0 ? buffers[1] : forwarded_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_lisp_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!lisp_shared_view_success_test (vm, "lisp-gpe-ip4-input", 1) ||
      !lisp_shared_view_success_test (vm, "lisp-gpe-ip6-input", 0) ||
      !lisp_shared_view_failure_test (vm, "lisp-gpe-ip4-input", 1) ||
      !lisp_shared_view_failure_test (vm, "lisp-gpe-ip6-input", 0) ||
      !lisp_cp_shared_view_success_test (vm) || !lisp_cp_shared_view_failure_test (vm) ||
      !lisp_lookup_shared_view_success_test (vm, "lisp-cp-lookup-ip4", LISP_AFI_IP) ||
      !lisp_lookup_shared_view_success_test (vm, "lisp-cp-lookup-ip6", LISP_AFI_IP6) ||
      !lisp_lookup_shared_view_success_test (vm, "lisp-cp-lookup-l2", LISP_AFI_MAC) ||
      !lisp_lookup_shared_view_success_test (vm, "lisp-cp-lookup-nsh", LISP_AFI_LCAF) ||
      !lisp_lookup_shared_view_failure_test (vm, "lisp-cp-lookup-ip4") ||
      !lisp_lookup_shared_view_failure_test (vm, "lisp-cp-lookup-ip6") ||
      !lisp_lookup_shared_view_failure_test (vm, "lisp-cp-lookup-l2") ||
      !lisp_lookup_shared_view_failure_test (vm, "lisp-cp-lookup-nsh") ||
      !lisp_ndp_shared_view_rewrite_test (vm))
    return clib_error_return (0, "LISP shared-view test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_lisp_shared_view_command, static) = {
  .path = "test lisp-shared-view",
  .short_help = "test lisp-shared-view",
  .function = test_lisp_shared_view_fn,
};
