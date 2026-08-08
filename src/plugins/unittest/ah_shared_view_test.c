/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ipsec/ah.h>
#include <vnet/ipsec/ipsec_sa.h>

#define AH_TEST(_cond, _comment)                                                                   \
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
ah_shared_view_dispatch (vlib_main_t *vm, const char *node_name, u32 buffer_index,
			 u32 *forwarded_index)
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

static int
ah_shared_view_add_sa (u32 id, ipsec_sa_flags_t flags, u32 *sa_index)
{
  ipsec_key_t crypto_key = {};
  ipsec_key_t integ_key = {};
  const u8 integ_key_data[20] = {};
  tunnel_t tunnel = {};

  ipsec_mk_key (&integ_key, integ_key_data, sizeof (integ_key_data));
  return ipsec_sa_add_and_lock (id, 0x01020304, IPSEC_PROTOCOL_AH, IPSEC_CRYPTO_ALG_NONE,
				&crypto_key, IPSEC_INTEG_ALG_SHA1_96, &integ_key, flags, 0,
				IPSEC_UDP_PORT_NONE, IPSEC_UDP_PORT_NONE, 0, &tunnel, sa_index);
}

static void
ah_shared_view_init_ip4 (vlib_buffer_t *buffer, u32 sa_index, int is_fragment)
{
  ip4_header_t *ip = vlib_buffer_get_current (buffer);

  buffer->current_length = sizeof (*ip);
  clib_memset (ip, 0, sizeof (*ip));
  ip->ip_version_and_header_length = 0x45;
  ip->length = clib_host_to_net_u16 (sizeof (*ip));
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  if (is_fragment)
    ip->flags_and_fragment_offset = clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);
  vnet_buffer (buffer)->ipsec.sad_index = sa_index;
}

static int
ah_shared_view_node_test (vlib_main_t *vm, const char *node_name, u32 expected_error,
			  int is_inbound, int is_fragment)
{
  vlib_buffer_t *root;
  vlib_buffer_t *forwarded;
  ipsec_sa_outb_rt_t *ort;
  u32 buffers[2];
  u32 forwarded_index = ~0;
  u32 sa_index = INDEX_INVALID;
  u32 n_alloc;
  int ret = 0;

  if (ah_shared_view_add_sa (0xa0000000 | expected_error,
			     is_inbound ? IPSEC_SA_FLAG_IS_INBOUND : IPSEC_SA_FLAG_NONE, &sa_index))
    return 0;
  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      goto done;
    }

  root = vlib_get_buffer (vm, buffers[0]);
  ah_shared_view_init_ip4 (root, sa_index, is_fragment);
  if (!is_inbound)
    {
      ort = ipsec_sa_get_outb_rt_by_index (sa_index);
      ort->seq64 = CLIB_U32_MAX;
    }
  AH_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	   "attach AH shared-view descriptor");
  vnet_buffer (vlib_get_buffer (vm, buffers[1]))->ipsec.sad_index = sa_index;
  AH_TEST (ah_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index) == 0,
	   "dispatch AH node with headerless descriptor");
  AH_TEST (forwarded_index != buffers[1], "replace AH descriptor frame slot");
  forwarded = vlib_get_buffer (vm, forwarded_index);
  AH_TEST (!vlib_buffer_shared_view_is_shared (forwarded),
	   "forward ordinary replacement after AH COW");
  AH_TEST (forwarded->error ==
	     vlib_node_get_runtime (vm, vlib_get_node_by_name (vm, (u8 *) node_name)->index)
	       ->errors[expected_error],
	   "preserve AH error disposition");
  ((ip4_header_t *) vlib_buffer_get_current (forwarded))->ttl = 1;
  AH_TEST (((ip4_header_t *) vlib_buffer_get_current (root))->ttl == 64,
	   "AH mutation leaves canonical root unchanged");
  ret = 1;

done:
  if (forwarded_index != ~0)
    vlib_buffer_free_one (vm, forwarded_index);
  else if (n_alloc == ARRAY_LEN (buffers))
    vlib_buffer_free_one (vm, buffers[1]);
  if (n_alloc == ARRAY_LEN (buffers))
    vlib_buffer_free_one (vm, buffers[0]);
  ipsec_sa_unlock (sa_index);
  return ret;
}

static int
ah_shared_view_cow_failure_test (vlib_main_t *vm, const char *node_name, u32 expected_error,
				 int is_inbound)
{
  vlib_buffer_t *descriptor;
  vlib_buffer_t *root;
  vlib_node_t *node;
  u32 buffers[2];
  u32 forwarded_index = ~0;
  u32 sa_index = INDEX_INVALID;
  u32 descriptor_next;
  u32 n_alloc;
  counter_t no_buffers_before;
  int dispatch_result;
  int ret = 0;

  if (ah_shared_view_add_sa (0xa0000000 | (is_inbound << 16) | expected_error,
			     is_inbound ? IPSEC_SA_FLAG_IS_INBOUND : IPSEC_SA_FLAG_NONE, &sa_index))
    return 0;
  no_buffers_before =
    vlib_get_simple_counter (&ipsec_sa_err_counters[IPSEC_SA_ERROR_NO_BUFFERS], sa_index);
  n_alloc = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  if (n_alloc != ARRAY_LEN (buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffers, n_alloc);
      goto done;
    }

  root = vlib_get_buffer (vm, buffers[0]);
  ah_shared_view_init_ip4 (root, sa_index, 0);
  AH_TEST (vlib_buffer_shared_view_attach (vm, buffers[1], buffers[0]) == 0,
	   "attach AH COW-failure descriptor");
  descriptor = vlib_get_buffer (vm, buffers[1]);
  vnet_buffer (descriptor)->ipsec.sad_index = sa_index;
  descriptor_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  dispatch_result = ah_shared_view_dispatch (vm, node_name, buffers[1], &forwarded_index);
  descriptor->next_buffer = descriptor_next;
  AH_TEST (dispatch_result == 0, "dispatch AH COW-failure descriptor");
  AH_TEST (forwarded_index == buffers[1], "retain AH input after COW failure");

  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  AH_TEST (node != 0, "find AH COW-failure node");
  AH_TEST (descriptor->error == vlib_node_get_runtime (vm, node->index)->errors[expected_error],
	   "send AH COW failure to no-buffers drop");
  AH_TEST (vlib_get_simple_counter (&ipsec_sa_err_counters[IPSEC_SA_ERROR_NO_BUFFERS], sa_index) ==
	     no_buffers_before + 1,
	   "increment AH COW-failure no-buffers SA counter");
  ret = 1;

done:
  if (n_alloc == ARRAY_LEN (buffers))
    {
      if (forwarded_index == ~0)
	vlib_buffer_free_one (vm, buffers[1]);
      else
	vlib_buffer_free_one (vm, forwarded_index);
      vlib_buffer_free_one (vm, buffers[0]);
    }
  ipsec_sa_unlock (sa_index);
  return ret;
}

static clib_error_t *
test_ah_shared_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!ah_shared_view_node_test (vm, "ah4-encrypt", AH_ENCRYPT_ERROR_SEQ_CYCLED, 0, 0) ||
      !ah_shared_view_node_test (vm, "ah4-decrypt", AH_DECRYPT_ERROR_DROP_FRAGMENTS, 1, 1) ||
      !ah_shared_view_cow_failure_test (vm, "ah4-encrypt", AH_ENCRYPT_ERROR_NO_BUFFERS, 0) ||
      !ah_shared_view_cow_failure_test (vm, "ah4-decrypt", AH_DECRYPT_ERROR_NO_BUFFERS, 1))
    return clib_error_return (0, "AH shared-view test failed");
  return 0;
}

VLIB_CLI_COMMAND (test_ah_shared_view_command, static) = {
  .path = "test ah-shared-view",
  .short_help = "test ah-shared-view",
  .function = test_ah_shared_view_fn,
};
