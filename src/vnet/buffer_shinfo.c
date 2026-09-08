/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/*
 * Copyright (c) 2026
 */

#include <vnet/buffer_shinfo.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>

static int
vnet_buffer_shinfo_root (vlib_main_t *vm, u32 buffer_index, u32 *root_index, vlib_buffer_t **root)
{
  if (vlib_buffer_shared_view_root (vm, buffer_index, root_index))
    return -1;

  *root = vlib_get_buffer_checked (vm, *root_index);
  return *root == 0 ? -1 : 0;
}

static int
vnet_buffer_shinfo_gso (vlib_buffer_t *root, vnet_buffer_shinfo_t *shinfo)
{
  u32 ip_flags = root->flags & (VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_IS_IP6);
  i64 data_end = (i64) root->current_data + root->current_length;
  i16 l3_offset = vnet_buffer (root)->l3_hdr_offset;
  i16 l4_offset = vnet_buffer (root)->l4_hdr_offset;

  if ((root->flags & VNET_BUFFER_F_GSO) == 0)
    return 0;

  if (ip_flags != VNET_BUFFER_F_IS_IP4 && ip_flags != VNET_BUFFER_F_IS_IP6)
    return -1;

  if ((root->flags & (VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID)) !=
      (VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID))
    return -1;

  if (vnet_buffer2 (root)->gso_size == 0 ||
      vnet_buffer2 (root)->gso_l4_hdr_sz < sizeof (tcp_header_t) ||
      l3_offset < root->current_data || l4_offset < l3_offset ||
      l4_offset + vnet_buffer2 (root)->gso_l4_hdr_sz > data_end)
    return -1;

  if (root->flags & VNET_BUFFER_F_OFFLOAD &&
      ((vnet_buffer (root)->oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM) == 0 ||
       vnet_buffer (root)->oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
    return -1;

  if (ip_flags == VNET_BUFFER_F_IS_IP4)
    {
      ip4_header_t *ip4 = (void *) (root->data + l3_offset);
      u16 ip4_header_size;

      if (l3_offset + sizeof (*ip4) > data_end || ip4->protocol != IP_PROTOCOL_TCP)
	return -1;

      ip4_header_size = ip4_header_bytes (ip4);
      if (ip4_header_size < sizeof (*ip4) || l3_offset + ip4_header_size != l4_offset)
	return -1;

      shinfo->gso_type = VNET_BUFFER_SHINFO_GSO_TYPE_TCP4;
    }
  else
    {
      ip6_header_t *ip6 = (void *) (root->data + l3_offset);

      if (l3_offset + sizeof (*ip6) > data_end || ip6->protocol != IP_PROTOCOL_TCP ||
	  l3_offset + sizeof (*ip6) != l4_offset)
	return -1;

      shinfo->gso_type = VNET_BUFFER_SHINFO_GSO_TYPE_TCP6;
    }

  shinfo->gso_enabled = 1;
  shinfo->gso_size = vnet_buffer2 (root)->gso_size;
  shinfo->gso_l4_header_size = vnet_buffer2 (root)->gso_l4_hdr_sz;
  shinfo->gso_flags = vnet_buffer2 (root)->gso_flags;
  return 0;
}

static int
vnet_buffer_shinfo_walk (vlib_main_t *vm, u32 root_index, vnet_buffer_shinfo_t *shinfo,
			 u32 wanted_span, vnet_buffer_shinfo_span_t *span, u8 check_refs)
{
  vlib_buffer_t *buffer;
  vlib_buffer_pool_t *pool;
  u32 buffer_index = root_index;
  u32 data_bytes = 0;
  u32 backing_bytes = 0;
  u32 span_count = 0;

  clib_memset (shinfo, 0, sizeof (*shinfo));
  shinfo->root_buffer_index = root_index;

  while (1)
    {
      i64 data_end;

      if (PREDICT_FALSE (span_count == (u16) ~0))
	return -1;

      buffer = vlib_get_buffer_checked (vm, buffer_index);
      if (buffer == 0 || (span_count != 0 && buffer->flags & (VNET_BUFFER_F_SHARED_ROOT |
							      VNET_BUFFER_F_SHARED_DESCRIPTOR)))
	return -1;

      if (check_refs && buffer->ref_count >= VLIB_BUFFER_MAX_CLONE)
	return -1;

      pool = vlib_get_buffer_pool (vm, buffer->buffer_pool_index);
      data_end = (i64) buffer->current_data + buffer->current_length;
      if (buffer->current_length == 0 || buffer->current_data < -VLIB_BUFFER_PRE_DATA_SIZE ||
	  data_end > pool->data_size || data_bytes > (u32) ~0 - buffer->current_length ||
	  backing_bytes > (u32) ~0 - pool->data_size)
	return -1;

      if (span_count == wanted_span && span != 0)
	{
	  span->buffer_pool = buffer->buffer_pool_index;
	  span->reserved = 0;
	  span->buffer_index = buffer_index;
	  span->data_offset = buffer->current_data;
	  span->length = buffer->current_length;
	}

      data_bytes += buffer->current_length;
      backing_bytes += pool->data_size;
      span_count++;

      if ((buffer->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
	break;
      buffer_index = buffer->next_buffer;
    }

  if (span != 0 && wanted_span >= span_count)
    return -1;

  buffer = vlib_get_buffer_checked (vm, root_index);
  if (buffer == 0)
    return -1;

  shinfo->data_bytes = data_bytes;
  shinfo->backing_bytes = backing_bytes;
  shinfo->span_count = span_count;
  shinfo->chain_buffers = span_count;
  if (buffer->flags & VNET_BUFFER_F_OFFLOAD)
    shinfo->offload_flags = vnet_buffer (buffer)->oflags;
  return vnet_buffer_shinfo_gso (buffer, shinfo);
}

int
vnet_buffer_shinfo_get (vlib_main_t *vm, u32 buffer_index, vnet_buffer_shinfo_t *shinfo)
{
  vlib_buffer_t *root;
  u32 root_index;

  if (shinfo == 0 || vnet_buffer_shinfo_root (vm, buffer_index, &root_index, &root))
    return -1;

  return vnet_buffer_shinfo_walk (vm, root_index, shinfo, 0, 0, 0);
}

int
vnet_buffer_shinfo_get_span (vlib_main_t *vm, u32 buffer_index, u32 span_index,
			     vnet_buffer_shinfo_span_t *span)
{
  vlib_buffer_t *root;
  vnet_buffer_shinfo_t shinfo;
  u32 root_index;

  if (span == 0 || vnet_buffer_shinfo_root (vm, buffer_index, &root_index, &root))
    return -1;

  return vnet_buffer_shinfo_walk (vm, root_index, &shinfo, span_index, span, 0);
}

int
vnet_buffer_shinfo_clone (vlib_main_t *vm, u32 source_buffer_index, u32 *clone_buffer_index)
{
  vlib_buffer_t *root;
  vlib_buffer_t *clone;
  vnet_buffer_shinfo_t shinfo;
  u32 root_index;
  u32 clone_index;

  if (clone_buffer_index == 0 ||
      vnet_buffer_shinfo_root (vm, source_buffer_index, &root_index, &root))
    return -1;

  if (vnet_buffer_shinfo_walk (vm, root_index, &shinfo, 0, 0, 1))
    return -1;

  /* A descriptor has no private packet header for GSO or offload paths. */
  if (shinfo.gso_enabled || root->flags & VNET_BUFFER_F_OFFLOAD)
    return -1;

  if (vlib_buffer_alloc_from_pool (vm, &clone_index, 1, root->buffer_pool_index) != 1)
    return -1;

  clone = vlib_get_buffer (vm, clone_index);
  clone->current_data = 0;
  clone->current_length = 0;
  clone->next_buffer = VLIB_BUFFER_INVALID_INDEX;
  clone->total_length_not_including_first_buffer = 0;
  clone->flags =
    root->flags &
    (VLIB_BUFFER_IS_TRACED | VNET_BUFFER_F_GSO | VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_IS_IP6 |
     VNET_BUFFER_F_OFFLOAD | VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
  if (clone->flags & VLIB_BUFFER_IS_TRACED)
    clone->trace_handle = root->trace_handle;

  clib_memset (clone->opaque, 0, sizeof (clone->opaque));
  clib_memset (clone->opaque2, 0, sizeof (clone->opaque2));
  vnet_buffer (clone)->oflags = 0;
  vnet_buffer (clone)->l3_hdr_offset = 0;
  vnet_buffer (clone)->l4_hdr_offset = 0;
  vnet_buffer2 (clone)->gso_size = 0;
  vnet_buffer2 (clone)->gso_l4_hdr_sz = 0;
  if (root->flags & VNET_BUFFER_F_OFFLOAD)
    {
      vnet_buffer (clone)->oflags = vnet_buffer (root)->oflags;
      vnet_buffer (clone)->l3_hdr_offset = vnet_buffer (root)->l3_hdr_offset;
      vnet_buffer (clone)->l4_hdr_offset = vnet_buffer (root)->l4_hdr_offset;
    }
  if (root->flags & VNET_BUFFER_F_GSO)
    {
      vnet_buffer (clone)->l3_hdr_offset = vnet_buffer (root)->l3_hdr_offset;
      vnet_buffer (clone)->l4_hdr_offset = vnet_buffer (root)->l4_hdr_offset;
      vnet_buffer2 (clone)->gso_size = vnet_buffer2 (root)->gso_size;
      vnet_buffer2 (clone)->gso_l4_hdr_sz = vnet_buffer2 (root)->gso_l4_hdr_sz;
    }

  if (vlib_buffer_shared_view_attach (vm, clone_index, root_index))
    {
      vlib_buffer_free_one (vm, clone_index);
      return -1;
    }

  *clone_buffer_index = clone_index;
  return 0;
}

int
vnet_buffer_shinfo_cow (vlib_main_t *vm, u32 *buffer_index)
{
  return vlib_buffer_shared_view_make_writable (vm, buffer_index);
}

int
vnet_buffer_shinfo_make_writable (vlib_main_t *vm, u32 *buffer_index, vlib_buffer_t **buffer)
{
  return vlib_buffer_shared_view_make_writable_and_get (vm, buffer_index, buffer);
}
