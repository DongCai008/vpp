/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/*
 * Copyright (c) 2026
 */

#ifndef included_vnet_buffer_shinfo_h
#define included_vnet_buffer_shinfo_h

#include <vnet/buffer.h>

typedef enum
{
  VNET_BUFFER_SHINFO_GSO_TYPE_NONE,
  VNET_BUFFER_SHINFO_GSO_TYPE_TCP4,
  VNET_BUFFER_SHINFO_GSO_TYPE_TCP6,
} vnet_buffer_shinfo_gso_type_t;

typedef struct
{
  u32 root_buffer_index;
  u32 data_bytes;
  u32 backing_bytes;
  u32 span_count;
  u32 gso_segs;
  u16 chain_buffers;
  u16 gso_size;
  u16 gso_l4_header_size;
  u8 gso_enabled;
  u8 gso_type;
  u8 offload_flags;
} vnet_buffer_shinfo_t;

typedef struct
{
  u16 buffer_pool;
  u16 reserved;
  u32 buffer_index;
  i32 data_offset;
  u32 length;
} vnet_buffer_shinfo_span_t;

int vnet_buffer_shinfo_get (vlib_main_t *vm, u32 buffer_index, vnet_buffer_shinfo_t *shinfo);

int vnet_buffer_shinfo_get_span (vlib_main_t *vm, u32 buffer_index, u32 span_index,
				 vnet_buffer_shinfo_span_t *span);

int vnet_buffer_shinfo_clone (vlib_main_t *vm, u32 source_buffer_index, u32 *clone_buffer_index);

#endif /* included_vnet_buffer_shinfo_h */
