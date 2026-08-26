/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_VNET_SESSION_SESSION_OBSERVABILITY_H_
#define SRC_VNET_SESSION_SESSION_OBSERVABILITY_H_

#include <vppinfra/cache.h>
#include <vppinfra/clib.h>
#include <svm/message_queue.h>

#define SESSION_OBSERVABILITY_ABI_VERSION   2
#define SESSION_OBSERVABILITY_LAYOUT_HASH   0x6ef8e349
#define SESSION_OBSERVABILITY_SLOT_COUNT    256
#define SESSION_OBSERVABILITY_RECEIPT_MAX   128
#define SESSION_OBSERVABILITY_SEGMENT_BYTES 147712

typedef enum
{
  SESSION_OBSERVABILITY_SAMPLING_POST_HANDSHAKE = 1,
  SESSION_OBSERVABILITY_SAMPLING_POST_DATA,
  SESSION_OBSERVABILITY_SAMPLING_POST_RECOVERY,
  SESSION_OBSERVABILITY_SAMPLING_TERMINAL,
} session_observability_sampling_point_t;

typedef enum
{
  SESSION_OBSERVABILITY_HEADER_CREATED = 1,
  SESSION_OBSERVABILITY_HEADER_MAP_VALID,
  SESSION_OBSERVABILITY_HEADER_DETACHING,
  SESSION_OBSERVABILITY_HEADER_DEAD,
  SESSION_OBSERVABILITY_HEADER_RETIRED,
} session_observability_header_state_t;

/*
 * These values are shared by the VCL producer and the session-owner
 * consumer.  A ticket may be cancelled before QUEUED, but once QUEUED only
 * the owner is allowed to publish the one terminal result.
 */
typedef enum
{
  SESSION_OBSERVABILITY_CELL_FREE = 0,
  SESSION_OBSERVABILITY_CELL_INITIALIZING,
  SESSION_OBSERVABILITY_CELL_ADMITTED,
  SESSION_OBSERVABILITY_CELL_FENCE_WON,
  SESSION_OBSERVABILITY_CELL_RESERVED,
  SESSION_OBSERVABILITY_CELL_QUEUED,
  SESSION_OBSERVABILITY_CELL_DRAINING,
  SESSION_OBSERVABILITY_CELL_COMPLETED,
  SESSION_OBSERVABILITY_CELL_CANCELLED,
  SESSION_OBSERVABILITY_CELL_DEAD,
} session_observability_cell_state_t;

typedef enum
{
  SESSION_OBSERVABILITY_DIRECTORY_FREE = 0,
  SESSION_OBSERVABILITY_DIRECTORY_INITIALIZING,
  SESSION_OBSERVABILITY_DIRECTORY_LIVE,
  SESSION_OBSERVABILITY_DIRECTORY_FENCING,
  SESSION_OBSERVABILITY_DIRECTORY_INVALID,
  SESSION_OBSERVABILITY_DIRECTORY_RETIRED,
} session_observability_directory_state_t;

typedef enum
{
  SESSION_OBSERVABILITY_TICKET_FREE,
  SESSION_OBSERVABILITY_TICKET_LOCAL_RESERVED,
  SESSION_OBSERVABILITY_TICKET_COMMITTING,
  SESSION_OBSERVABILITY_TICKET_QUEUED,
  SESSION_OBSERVABILITY_TICKET_DRAINING,
  SESSION_OBSERVABILITY_TICKET_CANCELLED,
  SESSION_OBSERVABILITY_TICKET_OWNER_DEAD,
  SESSION_OBSERVABILITY_TICKET_BROKEN,
} session_observability_ticket_state_t;

typedef enum
{
  SESSION_OBSERVABILITY_CANCEL_NONE,
  SESSION_OBSERVABILITY_CANCEL_REQUESTED,
  SESSION_OBSERVABILITY_CANCEL_QUEUED,
  SESSION_OBSERVABILITY_CANCEL_OBSERVED,
} session_observability_cancel_state_t;

typedef enum
{
  SESSION_OBSERVABILITY_RESULT_NONE,
  SESSION_OBSERVABILITY_RESULT_OK,
  SESSION_OBSERVABILITY_RESULT_SESSION_NOT_FOUND,
  SESSION_OBSERVABILITY_RESULT_ASSOCIATION_TOKEN_STALE,
  SESSION_OBSERVABILITY_RESULT_ASSOCIATION_MIGRATED,
  SESSION_OBSERVABILITY_RESULT_ASSOCIATION_MISMATCH,
  SESSION_OBSERVABILITY_RESULT_DISPATCH_REJECTED,
  SESSION_OBSERVABILITY_RESULT_OWNER_DEAD,
  SESSION_OBSERVABILITY_RESULT_QUEUE_BUSY,
  SESSION_OBSERVABILITY_RESULT_DESCRIPTOR_FULL,
  SESSION_OBSERVABILITY_RESULT_RING_FULL,
  SESSION_OBSERVABILITY_RESULT_QUEUE_BROKEN,
  SESSION_OBSERVABILITY_RESULT_CANCELLED,
} session_observability_result_t;

#define SESSION_OBSERVABILITY_ADMISSION_CLOSED	   (1U << 31)
#define SESSION_OBSERVABILITY_ADMISSION_COUNT_MASK (~SESSION_OBSERVABILITY_ADMISSION_CLOSED)

typedef struct
{
  u64 magic;
  u16 abi;
  u16 header_bytes;
  u32 little_endian_marker;
  u32 layout_hash;
  u32 total_bytes;
  u32 directory_offset;
  u16 directory_count;
  u16 directory_stride;
  u32 cell_offset;
  u16 cell_count;
  u16 cell_stride;
  u32 sidecar_offset;
  u16 sidecar_count;
  u16 sidecar_stride;
  u16 event_bytes;
  u16 descriptor_bytes;
  u8 reserved_zero0[4];
  u64 segment_handle;
  u64 attachment_instance;
  u64 attach_generation;
  u64 queue_identity;
  u64 queue_generation;
  volatile u64 ticket_sequence_next;
  volatile u32 lifecycle;
  u8 reserved_zero1[148];
} __clib_packed
__clib_aligned (CLIB_CACHE_LINE_BYTES)
session_observability_header_t;

typedef struct
{
  u64 entry_nonce;
  u64 association_token;
  u64 session_handle;
  u64 attachment_instance;
  u64 binding_generation;
  u64 migration_sequence;
  u32 owner_thread;
  u32 vcl_application_association;
  volatile u32 lifecycle;
  volatile u32 admission_gate;
  volatile u32 references;
  volatile u32 admissions;
  volatile u32 mapping_references;
  volatile u32 reservations;
  u8 reserved_zero[48];
} __clib_packed
__clib_aligned (CLIB_CACHE_LINE_BYTES)
session_observability_directory_t;

typedef struct
{
  u64 magic;
  u32 abi;
  u16 header_bytes;
  u16 slot;
  u64 allocation_nonce;
  u32 owner_vcl_worker;
  u32 vcl_application_association;
  volatile u32 cell_state;
  volatile u32 references;
  volatile u32 completion_claim;
  volatile u32 cancellation;
  volatile u64 completion_sequence;
  u8 reserved_zero0[8];
  u64 request_id;
  u64 directory_nonce;
  u64 attachment_instance;
  u64 binding_generation;
  u64 association_token;
  u64 session_handle;
  u64 migration_sequence;
  u32 owner_thread;
  u32 request_vcl_application_association;
  u32 sampling_point;
  u32 request_flags;
  volatile u32 cell_references;
  volatile u32 admission_pin;
  volatile u32 reservation_pin;
  u8 reserved_zero1[4];
  u64 ticket_sequence;
  u64 reply_request_id;
  u32 reply_status;
  u32 reply_detail;
  u32 receipt_length;
  u32 reply_flags;
  u8 receipt[SESSION_OBSERVABILITY_RECEIPT_MAX];
  u8 reserved_zero2[8];
} __clib_packed
__clib_aligned (CLIB_CACHE_LINE_BYTES)
session_observability_cell_t;

typedef struct
{
  u64 queue_identity;
  u64 queue_generation;
  u64 ticket_sequence;
  u64 allocation_nonce;
  u64 directory_nonce;
  u64 attachment_instance;
  u64 binding_generation;
  u32 ring_index;
  u32 ring_element_index;
  u32 descriptor_element_index;
  u32 attachment_slot;
  volatile u32 references;
  volatile u32 result;
  volatile u32 ticket_state;
  u32 flags;
  u8 reserved_zero[40];
} __clib_packed
__clib_aligned (CLIB_CACHE_LINE_BYTES)
session_observability_sidecar_t;

typedef struct session_observability_segment_ session_observability_segment_t;

/*
 * The attachment owns the queue and mapped image.  A producer takes one
 * reference before it publishes a ticket; the final consumer release calls
 * release only after a detach/death path dropped the attachment's base ref.
 */
typedef struct session_observability_owner_
{
  session_observability_segment_t *segment;
  svm_msg_q_t *queue;
  volatile u32 references;
  volatile u32 fenced;
  void (*drained) (struct session_observability_owner_ *owner);
  void (*release) (struct session_observability_owner_ *owner);
} session_observability_owner_t;

typedef struct
{
  u16 abi;
  u16 bytes;
  u32 layout_hash;
  u64 segment_handle;
  u64 attachment_instance;
  u64 attach_generation;
  u64 queue_identity;
  u64 queue_generation;
  u32 segment_bytes;
  u32 binding_index;
  u64 binding_nonce;
} __clib_packed session_observability_descriptor_t;

typedef struct
{
  u16 opcode;
  u16 abi;
  u32 attachment_slot;
  u64 allocation_nonce;
  u64 association_token;
  u64 session_handle;
  u64 directory_nonce;
  u64 attachment_instance;
  u64 binding_generation;
  u64 request_id;
  u32 owner_thread;
  u32 vcl_application_association;
  u64 ticket_sequence;
} __clib_packed session_observability_event_t;

/*
 * This is private VPP-side state.  It is deliberately separate from the
 * shared ABI so a producer can retain the exact image objects it admitted
 * until the owner either completes or drains the ticket.
 */
typedef struct
{
  session_observability_directory_t *directory;
  session_observability_cell_t *cell;
  session_observability_sidecar_t *sidecar;
  session_observability_owner_t *owner;
  session_observability_event_t event;
} session_observability_admission_t;

/*
 * This is deliberately a value-only transport boundary.  The session layer
 * owns the attachment image and performs the one-shot completion after the
 * transport returns; a transport hook never receives a mapping, cell, queue
 * ticket, or VCL identity it could retain.
 */
typedef struct
{
  u16 schema_version;
  u16 sampling_point;
  u32 request_flags;
  u64 request_id;
  u64 session_handle;
  u64 association_token;
  u64 directory_nonce;
  u64 binding_generation;
  u32 owner_thread;
  u32 application_association;
} session_observability_request_t;

typedef struct
{
  u64 request_id;
  u32 status;
  u32 detail;
  u32 receipt_length;
  u32 reply_flags;
  u8 receipt[SESSION_OBSERVABILITY_RECEIPT_MAX];
} session_observability_reply_t;

/* A terminal sink is a value-only transport boundary.  The opaque value is
 * generated by the session layer and is resolved there; it is not a pointer
 * to an attachment, a session, or VCL-owned state. */
typedef struct session_observability_terminal_sink_
{
  u64 opaque;
  int (*complete) (const struct session_observability_terminal_sink_ *sink,
		   const session_observability_reply_t *reply);
} session_observability_terminal_sink_t;

/* This is an internal completion sink.  It carries only the fixed redacted
 * reply and is not an attachment mapping or a generic transport callback. */
typedef void (*session_observability_completion_fn_t) (void *context,
						       const session_observability_reply_t *reply);

int session_observability_terminal_complete (const session_observability_terminal_sink_t *sink,
					     const session_observability_reply_t *reply);
int session_observability_terminal_request_id_in_use (session_observability_owner_t *owner,
						      u64 request_id);
int session_observability_terminal_await (session_observability_owner_t *owner, u64 request_id,
					  session_observability_completion_fn_t completion,
					  void *completion_context);
int session_observability_terminal_cancel (session_observability_owner_t *owner, u64 request_id,
					   session_observability_result_t result);

struct session_observability_segment_
{
  session_observability_header_t header;
  session_observability_directory_t directory[SESSION_OBSERVABILITY_SLOT_COUNT];
  session_observability_cell_t cell[SESSION_OBSERVABILITY_SLOT_COUNT];
  session_observability_sidecar_t sidecar[SESSION_OBSERVABILITY_SLOT_COUNT];
} __clib_packed __clib_aligned (CLIB_CACHE_LINE_BYTES);

STATIC_ASSERT (sizeof (session_observability_header_t) == 256, "observability header ABI changed");
STATIC_ASSERT (sizeof (session_observability_directory_t) == 128,
	       "observability directory ABI changed");
STATIC_ASSERT (sizeof (session_observability_cell_t) == 320, "observability cell ABI changed");
STATIC_ASSERT (sizeof (session_observability_sidecar_t) == 128,
	       "observability sidecar ABI changed");
STATIC_ASSERT (sizeof (session_observability_descriptor_t) == 64,
	       "observability descriptor ABI changed");
STATIC_ASSERT (sizeof (session_observability_event_t) == 80, "observability event ABI changed");
STATIC_ASSERT (sizeof (session_observability_segment_t) == SESSION_OBSERVABILITY_SEGMENT_BYTES,
	       "observability segment ABI changed");
STATIC_ASSERT (STRUCT_OFFSET_OF (session_observability_segment_t, directory) == 256,
	       "observability directory offset changed");
STATIC_ASSERT (STRUCT_OFFSET_OF (session_observability_segment_t, cell) == 33024,
	       "observability cell offset changed");
STATIC_ASSERT (STRUCT_OFFSET_OF (session_observability_segment_t, sidecar) == 114944,
	       "observability sidecar offset changed");

static inline int
session_observability_descriptor_is_valid (const session_observability_descriptor_t *descriptor)
{
  return descriptor && descriptor->abi == SESSION_OBSERVABILITY_ABI_VERSION &&
	 descriptor->bytes == sizeof (*descriptor) &&
	 descriptor->layout_hash == SESSION_OBSERVABILITY_LAYOUT_HASH &&
	 descriptor->segment_bytes == SESSION_OBSERVABILITY_SEGMENT_BYTES &&
	 descriptor->segment_handle && descriptor->attachment_instance &&
	 descriptor->attach_generation && descriptor->queue_identity &&
	 descriptor->queue_generation && descriptor->binding_nonce;
}

static inline int
session_observability_cell_claim_completion (session_observability_cell_t *cell)
{
  u32 expected = 0;

  return clib_atomic_cmp_and_swap_acq_relax_n (&cell->completion_claim, &expected, 1, 0);
}

static inline void
session_observability_cell_complete (session_observability_cell_t *cell,
				     session_observability_result_t result)
{
  if (!session_observability_cell_claim_completion (cell))
    return;

  cell->reply_request_id = cell->request_id;
  cell->reply_status = result == SESSION_OBSERVABILITY_RESULT_OK ? 1 : 2;
  cell->reply_detail = result;
  cell->receipt_length = 0;
  cell->reply_flags = 0;
  clib_memset (cell->receipt, 0, sizeof (cell->receipt));
  clib_atomic_store_rel_n (&cell->cell_state, SESSION_OBSERVABILITY_CELL_COMPLETED);
  clib_atomic_fetch_add_rel (&cell->completion_sequence, 1);
}

static inline void
session_observability_cell_complete_reply (session_observability_cell_t *cell,
					   const session_observability_reply_t *reply)
{
  if (!session_observability_cell_claim_completion (cell))
    return;

  cell->reply_request_id = reply->request_id;
  cell->reply_status = reply->status;
  cell->reply_detail = reply->detail;
  cell->receipt_length = clib_min (reply->receipt_length, (u32) sizeof (cell->receipt));
  cell->reply_flags = reply->reply_flags;
  clib_memset (cell->receipt, 0, sizeof (cell->receipt));
  clib_memcpy_fast (cell->receipt, reply->receipt, cell->receipt_length);
  clib_atomic_store_rel_n (&cell->cell_state, SESSION_OBSERVABILITY_CELL_COMPLETED);
  clib_atomic_fetch_add_rel (&cell->completion_sequence, 1);
}

#endif /* SRC_VNET_SESSION_SESSION_OBSERVABILITY_H_ */
