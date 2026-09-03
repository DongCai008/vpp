/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#ifndef SRC_VNET_SESSION_TRANSPORT_H_
#define SRC_VNET_SESSION_TRANSPORT_H_

#include <vnet/vnet.h>
#include <vnet/session/session_types.h>
#include <vnet/session/transport_types.h>

#define TRANSPORT_PACER_MIN_MSS 	1460
#define TRANSPORT_PACER_MIN_BURST 	TRANSPORT_PACER_MIN_MSS
#define TRANSPORT_PACER_MAX_BURST	(43 * TRANSPORT_PACER_MIN_MSS)
#define TRANSPORT_PACER_MAX_BURST_PKTS	43
#define TRANSPORT_PACER_BURSTS_PER_RTT	20
#define TRANSPORT_PACER_MIN_IDLE	100
#define TRANSPORT_PACER_IDLE_FACTOR	0.05

typedef struct _transport_options_t
{
  char *name;
  char *short_name;
  transport_tx_fn_type_t tx_type;
  transport_service_type_t service_type;
} transport_options_t;

typedef enum transport_snd_flags_
{
  TRANSPORT_SND_F_DESCHED = 1 << 0,
  TRANSPORT_SND_F_POSTPONE = 1 << 1,
  TRANSPORT_SND_N_FLAGS
} __clib_packed transport_snd_flags_t;

typedef struct transport_send_params_
{
  union
  {
    /* Used to retrieve snd params from transports */
    struct
    {
      u32 snd_space;
      u32 tx_offset;
      u16 snd_mss;
    };
    /* Used by custom tx functions */
    struct
    {
      u32 max_burst_size;
      u32 bytes_dequeued;
    };
  };
  transport_snd_flags_t flags;
} transport_send_params_t;

/**
 * Session table iteration connection information
 *
 * session_connection_info_t is the value boundary the barrier-owned session
 * table dump (session.api's session_table_dump) uses to pull
 * transport-specific state out of a transport connection while the worker
 * barrier is held. It is:
 *
 *  - an internal, short-lived, host-order C structure, valid only for the
 *    duration of the call that fills it;
 *  - value-only: every field is a copy, never a pointer into live session,
 *    transport, or TCP socket state; and
 *  - NOT a binary API message, a shared-memory layout, a SAPI/VCL/
 *    application ABI, or a stable cross-version plugin ABI. session.api's
 *    messages are the wire contract; this structure is only ever converted
 *    into them, never sent as-is. It must not be assumed stable across
 *    independently built plugins linked against different VPP headers.
 *
 * transport_endpoint_t rmt/lcl are the one exception to "host-order": their
 * address and port fields keep transport_endpoint_t's own normal internal
 * representation (see foreach_transport_endpoint_fields above), not a
 * host-order reinterpretation of it. session_api.c is solely responsible for
 * converting every field, including these, to the public API representation
 * and byte order.
 */

#define SESSION_CONNECTION_INFO_VERSION 1

typedef enum session_connection_info_status_
{
  SESSION_CONNECTION_INFO_OK = 0,
  SESSION_CONNECTION_INFO_NOT_SUPPORTED,
  SESSION_CONNECTION_INFO_NOT_FOUND,
  SESSION_CONNECTION_INFO_LINK_MISMATCH,
  SESSION_CONNECTION_INFO_STATE_UNAVAILABLE,
  SESSION_CONNECTION_INFO_INVALID_DATA,
  SESSION_CONNECTION_INFO_INTERNAL_ERROR,
} session_connection_info_status_t;

typedef enum session_connection_info_field_
{
  SESSION_CONNECTION_INFO_F_ENDPOINTS = 1ULL << 0,
  SESSION_CONNECTION_INFO_F_TCP_STATE = 1ULL << 1,
  SESSION_CONNECTION_INFO_F_TCP_RECOVERY = 1ULL << 2,
  SESSION_CONNECTION_INFO_F_TCP_SEQUENCES = 1ULL << 3,
  SESSION_CONNECTION_INFO_F_TCP_CONGESTION = 1ULL << 4,
  SESSION_CONNECTION_INFO_F_TCP_TIMING = 1ULL << 5,
  SESSION_CONNECTION_INFO_F_TCP_RECOVERY_DATA = 1ULL << 6,
  SESSION_CONNECTION_INFO_F_TCP_TIMESTAMPS = 1ULL << 7,
} session_connection_info_field_t;

/**
 * Copied, value-only TCP state. Populated only by a TCP
 * get_connection_info () provider; see session_connection_info_field_t for
 * which fields a given valid_fields bitmap actually covers.
 */
typedef struct session_tcp_info_
{
  u8 tcp_state;
  u8 recovery_state;
  u8 timestamp_negotiated;
  u8 reserved;
  u32 snd_una;
  u32 snd_nxt;
  u32 rcv_nxt;
  u32 cwnd;
  u32 ssthresh;
  u32 rto_usecs;
  u32 receive_rtt_usecs;
  u32 retransmits;
  u32 high_seq;
  u32 recovery_point;
} session_tcp_info_t;

typedef struct session_connection_info_
{
  u16 version;
  u16 bytes;
  transport_proto_t transport_proto;
  session_connection_info_status_t status;
  u16 reserved;
  u64 valid_fields;
  transport_endpoint_t rmt;
  transport_endpoint_t lcl;
  union
  {
    session_tcp_info_t tcp;
  } data;
} session_connection_info_t;

/*
 * Transport protocol virtual function table
 */
typedef struct _transport_proto_vft
{
  /*
   * Setup
   */
  u32 (*start_listen) (u32 session_index, transport_endpoint_cfg_t *lcl);
  u32 (*stop_listen) (u32 conn_index);
  int (*connect) (transport_endpoint_cfg_t *rmt, transport_connection_t **tconn);
  int (*connect_stream) (transport_endpoint_cfg_t *rmt,
			 session_t *session_index, u32 *conn_index);
  void (*half_close) (u32 conn_index, clib_thread_index_t thread_index);
  void (*close) (u32 conn_index, clib_thread_index_t thread_index);
  void (*reset) (u32 conn_index, clib_thread_index_t thread_index);
  void (*cleanup) (u32 conn_index, clib_thread_index_t thread_index);
  void (*cleanup_ho) (u32 conn_index, clib_thread_index_t thread_index);
  clib_error_t *(*enable) (vlib_main_t * vm, u8 is_en);

  /*
   * Transmission
   */

  u32 (*push_header) (transport_connection_t *tconn, vlib_buffer_t **b,
		      u32 n_bufs);
  int (*send_params) (transport_connection_t * tconn,
		      transport_send_params_t *sp);
  void (*update_time) (f64 time_now, u8 thread_index);
  void (*flush_data) (transport_connection_t *tconn);
  int (*custom_tx) (void *session, transport_send_params_t *sp);
  int (*app_rx_evt) (transport_connection_t *tconn);
  void (*pmtu_update) (transport_connection_t *tconn, u16 pmtu);

  /*
   * Connection retrieval
   */
  transport_connection_t *(*get_connection) (u32 conn_idx,
					     clib_thread_index_t thread_idx);
  transport_connection_t *(*get_listener) (u32 conn_index);
  transport_connection_t *(*get_half_open) (u32 conn_index, clib_thread_index_t thread_index);

  /*
   * Format
   */
  u8 *(*format_connection) (u8 * s, va_list * args);
  u8 *(*format_listener) (u8 * s, va_list * args);
  u8 *(*format_half_open) (u8 * s, va_list * args);

  /*
   *  Properties retrieval/setting
   */
  void (*get_transport_endpoint) (u32 conn_index,
				  clib_thread_index_t thread_index,
				  transport_endpoint_t *tep_rmt,
				  transport_endpoint_t *tep_lcl);
  void (*get_transport_listener_endpoint) (u32 conn_index,
					   transport_endpoint_t *tep_rmt,
					   transport_endpoint_t *tep_lcl);
  int (*attribute) (u32 conn_index, clib_thread_index_t thread_index,
		    u8 is_get, transport_endpt_attr_t *attr);

  /*
   * Session table iteration
   */

  /**
   * Barrier-safe transport connection information provider (optional)
   *
   * Called only by the session layer's barrier-owned table dump collector,
   * while the worker barrier is held and thread_index's workers are
   * stopped. thread_index names the worker that owns connection_index and
   * may differ from vlib_get_thread_index (): the barrier, not thread
   * ownership, is what makes it safe to read that worker's state from the
   * main thread. expected_session_index lets the provider verify the
   * session-to-transport linkage before it copies anything.
   *
   * The callback must be synchronous, read-only, allocation-free,
   * nonblocking, and complete before it returns. Like every
   * session_table_iter_fn_t callback (session.h), it must not retain a
   * session, transport, TCP socket, FIFO, pool or vector pointer beyond the
   * call; invoke a worker-local execution API; send an RPC, session event,
   * or binary API message; acquire the worker barrier, recursively or
   * otherwise; wait on a queue, mutex, condition variable or file
   * descriptor; format unbounded text; or close, migrate, reset or
   * otherwise mutate the session or its transport.
   *
   * Before calling, the collector clears *info and sets its version, bytes,
   * transport_proto and a default status of
   * SESSION_CONNECTION_INFO_NOT_SUPPORTED, so a NULL get_connection_info is
   * always safe and unambiguous: an absent provider is simply
   * "not supported", not a missing session.
   *
   * On a normal (>= 0) return, the callback must have set every field of
   * *info its declared version defines: version, bytes, transport_proto,
   * status, valid_fields for every field group it populated, and every
   * reserved byte zeroed. status == OK requires every field group this
   * transport's initial API contract promises; anything else uses a
   * defined non-OK status and sets valid_fields only for the groups it
   * actually filled in.
   *
   * A negative return means the invocation itself failed (e.g. a broken
   * provider invariant); the collector then discards *info entirely and
   * substitutes SESSION_CONNECTION_INFO_INTERNAL_ERROR. An ordinary runtime
   * outcome, such as connection_index no longer being present or a
   * session/connection mismatch, must be reported through a successful
   * return and the matching *info status, never a negative return.
   *
   * @param connection_index       transport connection index to inspect.
   * @param thread_index           worker owning connection_index.
   * @param expected_session_index session index the caller expects
   *                                connection_index to still be linked to.
   * @param info                   caller-owned output; written only for the
   *                                duration of this call.
   * @return 0 on a well-formed result (see info->status for the outcome),
   *         negative only when the invocation itself could not produce a
   *         usable result.
   */
  int (*get_connection_info) (u32 connection_index,
			      clib_thread_index_t thread_index,
			      u32 expected_session_index,
			      session_connection_info_t *info);

  /*
   * Properties
   */
  transport_options_t transport_options;
} transport_proto_vft_t;

extern transport_proto_vft_t *tp_vfts;

#define transport_proto_foreach(VAR, VAR_ALLOW_BM)                            \
  for (VAR = 0; VAR < vec_len (tp_vfts); VAR++)                               \
    if (tp_vfts[VAR].push_header != 0)                                        \
      if (VAR_ALLOW_BM & (1 << VAR))

int transport_connect (transport_proto_t tp, transport_endpoint_cfg_t *tep,
		       transport_connection_t **tconn);
int transport_connect_stream (transport_proto_t tp,
			      transport_endpoint_cfg_t *tep,
			      session_t *stream_session, u32 *conn_index);
void transport_half_close (transport_proto_t tp, u32 conn_index,
			   u8 thread_index);
void transport_close (transport_proto_t tp, u32 conn_index, u8 thread_index);
void transport_reset (transport_proto_t tp, u32 conn_index, u8 thread_index);
u32 transport_start_listen (transport_proto_t tp, u32 session_index,
			    transport_endpoint_cfg_t *tep);
u32 transport_stop_listen (transport_proto_t tp, u32 conn_index);
void transport_cleanup (transport_proto_t tp, u32 conn_index,
			u8 thread_index);
void transport_cleanup_half_open (transport_proto_t tp, u32 conn_index,
				  clib_thread_index_t thread_index);
void transport_get_endpoint (transport_proto_t tp, u32 conn_index,
			     clib_thread_index_t thread_index,
			     transport_endpoint_t *tep_rmt,
			     transport_endpoint_t *tep_lcl);
void transport_get_listener_endpoint (transport_proto_t tp, u32 conn_index,
				      transport_endpoint_t *tep_rmt,
				      transport_endpoint_t *tep_lcl);
int transport_connection_attribute (transport_proto_t tp, u32 conn_index,
				    u8 thread_index, u8 is_get,
				    transport_endpt_attr_t *attr);

static inline transport_connection_t *
transport_get_connection (transport_proto_t tp, u32 conn_index,
			  u8 thread_index)
{
  return tp_vfts[tp].get_connection (conn_index, thread_index);
}

static inline transport_connection_t *
transport_get_listener (transport_proto_t tp, u32 conn_index)
{
  return tp_vfts[tp].get_listener (conn_index);
}

static inline transport_connection_t *
transport_get_half_open (transport_proto_t tp, u32 conn_index, clib_thread_index_t thread_index)
{
  return tp_vfts[tp].get_half_open (conn_index, thread_index);
}

static inline int
transport_custom_tx (transport_proto_t tp, void *s,
		     transport_send_params_t * sp)
{
  return tp_vfts[tp].custom_tx (s, sp);
}

static inline int
transport_app_rx_evt (transport_proto_t tp, u32 conn_index,
		      clib_thread_index_t thread_index)
{
  transport_connection_t *tc;
  if (!tp_vfts[tp].app_rx_evt)
    return 0;
  tc = transport_get_connection (tp, conn_index, thread_index);
  return tp_vfts[tp].app_rx_evt (tc);
}

/**
 * Get send parameters for transport connection
 *
 * These include maximum tx burst, mss, tx offset and other flags
 * transport might want to provide to sessin layer
 *
 * @param tc		transport connection
 * @param sp		send paramaters
 *
 */
static inline u32
transport_connection_snd_params (transport_connection_t * tc,
				 transport_send_params_t * sp)
{
  return tp_vfts[tc->proto].send_params (tc, sp);
}

static inline u8
transport_connection_is_descheduled (transport_connection_t * tc)
{
  return ((tc->flags & TRANSPORT_CONNECTION_F_DESCHED) ? 1 : 0);
}

static inline void
transport_connection_deschedule (transport_connection_t * tc)
{
  tc->flags |= TRANSPORT_CONNECTION_F_DESCHED;
}

static inline u8
transport_connection_is_cless (transport_connection_t * tc)
{
  return ((tc->flags & TRANSPORT_CONNECTION_F_CLESS) ? 1 : 0);
}

void transport_connection_reschedule (transport_connection_t * tc);
void transport_fifos_init_ooo (transport_connection_t * tc);

/**
 * Register transport virtual function table.
 *
 * @param transport_proto - transport protocol type (i.e., TCP, UDP ..)
 * @param vft - virtual function table for transport proto
 * @param fib_proto - network layer protocol
 * @param output_node - output node index that session layer will hand off
 * 			buffers to, for requested fib proto
 */
void transport_register_protocol (transport_proto_t transport_proto,
				  const transport_proto_vft_t * vft,
				  fib_protocol_t fib_proto, u32 output_node);
transport_proto_t
transport_register_new_protocol (const transport_proto_vft_t * vft,
				 fib_protocol_t fib_proto, u32 output_node);
const transport_proto_vft_t *transport_protocol_get_vft (transport_proto_t tp);
void transport_update_time (clib_time_type_t time_now, u8 thread_index);

int transport_alloc_local_port (u8 proto, ip46_address_t *ip,
				transport_endpoint_cfg_t *rmt);
int transport_alloc_local_endpoint (u8 proto, transport_endpoint_cfg_t *rmt,
				    ip46_address_t *lcl_addr, u16 *lcl_port);
void transport_share_local_endpoint (u8 proto, u32 fib_index,
				     ip46_address_t *lcl_ip, u16 port);
int transport_mark_used_local_endpoint (u8 proto, u32 fib_index, ip46_address_t *ip, u16 port);
int transport_release_local_endpoint (u8 proto, u32 fib_index, ip46_address_t *lcl_ip, u16 port);
u16 transport_port_alloc_max_tries ();
u32 transport_port_local_in_use ();
void transport_clear_stats ();
void transport_enable_disable (vlib_main_t * vm, u8 is_en);
void transport_init (void);

always_inline u32
transport_elog_track_index (transport_connection_t * tc)
{
#if TRANSPORT_DEBUG
  return tc->elog_track.track_index_plus_one - 1;
#else
  return ~0;
#endif
}

void transport_connection_tx_pacer_reset (transport_connection_t * tc,
					  u64 rate_bytes_per_sec,
					  u32 initial_bucket,
					  clib_us_time_t rtt);
/**
 * Initialize tx pacer for connection
 *
 * @param tc				transport connection
 * @param rate_bytes_per_second		initial byte rate
 * @param burst_bytes			initial burst size in bytes
 */
void transport_connection_tx_pacer_init (transport_connection_t *tc, u64 rate_bytes_per_sec,
					 u32 initial_bucket, u32 min_burst);

/**
 * Update tx pacer pacing rate
 *
 * @param tc			transport connection
 * @param bytes_per_sec		new pacing rate
 * @param rtt			connection rtt that is used to compute
 * 				inactivity time after which pacer bucket is
 * 				reset to 1 mtu
 */
void transport_connection_tx_pacer_update (transport_connection_t * tc,
					   u64 bytes_per_sec,
					   clib_us_time_t rtt);

/**
 * Get tx pacer max burst
 *
 * @param tc		transport connection
 * @param time_now	current cpu time
 * @return		max burst for connection
 */
u32 transport_connection_tx_pacer_burst (transport_connection_t * tc);

/**
 * Get tx pacer current rate
 *
 * @param tc		transport connection
 * @return		rate for connection in bytes/s
 */
u64 transport_connection_tx_pacer_rate (transport_connection_t * tc);

/**
 * Reset tx pacer bucket
 *
 * @param tc		transport connection
 * @param bucket	value the bucket will be reset to
 */
void transport_connection_tx_pacer_reset_bucket (transport_connection_t * tc,
						 u32 bucket);

/**
 * Check if transport connection is paced
 */
always_inline u8
transport_connection_is_tx_paced (transport_connection_t * tc)
{
  return (tc->flags & TRANSPORT_CONNECTION_F_IS_TX_PACED);
}

/**
 * Clear descheduled flag and update pacer if needed
 *
 * To add session to scheduler use @ref transport_connection_reschedule
 */
always_inline void
transport_connection_clear_descheduled (transport_connection_t *tc)
{
  tc->flags &= ~TRANSPORT_CONNECTION_F_DESCHED;
  if (transport_connection_is_tx_paced (tc))
    transport_connection_tx_pacer_reset_bucket (tc, 0 /* bucket */);
}

u8 *format_transport_pacer (u8 * s, va_list * args);

/**
 * Update tx bytes for paced transport connection
 *
 * If tx pacing is enabled, this update pacer bucket to account for the
 * amount of bytes that have been sent.
 *
 * @param tc		transport connection
 * @param bytes		bytes recently sent
 */
void transport_connection_update_tx_bytes (transport_connection_t * tc,
					   u32 bytes);

void
transport_connection_tx_pacer_update_bytes (transport_connection_t * tc,
					    u32 bytes);

/**
 * Request pacer time update
 *
 * @param thread_index	thread for which time is updated
 * @param now		time now
 */
void transport_update_pacer_time (clib_thread_index_t thread_index,
				  clib_time_type_t now);

#endif /* SRC_VNET_SESSION_TRANSPORT_H_ */
