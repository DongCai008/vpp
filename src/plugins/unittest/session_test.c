/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#include <arpa/inet.h>
#include <vnet/session/application.h>
#include <vnet/session/application_crypto.h>
#include <vnet/session/session.h>
#include <vnet/session/session_lookup.h>
#include <vnet/session/session_sdl.h>
#include <vnet/session/transport.h>
#include <vnet/tcp/tcp_inlines.h>
#include <sys/epoll.h>
#include <vnet/session/session_rules_table.h>
#include <unittest/session/test_session_helpers.h>

#define vl_typedefs
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_typedefs

extern int vcl_test_preclosed_connected (svm_msg_q_t *mq, u32 client_index,
					  session_handle_t vpp_handle);
extern int vcl_test_preclosed_connect_error (void);
extern void vl_api_memclnt_delete_t_handler (vl_api_memclnt_delete_t *mp);

#define SESSION_TEST_I(_cond, _comment, _args...)		\
({								\
  int _evald = (_cond);						\
  if (!(_evald)) {						\
    fformat(stderr, "FAIL:%d: " _comment "\n",			\
	    __LINE__, ##_args);					\
  } else {							\
    fformat(stderr, "PASS:%d: " _comment "\n",			\
	    __LINE__, ##_args);					\
  }								\
  _evald;							\
})

#define SESSION_TEST(_cond, _comment, _args...)                               \
  do                                                                          \
    {                                                                         \
      if (!SESSION_TEST_I (_cond, _comment, ##_args))                         \
	{                                                                     \
	  return 1;                                                           \
	}                                                                     \
    }                                                                         \
  while (0)

#define ST_DBG(_comment, _args...) fformat (stderr, _comment "\n", ##_args);

static void
session_test_cli_input (vlib_main_t *vm, char *cmd)
{
  unformat_input_t input;

  unformat_init_string (&input, cmd, strlen (cmd));
  vlib_cli_input (vm, &input, 0, 0);
  unformat_free (&input);
}

static u32 session_test_ca_update_count;
static app_crypto_ca_trust_update_type_t session_test_ca_update_type;

static void
session_test_ca_update_cb (app_crypto_ca_trust_int_ctx_t *cti, app_crypto_ca_trust_t *ct,
			   app_crypto_ca_trust_update_type_t type)
{
  session_test_ca_update_count++;
  session_test_ca_update_type = type;
}

static u32 session_test_crypto_async_count;
static u32 session_test_crypto_async_reply_count;
static app_crypto_async_req_t *session_test_crypto_async_last_req;
static app_crypto_async_req_handle_t session_test_crypto_async_reply_handle;

static int
session_test_crypto_async_cb (app_crypto_async_req_t *req)
{
  session_test_crypto_async_count++;
  session_test_crypto_async_last_req = req;
  return 0;
}

static void
session_test_crypto_async_reply_cb (app_crypto_async_reply_t *reply)
{
  session_test_crypto_async_reply_count++;
  session_test_crypto_async_reply_handle = reply->handle;
}

static void
session_test_sdl_walk_cb (u32 fei, ip46_address_t *rmt_ip, u16 fp_len, u32 action_index,
			  u32 fp_proto, u8 *tag, void *args)
{
  u32 *n_rules = args;
  *n_rules += 1;
}

static int session_test_endpoint_cfg (vlib_main_t *vm, unformat_input_t *input);

static volatile u32 session_test_cancel_connect_notifications;
static volatile u32 session_test_cancel_connect_context;
static volatile u32 session_test_connect_completions;
static volatile u32 session_test_connect_context;

typedef struct
{
  session_handle_t half_open;
  session_handle_t connected;
  app_worker_t *app_wrk;
  volatile u8 done;
  int rv;
} session_test_complete_connect_args_t;

static session_test_complete_connect_args_t session_test_complete_connect_args;

static void
session_test_complete_connect_on_worker (void *arg)
{
  session_test_complete_connect_args_t *args = arg;
  tcp_connection_t *tc, *new_tc;
  session_t *ho;

  ho = session_get_from_handle_if_valid (args->half_open);
  if (!ho)
    {
      args->rv = -1;
      goto done;
    }

  tc = tcp_ho_connection_get (ho->connection_index);
  new_tc = tcp_connection_alloc_w_base (vlib_get_thread_index (), &tc);
  new_tc->state = TCP_STATE_ESTABLISHED;
  args->rv = session_stream_connect_notify (&new_tc->connection, SESSION_E_NONE);
  if (!args->rv)
    args->connected = session_handle (
      session_get (new_tc->c_s_index, new_tc->c_thread_index));

  if (!tcp_half_open_connection_cleanup (tc))
    app_wrk_flush_wrk_events (args->app_wrk, vlib_get_thread_index ());
done:
  args->done = 1;
}

static void
session_test_cleanup_connect_on_worker (void *arg)
{
  session_test_complete_connect_args_t *args = arg;
  session_t *s;
  transport_connection_t *tc;

  s = session_get_from_handle_if_valid (args->connected);
  if (!s)
    goto done;
  tc = session_get_transport (s);
  session_lookup_del_connection (tc);
  transport_cleanup (TRANSPORT_PROTO_TCP, s->connection_index, s->thread_index);
  session_cleanup (s);
done:
  args->done = 1;
}

static int
session_test_cancel_connect_callback (u32 app_index, u32 api_context, session_t *s,
			      session_error_t err)
{
  (void) app_index;
  if (!s && err == SESSION_E_INVALID)
    {
      session_test_cancel_connect_notifications++;
      session_test_cancel_connect_context = api_context;
    }
  else if (s && !err)
    {
      session_test_connect_completions++;
      session_test_connect_context = api_context;
    }
  return 0;
}

static session_cb_vft_t session_test_cancel_connect_cbs = {
  .session_connected_callback = session_test_cancel_connect_callback,
};

static void
session_test_send_connect_event (svm_msg_q_t *mq, session_evt_type_t event_type,
				 u32 client_index, u32 context, uword ext_config)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_connect_msg_t *mp;

  app_alloc_ctrl_evt_to_vpp (mq, app_evt, event_type);
  mp = (session_connect_msg_t *) app_evt->evt->data;
  clib_memset (mp, 0, sizeof (*mp));
  mp->client_index = client_index;
  mp->wrk_index = 0;
  mp->context = context;
  mp->ext_config = ext_config;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

static int
session_test_preconnect_cancel (vlib_main_t *vm, unformat_input_t *input)
{
  const u32 pending_context = 0x101, half_open_context = 0x202,
	    successful_context = 0x303;
  u64 options[APP_OPTIONS_N_OPTIONS] = { 0 };
  vnet_app_attach_args_t attach_args = {
    .namespace_id = 0,
    .session_cb_vft = &session_test_cancel_connect_cbs,
    .name = format (0, "preconnect_cancel_test"),
  };
  vnet_app_detach_args_t detach_args;
  vnet_connect_args_t connect_args = { 0 };
  vl_api_memclnt_delete_reply_t *delete_reply;
  svm_queue_t *api_queue = 0;
  app_worker_t *app_wrk;
  application_t *app;
  fifo_segment_t *rx_mqs_segment;
  svm_fifo_chunk_t *ext_config_chunk;
  svm_msg_q_t *mq;
  session_worker_t *wrk;
  session_handle_t *sh = 0;
  session_t *ho;
  session_test_complete_connect_args_t *complete_args =
    &session_test_complete_connect_args;
  svm_msg_q_shared_t *vcl_mq_shared = 0;
  svm_msg_q_t vcl_mq = { 0 };
  svm_msg_q_ring_cfg_t vcl_ring_cfg[SESSION_MQ_N_RINGS] = {
    [SESSION_MQ_IO_EVT_RING] = { 4, sizeof (session_event_t), 0 },
    [SESSION_MQ_CTRL_EVT_RING] = { 4,
				   sizeof (session_event_t) + sizeof (session_terminate_msg_t), 0 },
  };
  svm_msg_q_cfg_t vcl_mq_cfg = {
    .consumer_pid = getpid (),
    .q_nitems = 4,
    .n_rings = SESSION_MQ_N_RINGS,
    .ring_cfgs = vcl_ring_cfg,
  };
  svm_msg_q_msg_t vcl_msg;
  session_event_t *vcl_evt;
  session_terminate_msg_t *vcl_terminate;
  ip4_address_t intf_addr[2];
  u32 api_index = ~0, app_index = APP_INVALID_INDEX, sw_if_index[2];
  int rv = -1;

  u32 ext_config_free_chunks, ext_config_chunk_size, pending_connects;
  uword ext_config;

  (void) input;
  if (!transport_cl_thread ())
    return 1;

  api_queue = svm_queue_alloc_and_init (1, sizeof (uword), getpid ());
  if (!api_queue)
    goto done;
  api_index = vl_api_memclnt_create_internal ("preconnect_cancel_test", api_queue);
  if (api_index == ~0 || !vl_api_client_index_to_registration (api_index))
    goto done;

  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  attach_args.api_client_index = api_index;
  attach_args.options = options;
  if (vnet_application_attach (&attach_args))
    goto done;
  app_index = attach_args.app_index;
  app = application_get (app_index);
  app_wrk = application_get_worker (app, 0);
  wrk = session_main_get_worker (transport_cl_thread ());
  mq = session_main_get_vpp_event_queue (transport_cl_thread ());
  if (!app_wrk || !wrk || !mq)
    goto detach;
  if (!SESSION_TEST_I (application_lookup (api_index) == app,
		       "control messages resolve the attached application"))
    goto detach;

  session_test_cancel_connect_notifications = 0;
  session_test_cancel_connect_context = ~0;
  session_test_connect_completions = 0;
  session_test_connect_context = ~0;
  pending_connects = wrk->n_pending_connects;
  rx_mqs_segment = application_get_rx_mqs_segment (app);
  ext_config_chunk = fifo_segment_alloc_chunk_w_slice (
    rx_mqs_segment, 0, sizeof (transport_endpt_ext_cfg_t));
  if (!ext_config_chunk)
    goto detach;
  ext_config_chunk_size = ext_config_chunk->length;
  ext_config_free_chunks = fifo_segment_num_free_chunks (rx_mqs_segment, ext_config_chunk_size);
  ((transport_endpt_ext_cfg_t *) ext_config_chunk->data)->len = 0;
  ext_config = fifo_segment_chunk_offset (rx_mqs_segment, ext_config_chunk);

  session_test_send_connect_event (mq, SESSION_CTRL_EVT_CONNECT, api_index,
				   pending_context, ext_config);
  session_test_send_connect_event (mq, SESSION_CTRL_EVT_CANCEL_CONNECT, api_index,
				   pending_context, 0);
  if (!SESSION_TEST_I (session_wrk_handle_mq (wrk, mq) == 2,
		       "control MQ copies CONNECT and CANCEL"))
    goto detach;
  session_wrk_dispatch_ctrl_events (wrk);
  session_wrk_handle_evts_main_rpc (
    uword_to_pointer ((uword) transport_cl_thread (), void *));
  if (!SESSION_TEST_I (wrk->n_pending_connects == pending_connects,
		       "main RPC makes CONNECT pending then CANCEL removes it (%u != %u)",
		       wrk->n_pending_connects, pending_connects) ||
      !SESSION_TEST_I (fifo_segment_num_free_chunks (rx_mqs_segment, ext_config_chunk_size) ==
			       ext_config_free_chunks + 1,
		       "canceled deferred CONNECT returns ext-config ownership"))
    goto detach;
  app_wrk_flush_wrk_events (app_wrk, 0);
  if (!SESSION_TEST_I (session_test_cancel_connect_notifications == 1 &&
		       session_test_cancel_connect_context == pending_context,
		       "deferred cancellation emits one terminal completion"))
    goto detach;
  vlib_worker_thread_barrier_sync (vm);
  session_test_send_connect_event (mq, SESSION_CTRL_EVT_CANCEL_CONNECT, api_index,
				   pending_context, 0);
  session_wrk_handle_mq (wrk, mq);
  session_wrk_dispatch_ctrl_events (wrk);
  vlib_worker_thread_barrier_release (vm);
  app_wrk_flush_wrk_events (app_wrk, 0);
  if (!SESSION_TEST_I (session_test_cancel_connect_notifications == 1,
		       "duplicate cancellation cannot emit another completion"))
    goto detach;

  intf_addr[0].as_u32 = clib_host_to_net_u32 (0x0a000001);
  intf_addr[1].as_u32 = clib_host_to_net_u32 (0x0a000002);
  if (session_create_lookpback (0, &sw_if_index[0], &intf_addr[0]) ||
      session_create_lookpback (1, &sw_if_index[1], &intf_addr[1]))
    goto detach;
  session_add_del_route_via_lookup_in_table (0, 1, &intf_addr[1], 32, 1);
  session_add_del_route_via_lookup_in_table (1, 0, &intf_addr[0], 32, 1);

  connect_args.sep.is_ip4 = 1;
  connect_args.sep.ip.ip4 = intf_addr[1];
  connect_args.sep.port = 43210;
  connect_args.sep.peer.is_ip4 = 1;
  connect_args.sep.peer.ip.ip4 = intf_addr[0];
  connect_args.sep.peer.port = 43211;
  connect_args.sep.transport_proto = TRANSPORT_PROTO_TCP;
  connect_args.api_context = half_open_context;
  connect_args.app_index = app_index;
  if (vnet_connect (&connect_args) || pool_elts (app_wrk->half_open_table) != 1)
    goto routes;
  pool_foreach (sh, app_wrk->half_open_table)
    break;
  if (!sh)
    goto routes;
  ho = session_get_from_handle (*sh);
  if (!SESSION_TEST_I (ho->session_state == SESSION_STATE_CONNECTING,
		       "TCP active open remains cancellable before SYN-ACK") ||
      !SESSION_TEST_I (1, "CONNECT has a real SYN-SENT half-open"))
    goto routes;
  session_test_send_connect_event (mq, SESSION_CTRL_EVT_CANCEL_CONNECT, api_index,
				   half_open_context, 0);
  if (!SESSION_TEST_I (session_wrk_handle_mq (wrk, mq) == 1,
		       "half-open CANCEL is copied through control MQ"))
    goto routes;
  session_wrk_dispatch_ctrl_events (wrk);
  if (!SESSION_TEST_I (!pool_elts (app_wrk->half_open_table),
		       "control-MQ cancellation cleans the SYN-SENT half-open"))
    goto routes;
  app_wrk_flush_wrk_events (app_wrk, 0);
  if (!SESSION_TEST_I (session_test_cancel_connect_notifications == 2 &&
		       session_test_cancel_connect_context == half_open_context,
		       "half-open cancellation emits one completion") ||
      !SESSION_TEST_I (session_test_connect_completions == 0,
		       "cancellation has not committed a successful connection"))
    goto routes;

  connect_args.api_context = successful_context;
  if (vnet_connect (&connect_args) || pool_elts (app_wrk->half_open_table) != 1)
    goto routes;
  pool_foreach (sh, app_wrk->half_open_table)
    break;
  if (!sh)
    goto routes;
  clib_memset (complete_args, 0, sizeof (*complete_args));
  complete_args->half_open = *sh;
  complete_args->app_wrk = app_wrk;
  /* The half-open belongs to the transport control worker.  Hold the worker
   * barrier while selecting that worker's VPP TLS context so this invokes the
   * real completion function against its owner pools without a concurrent
   * packet-path transition. */
  vlib_worker_thread_barrier_sync (vm);
  os_set_thread_index (transport_cl_thread ());
  session_test_complete_connect_on_worker (complete_args);
  os_set_thread_index (0);
  vlib_worker_thread_barrier_release (vm);
  if (!SESSION_TEST_I (complete_args->done && !complete_args->rv,
		       "owning worker completes the real session_stream_connect_notify path") ||
      !SESSION_TEST_I (session_test_connect_completions == 1 &&
		       session_test_connect_context == successful_context,
		       "ordinary successful completion is delivered exactly once"))
    goto routes;

  vlib_worker_thread_barrier_sync (vm);
  session_test_send_connect_event (mq, SESSION_CTRL_EVT_CANCEL_CONNECT, api_index,
				   successful_context, 0);
  session_wrk_handle_mq (wrk, mq);
  session_wrk_dispatch_ctrl_events (wrk);
  vlib_worker_thread_barrier_release (vm);
  if (!SESSION_TEST_I (session_test_connect_completions == 1 &&
		       session_test_cancel_connect_notifications == 2,
		       "late CANCEL cannot duplicate a successful completion or terminal cleanup"))
    goto routes;

  vcl_mq_shared = svm_msg_q_alloc (&vcl_mq_cfg);
  if (!vcl_mq_shared)
    goto routes;
  svm_msg_q_attach (&vcl_mq, vcl_mq_shared);
  if (!SESSION_TEST_I (!vcl_test_preclosed_connect_error (),
		       "pre-closed VCL session retires on canceled CONNECTED completion") ||
      !SESSION_TEST_I (!vcl_test_preclosed_connected (&vcl_mq, api_index,
					      complete_args->connected),
		       "late VCL CONNECTED takes the establishment-won terminate fallback"))
    goto routes;
  if (svm_msg_q_sub (&vcl_mq, &vcl_msg, SVM_Q_NOWAIT, 0))
    goto routes;
  vcl_evt = svm_msg_q_msg_data (&vcl_mq, &vcl_msg);
  vcl_terminate = (session_terminate_msg_t *) vcl_evt->data;
  if (!SESSION_TEST_I (vcl_evt->event_type == SESSION_CTRL_EVT_TERMINATE &&
		       vcl_terminate->client_index == api_index &&
		       vcl_terminate->handle == complete_args->connected,
		       "VCL queues exactly one TERMINATE fallback for the established session") ||
      !SESSION_TEST_I (!svm_msg_q_size (&vcl_mq),
		       "late VCL CONNECTED leaves no duplicate terminate event"))
    {
      svm_msg_q_free_msg (&vcl_mq, &vcl_msg);
      goto routes;
    }
  svm_msg_q_free_msg (&vcl_mq, &vcl_msg);

  complete_args->done = 0;
  vlib_worker_thread_barrier_sync (vm);
  os_set_thread_index (transport_cl_thread ());
  session_test_cleanup_connect_on_worker (complete_args);
  os_set_thread_index (0);
  vlib_worker_thread_barrier_release (vm);
  if (!SESSION_TEST_I (complete_args->done,
		       "owning worker reclaims the establishment-won test connection"))
    goto routes;

  rv = 0;
routes:
  if (vcl_mq_shared)
    {
      svm_msg_q_cleanup (&vcl_mq);
      clib_mem_free (vcl_mq_shared);
    }
  session_add_del_route_via_lookup_in_table (0, 1, &intf_addr[1], 32, 0);
  session_add_del_route_via_lookup_in_table (1, 0, &intf_addr[0], 32, 0);
  session_delete_loopback (sw_if_index[0]);
  session_delete_loopback (sw_if_index[1]);
detach:
  detach_args = (vnet_app_detach_args_t){ .app_index = app_index, .api_client_index = ~0 };
  if (app_index != APP_INVALID_INDEX)
    vnet_application_detach (&detach_args);
done:
  if (api_index != ~0 && vl_api_client_index_to_registration (api_index))
    {
      vl_api_memclnt_delete_t *delete = vl_msg_api_alloc_or_null (sizeof (*delete));
      if (!delete)
	{
	  rv = -1;
	  goto queue_cleanup;
	}
      *delete = (vl_api_memclnt_delete_t){ .index = api_index };
      vl_api_memclnt_delete_t_handler (delete);
      if (svm_queue_sub (api_queue, (u8 *) &delete_reply, SVM_Q_NOWAIT, 0))
	rv = -1;
      else
	{
	  VL_MSG_API_UNPOISON (delete_reply);
	  vl_msg_api_free (delete_reply);
	}
    }
queue_cleanup:
  if (api_queue)
    svm_queue_free (api_queue);
  return rv;
}

static int
session_test_basic (vlib_main_t * vm, unformat_input_t * input)
{
  session_endpoint_cfg_t server_sep = SESSION_ENDPOINT_CFG_NULL;
  u64 options[APP_OPTIONS_N_OPTIONS], bind4_handle, bind6_handle;
  u32 server_index;
  int error = 0;

  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "session_test"),
  };

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "app attached");
  server_index = attach_args.app_index;
  vec_free (attach_args.name);

  server_sep.is_ip4 = 1;
  vnet_listen_args_t bind_args = {
    .sep_ext = server_sep,
    .app_index = 0,
    .wrk_map_index = 0,
  };

  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "server bind4 should work");
  bind4_handle = bind_args.handle;

  error = vnet_listen (&bind_args);
  SESSION_TEST ((error != 0), "double server bind4 should not work");

  bind_args.sep.is_ip4 = 0;
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "server bind6 should work");
  bind6_handle = bind_args.handle;

  error = vnet_listen (&bind_args);
  SESSION_TEST ((error != 0), "double server bind6 should not work");

  vnet_unlisten_args_t unbind_args = {
    .handle = bind4_handle,
    .app_index = server_index,
  };
  error = vnet_unlisten (&unbind_args);
  SESSION_TEST ((error == 0), "unbind4 should work");

  unbind_args.handle = bind6_handle;
  error = vnet_unlisten (&unbind_args);
  SESSION_TEST ((error == 0), "unbind6 should work");

  vnet_app_detach_args_t detach_args = {
    .app_index = server_index,
    .api_client_index = ~0,
  };
  vnet_application_detach (&detach_args);
  return 0;
}

static int
session_test_endpoint_cfg (vlib_main_t * vm, unformat_input_t * input)
{
  session_endpoint_cfg_t client_sep = SESSION_ENDPOINT_CFG_NULL;
  u32 server_index, client_index, sw_if_index[2], tries = 0;
  u64 options[APP_OPTIONS_N_OPTIONS], placeholder_secret = 1234;
  u16 placeholder_server_port = 1234, placeholder_client_port = 5678;
  session_endpoint_cfg_t server_sep = SESSION_ENDPOINT_CFG_NULL;
  u32 client_vrf = 0, server_vrf = 1;
  ip4_address_t intf_addr[3];
  transport_connection_t *tc;
  session_lookup_connection4_result_t lookup_result;
  session_t *s;
  u8 *appns_id;
  int error;

  /*
   * Create the loopbacks
   */
  intf_addr[0].as_u32 = clib_host_to_net_u32 (0x01010101);
  session_create_lookpback (client_vrf, &sw_if_index[0], &intf_addr[0]);

  intf_addr[1].as_u32 = clib_host_to_net_u32 (0x02020202);
  session_create_lookpback (server_vrf, &sw_if_index[1], &intf_addr[1]);

  session_add_del_route_via_lookup_in_table (
    client_vrf, server_vrf, &intf_addr[1], 32, 1 /* is_add */);
  session_add_del_route_via_lookup_in_table (
    server_vrf, client_vrf, &intf_addr[0], 32, 1 /* is_add */);

  /*
   * Insert namespace
   */
  appns_id = format (0, "appns_server");
  vnet_app_namespace_add_del_args_t ns_args = {
    .ns_id = appns_id,
    .secret = placeholder_secret,
    .sw_if_index = sw_if_index[1], /* server interface*/
    .ip4_fib_id = 0,		   /* sw_if_index takes precedence */
    .is_add = 1
  };
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %d", error);

  /*
   * Attach client/server
   */
  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "session_test_client"),
  };

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "client app attached");
  client_index = attach_args.app_index;
  vec_free (attach_args.name);

  attach_args.name = format (0, "session_test_server");
  attach_args.namespace_id = appns_id;
  /* Allow server to allocate another segment for listens. Needed
   * because by default we do not allow segment additions */
  attach_args.options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 32 << 20;
  attach_args.options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server app attached: %U", format_clib_error,
		error);
  vec_free (attach_args.name);
  server_index = attach_args.app_index;

  server_sep.is_ip4 = 1;
  server_sep.port = placeholder_server_port;
  vnet_listen_args_t bind_args = {
    .sep_ext = server_sep,
    .app_index = server_index,
  };
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "server bind should work");

  /*
   * Connect and force lcl ip
   */
  client_sep.is_ip4 = 1;
  client_sep.ip.ip4.as_u32 = intf_addr[1].as_u32;
  client_sep.port = placeholder_server_port;
  client_sep.peer.is_ip4 = 1;
  client_sep.peer.ip.ip4.as_u32 = intf_addr[0].as_u32;
  client_sep.peer.port = placeholder_client_port;
  client_sep.transport_proto = TRANSPORT_PROTO_TCP;

  vnet_connect_args_t connect_args = {
    .sep_ext = client_sep,
    .app_index = client_index,
  };

  connected_session_index = connected_session_thread = ~0;
  accepted_session_index = accepted_session_thread = ~0;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error == 0), "connect should work");

  /* wait for stuff to happen */
  while (connected_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  while (accepted_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

  clib_warning ("waited %.1f seconds for connections", tries / 10.0);
  SESSION_TEST ((connected_session_index != ~0), "session should exist");
  SESSION_TEST ((connected_session_thread != ~0), "thread should exist");
  SESSION_TEST ((accepted_session_index != ~0), "session should exist");
  SESSION_TEST ((accepted_session_thread != ~0), "thread should exist");
  s = session_get (connected_session_index, connected_session_thread);
  tc = session_get_transport (s);
  SESSION_TEST ((tc != 0), "transport should exist");
  SESSION_TEST ((memcmp (&tc->lcl_ip, &client_sep.peer.ip,
			 sizeof (tc->lcl_ip)) == 0), "ips should be equal");
  SESSION_TEST ((tc->lcl_port == placeholder_client_port),
		"ports should be equal");
  error = session_lookup_connection4_result (
    0, &tc->lcl_ip.ip4, &tc->rmt_ip.ip4, tc->lcl_port, tc->rmt_port,
    tc->proto, &lookup_result);
  SESSION_TEST ((error == 0 &&
		 lookup_result.type == SESSION_LOOKUP_CONNECTION_TYPE_ESTABLISHED &&
		 lookup_result.session_handle == session_handle (s) &&
		 lookup_result.connection_index == ~0 &&
		 lookup_result.thread_index == tc->thread_index &&
		 lookup_result.transport_proto == tc->proto),
		"scalar lookup should return established identity");
  SESSION_TEST ((session_lookup_connection4_result_validate_owner (&lookup_result) == 0 &&
		 lookup_result.connection_index == tc->c_index),
		"owner validation should return established transport identity");

  /* Disconnect server session, should lead to faster port cleanup on client */
  vnet_disconnect_args_t disconnect_args = {
    .handle =
      session_make_handle (accepted_session_index, accepted_session_thread),
    .app_index = server_index,
  };

  error = vnet_disconnect_session (&disconnect_args);
  SESSION_TEST ((error == 0), "disconnect should work");

  /* wait for stuff to happen */
  tries = 0;
  while (connected_session_index != ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

  /* Active closes take longer to cleanup, don't wait */

  clib_warning ("waited %.1f seconds for disconnect", tries / 10.0);
  SESSION_TEST ((connected_session_index == ~0), "session should not exist");
  SESSION_TEST ((connected_session_thread == ~0), "thread should not exist");
  SESSION_TEST ((app_session_error == 0), "no app session errors");

  vnet_unlisten_args_t unbind_args = {
    .handle = bind_args.handle,
    .app_index = server_index,
  };
  error = vnet_unlisten (&unbind_args);

  /* Listen session consumes local port, so unbind before checking port usage */
  SESSION_TEST ((error == 0), "server unbind should work: %U", format_session_error, error);
  SESSION_TEST (transport_port_local_in_use () == 0, "port should be cleaned up");

  /* Start cleanup by detaching apps */
  vnet_app_detach_args_t detach_args = {
    .app_index = server_index,
    .api_client_index = ~0,
  };
  vnet_application_detach (&detach_args);
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  ns_args.is_add = 0;
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns delete should succeed: %d", error);

  /* Allow the disconnects to finish before removing the routes. */
  vlib_process_suspend (vm, 10e-3);

  session_add_del_route_via_lookup_in_table (
    client_vrf, server_vrf, &intf_addr[1], 32, 0 /* is_add */);
  session_add_del_route_via_lookup_in_table (
    server_vrf, client_vrf, &intf_addr[0], 32, 0 /* is_add */);

  session_delete_loopback (sw_if_index[0]);
  session_delete_loopback (sw_if_index[1]);

  /*
   * Redo the test but with client in the non-default namespace
   */

  /* Create the loopbacks */
  client_vrf = 1;
  server_vrf = 0;
  session_create_lookpback (client_vrf, &sw_if_index[0], &intf_addr[0]);
  session_create_lookpback (server_vrf, &sw_if_index[1], &intf_addr[1]);

  session_add_del_route_via_lookup_in_table (
    client_vrf, server_vrf, &intf_addr[1], 32, 1 /* is_add */);
  session_add_del_route_via_lookup_in_table (
    server_vrf, client_vrf, &intf_addr[0], 32, 1 /* is_add */);

  /* Insert new client namespace */
  vec_free (appns_id);
  appns_id = format (0, "appns_client");
  ns_args.ns_id = appns_id;
  ns_args.sw_if_index = sw_if_index[0]; /* client interface*/
  ns_args.is_add = 1;

  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %U",
		format_session_error, error);

  /* Attach client */
  attach_args.name = format (0, "session_test_client");
  attach_args.namespace_id = appns_id;
  attach_args.options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 0;
  attach_args.options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret;
  attach_args.api_client_index = ~0;

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "client app attached: %U", format_session_error,
		error);
  client_index = attach_args.app_index;
  vec_free (attach_args.name);

  /* Attach server */
  attach_args.name = format (0, "session_test_server");
  attach_args.namespace_id = 0;
  attach_args.options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 32 << 20;
  attach_args.options[APP_OPTIONS_NAMESPACE_SECRET] = 0;
  attach_args.api_client_index = ~0;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server app attached: %U", format_session_error,
		error);
  vec_free (attach_args.name);
  server_index = attach_args.app_index;

  /* Bind server */
  clib_memset (&server_sep, 0, sizeof (server_sep));
  server_sep.is_ip4 = 1;
  server_sep.port = placeholder_server_port;
  bind_args.sep_ext = server_sep;
  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "server bind should work: %U",
		format_session_error, error);

  /* Connect client */
  connected_session_index = connected_session_thread = ~0;
  accepted_session_index = accepted_session_thread = ~0;
  clib_memset (&client_sep, 0, sizeof (client_sep));
  client_sep.is_ip4 = 1;
  client_sep.ip.ip4.as_u32 = intf_addr[1].as_u32;
  client_sep.port = placeholder_server_port;
  client_sep.peer.is_ip4 = 1;
  client_sep.peer.ip.ip4.as_u32 = intf_addr[0].as_u32;
  client_sep.peer.port = placeholder_client_port;
  client_sep.transport_proto = TRANSPORT_PROTO_TCP;

  connect_args.sep_ext = client_sep;
  connect_args.app_index = client_index;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error == 0), "connect should work");

  /* wait for stuff to happen */
  while (connected_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  while (accepted_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

  clib_warning ("waited %.1f seconds for connections", tries / 10.0);
  SESSION_TEST ((connected_session_index != ~0), "session should exist");
  SESSION_TEST ((connected_session_thread != ~0), "thread should exist");
  SESSION_TEST ((accepted_session_index != ~0), "session should exist");
  SESSION_TEST ((accepted_session_thread != ~0), "thread should exist");
  s = session_get (connected_session_index, connected_session_thread);
  tc = session_get_transport (s);
  SESSION_TEST ((tc != 0), "transport should exist");
  SESSION_TEST (
    (memcmp (&tc->lcl_ip, &client_sep.peer.ip, sizeof (tc->lcl_ip)) == 0),
    "ips should be equal");
  SESSION_TEST ((tc->lcl_port == placeholder_client_port),
		"ports should be equal");

  /* Disconnect server session, for faster port cleanup on client */
  disconnect_args.app_index = server_index;
  disconnect_args.handle =
    session_make_handle (accepted_session_index, accepted_session_thread);

  error = vnet_disconnect_session (&disconnect_args);
  SESSION_TEST ((error == 0), "disconnect should work");

  /* wait for stuff to happen */
  tries = 0;
  while (connected_session_index != ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

  /* Active closes take longer to cleanup, don't wait */

  clib_warning ("waited %.1f seconds for disconnect", tries / 10.0);
  SESSION_TEST ((connected_session_index == ~0), "session should not exist");
  SESSION_TEST ((connected_session_thread == ~0), "thread should not exist");
  SESSION_TEST ((app_session_error == 0), "no app session errors");
  SESSION_TEST (transport_port_local_in_use () == 0,
		"port should be cleaned up");

  /* Start cleanup by detaching apps */
  detach_args.app_index = server_index;
  vnet_application_detach (&detach_args);
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  ns_args.is_add = 0;
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns delete should succeed: %d", error);

  /* Allow the disconnects to finish before removing the routes. */
  vlib_process_suspend (vm, 10e-3);

  session_add_del_route_via_lookup_in_table (
    client_vrf, server_vrf, &intf_addr[1], 32, 0 /* is_add */);
  session_add_del_route_via_lookup_in_table (
    server_vrf, client_vrf, &intf_addr[0], 32, 0 /* is_add */);

  session_delete_loopback (sw_if_index[0]);
  session_delete_loopback (sw_if_index[1]);

  return 0;
}

static int
session_test_namespace (vlib_main_t * vm, unformat_input_t * input)
{
  u64 options[APP_OPTIONS_N_OPTIONS], placeholder_secret = 1234, tries;
  u32 server_index, server_st_index, server_local_st_index;
  u32 placeholder_port = 1234, client_index, server_wrk_index;
  u32 placeholder_api_context = 4321, placeholder_client_api_index = ~0;
  u32 placeholder_server_api_index = ~0, sw_if_index = 0;
  session_endpoint_t server_sep = SESSION_ENDPOINT_NULL;
  session_endpoint_t client_sep = SESSION_ENDPOINT_NULL;
  session_endpoint_t intf_sep = SESSION_ENDPOINT_NULL;
  u8 *ns_id, *server_name, *client_name;
  app_namespace_t *app_ns;
  application_t *server;
  session_t *s;
  u64 handle;
  int error = 0;

  /* Make sure segment count and accept are reset before starting test
   * in case tests are ran multiple times */
  placeholder_segment_count = 0;
  placeholder_accept = 0;

  ns_id = format (0, "appns1");
  server_name = format (0, "session_test");
  client_name = format (0, "session_test_client");

  server_sep.is_ip4 = 1;
  server_sep.port = placeholder_port;
  client_sep.is_ip4 = 1;
  client_sep.port = placeholder_port;
  clib_memset (options, 0, sizeof (options));

  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = server_name,
  };

  vnet_listen_args_t bind_args = {
    .sep = server_sep,
    .app_index = 0,
  };

  vnet_connect_args_t connect_args = {
    .app_index = 0,
    .api_context = 0,
  };
  clib_memcpy (&connect_args.sep, &client_sep, sizeof (client_sep));

  vnet_unlisten_args_t unbind_args = {
    .handle = bind_args.handle,
    .app_index = 0,
  };

  vnet_app_detach_args_t detach_args = {
    .app_index = 0,
    .api_client_index = ~0,
  };

  ip4_address_t intf_addr = {
    .as_u32 = clib_host_to_net_u32 (0x07000105),
  };

  intf_sep.ip.ip4 = intf_addr;
  intf_sep.is_ip4 = 1;
  intf_sep.port = placeholder_port;

  /*
   * Insert namespace and lookup
   */

  vnet_app_namespace_add_del_args_t ns_args = {
    .ns_id = ns_id,
    .secret = placeholder_secret,
    .sw_if_index = APP_NAMESPACE_INVALID_INDEX,
    .is_add = 1
  };
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %d", error);

  app_ns = app_namespace_get_from_id (ns_id);
  SESSION_TEST ((app_ns != 0), "should find ns %v status", ns_id);
  SESSION_TEST ((app_ns->ns_secret == placeholder_secret),
		"secret should be %d", placeholder_secret);
  SESSION_TEST ((app_ns->sw_if_index == APP_NAMESPACE_INVALID_INDEX),
		"sw_if_index should be invalid");

  /*
   * Try application attach with wrong secret
   */

  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret - 1;
  attach_args.namespace_id = ns_id;
  attach_args.api_client_index = placeholder_server_api_index;

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error != 0), "app attachment should fail");
  SESSION_TEST ((error == SESSION_E_WRONG_NS_SECRET),
		"code should be wrong ns secret: %d", error);

  /*
   * Attach server with global default scope
   */
  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_NAMESPACE_SECRET] = 0;
  attach_args.namespace_id = 0;
  attach_args.api_client_index = placeholder_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attachment should work");
  server_index = attach_args.app_index;
  server = application_get (server_index);
  server_wrk_index = application_get_default_worker (server)->wrk_index;
  SESSION_TEST ((server->ns_index == 0),
		"server should be in the default ns");

  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "server bind should work");

  server_st_index = application_session_table (server, FIB_PROTOCOL_IP4);
  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s != 0), "listener should exist in global table");
  SESSION_TEST ((s->app_wrk_index == server_wrk_index), "app_index should be"
		" that of the server");
  server_local_st_index = application_local_session_table (server);
  SESSION_TEST ((server_local_st_index == APP_INVALID_INDEX),
		"server shouldn't have access to local table");

  unbind_args.app_index = server_index;
  unbind_args.handle = bind_args.handle;
  error = vnet_unlisten (&unbind_args);
  SESSION_TEST ((error == 0), "unbind should work");

  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s == 0), "listener should not exist in global table");

  detach_args.app_index = server_index;
  vnet_application_detach (&detach_args);

  /*
   * Attach server with local and global scope
   */
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret;
  attach_args.namespace_id = ns_id;
  attach_args.api_client_index = placeholder_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attachment should work");
  server_index = attach_args.app_index;
  server = application_get (server_index);
  server_wrk_index = application_get_default_worker (server)->wrk_index;
  SESSION_TEST ((server->ns_index == app_namespace_index (app_ns)),
		"server should be in the right ns");

  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "bind should work");
  server_st_index = application_session_table (server, FIB_PROTOCOL_IP4);
  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s != 0), "listener should exist in global table");
  SESSION_TEST ((s->app_wrk_index == server_wrk_index), "app_index should be"
		" that of the server");
  server_local_st_index = application_local_session_table (server);
  handle = session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((handle != SESSION_INVALID_HANDLE),
		"listener should exist in local table");

  /*
   * Try client connect with 1) local scope 2) global scope
   */
  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  attach_args.name = client_name;
  attach_args.api_client_index = placeholder_client_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "client attachment should work");
  client_index = attach_args.app_index;
  connect_args.api_context = placeholder_api_context;
  connect_args.app_index = client_index;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "client connect should return error code");
  SESSION_TEST ((error == SESSION_E_INVALID_RMT_IP),
		"error code should be invalid value (zero ip)");
  SESSION_TEST ((placeholder_segment_count == 0),
		"shouldn't have received request to map new segment");
  connect_args.sep.ip.ip4.as_u8[0] = 127;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error == 0), "client connect should not return error code");

  /* wait for accept */
  tries = 0;
  while (!placeholder_accept && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

  SESSION_TEST ((placeholder_segment_count == 1),
		"should've received request to map new segment");
  SESSION_TEST ((placeholder_accept == 1),
		"should've received accept request");
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  attach_args.api_client_index = placeholder_client_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "client attachment should work");
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "client connect should return error code");
  SESSION_TEST ((error == SESSION_E_NOINTF),
		"error code should be connect (nothing in local scope)");
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  /*
   * Unbind and detach server and then re-attach with local scope only
   */
  unbind_args.handle = bind_args.handle;
  unbind_args.app_index = server_index;
  error = vnet_unlisten (&unbind_args);
  SESSION_TEST ((error == 0), "unbind should work");

  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s == 0), "listener should not exist in global table");
  handle = session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((handle == SESSION_INVALID_HANDLE),
		"listener should not exist in local table");

  detach_args.app_index = server_index;
  vnet_application_detach (&detach_args);

  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  attach_args.api_client_index = placeholder_server_api_index;
  attach_args.name = server_name;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "app attachment should work");
  server_index = attach_args.app_index;
  server = application_get (server_index);
  SESSION_TEST ((server->ns_index == app_namespace_index (app_ns)),
		"app should be in the right ns");

  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "bind should work");

  server_st_index = application_session_table (server, FIB_PROTOCOL_IP4);
  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s == 0), "listener should not exist in global table");
  server_local_st_index = application_local_session_table (server);
  handle = session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((handle != SESSION_INVALID_HANDLE),
		"listener should exist in local table");

  unbind_args.handle = bind_args.handle;
  error = vnet_unlisten (&unbind_args);
  SESSION_TEST ((error == 0), "unbind should work");

  handle = session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((handle == SESSION_INVALID_HANDLE),
		"listener should not exist in local table");

  /*
   * Client attach + connect in default ns with local scope
   */
  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  attach_args.namespace_id = 0;
  attach_args.api_client_index = placeholder_client_api_index;
  attach_args.name = client_name;
  vnet_application_attach (&attach_args);
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "client connect should return error code");
  SESSION_TEST ((error == SESSION_E_NOROUTE),
		"error code should be noroute (not in same ns)");
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  /*
   * Detach server
   */
  detach_args.app_index = server_index;
  vnet_application_detach (&detach_args);

  /*
   * Create loopback interface
   */
  session_create_lookpback (0, &sw_if_index, &intf_addr);

  /*
   * Update namespace with interface
   */
  ns_args.sw_if_index = sw_if_index;
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %d", error);

  /*
   * Attach server with local and global scope
   */
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret;
  attach_args.namespace_id = ns_id;
  attach_args.api_client_index = placeholder_server_api_index;
  attach_args.name = server_name;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attachment should work");
  server_index = attach_args.app_index;
  server = application_get (server_index);
  server_wrk_index = application_get_default_worker (server)->wrk_index;

  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
  server_st_index = application_session_table (server, FIB_PROTOCOL_IP4);
  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s == 0), "zero listener should not exist in global table");

  s = session_lookup_listener (server_st_index, &intf_sep);
  SESSION_TEST ((s != 0), "intf listener should exist in global table");
  SESSION_TEST ((s->app_wrk_index == server_wrk_index), "app_index should be "
		"that of the server");
  server_local_st_index = application_local_session_table (server);
  handle = session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((handle != SESSION_INVALID_HANDLE),
		"zero listener should exist in local table");
  detach_args.app_index = server_index;
  vnet_application_detach (&detach_args);

  ns_args.is_add = 0;
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns delete should succeed: %d", error);

  /*
   * Cleanup
   */
  vec_free (server_name);
  vec_free (client_name);
  vec_free (ns_id);
  session_delete_loopback (sw_if_index);
  return 0;
}

static void
session_test_disable_rt_backend_engine (vlib_main_t *vm)
{
  session_enable_disable_args_t args = { .is_en = 0,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_DISABLE };
  vnet_session_enable_disable (vm, &args);
}

static void
session_test_enable_rule_table_engine (vlib_main_t *vm)
{
  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vnet_session_enable_disable (vm, &args);
}

static void
session_test_enable_sdl_engine (vlib_main_t *vm)
{
  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_SDL };
  vnet_session_enable_disable (vm, &args);
}

static int
session_test_rule_table (vlib_main_t * vm, unformat_input_t * input)
{
  session_table_t *st = session_table_alloc ();
  u16 lcl_port = 1234, rmt_port = 4321;
  u32 action_index = 1, res;
  ip4_address_t lcl_lkup, rmt_lkup;
  int verbose = 0, error;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  session_test_disable_rt_backend_engine (vm);
  session_test_enable_rule_table_engine (vm);

  session_table_init (st, FIB_PROTOCOL_MAX);
  vec_add1 (st->appns_index,
	    app_namespace_index (app_namespace_get_default ()));
  session_rules_table_init (st, FIB_PROTOCOL_MAX);

  ip4_address_t lcl_ip = {
    .as_u32 = clib_host_to_net_u32 (0x01020304),
  };
  ip4_address_t rmt_ip = {
    .as_u32 = clib_host_to_net_u32 (0x05060708),
  };
  ip4_address_t lcl_ip2 = {
    .as_u32 = clib_host_to_net_u32 (0x02020202),
  };
  ip4_address_t rmt_ip2 = {
    .as_u32 = clib_host_to_net_u32 (0x06060606),
  };
  ip4_address_t lcl_ip3 = {
    .as_u32 = clib_host_to_net_u32 (0x03030303),
  };
  ip4_address_t rmt_ip3 = {
    .as_u32 = clib_host_to_net_u32 (0x07070707),
  };
  fib_prefix_t lcl_pref = {
    .fp_addr.ip4.as_u32 = lcl_ip.as_u32,
    .fp_len = 16,
    .fp_proto = FIB_PROTOCOL_IP4,
  };
  fib_prefix_t rmt_pref = {
    .fp_addr.ip4.as_u32 = rmt_ip.as_u32,
    .fp_len = 16,
    .fp_proto = FIB_PROTOCOL_IP4,
  };

  session_rule_table_add_del_args_t args = {
    .lcl = lcl_pref,
    .rmt = rmt_pref,
    .lcl_port = lcl_port,
    .rmt_port = rmt_port,
    .action_index = action_index++,
    .is_add = 1,
  };
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/16 1234 5.6.7.8/16 4321 action %d",
		action_index - 1);

  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 1),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should " "be 1: %d",
		res);

  /*
   * Add 1.2.3.4/24 1234 5.6.7.8/16 4321 and 1.2.3.4/24 1234 5.6.7.8/24 4321
   */
  args.lcl.fp_addr.ip4 = lcl_ip;
  args.lcl.fp_len = 24;
  args.action_index = action_index++;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/24 1234 5.6.7.8/16 4321 action %d",
		action_index - 1);
  args.rmt.fp_addr.ip4 = rmt_ip;
  args.rmt.fp_len = 24;
  args.action_index = action_index++;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/24 1234 5.6.7.8/24 4321 action %d",
		action_index - 1);

  /*
   * Add 2.2.2.2/24 1234 6.6.6.6/16 4321 and 3.3.3.3/24 1234 7.7.7.7/16 4321
   */
  args.lcl.fp_addr.ip4 = lcl_ip2;
  args.lcl.fp_len = 24;
  args.rmt.fp_addr.ip4 = rmt_ip2;
  args.rmt.fp_len = 16;
  args.action_index = action_index++;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 2.2.2.2/24 1234 6.6.6.6/16 4321 action %d",
		action_index - 1);
  args.lcl.fp_addr.ip4 = lcl_ip3;
  args.rmt.fp_addr.ip4 = rmt_ip3;
  args.action_index = action_index++;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 3.3.3.3/24 1234 7.7.7.7/16 4321 action %d",
		action_index - 1);

  /*
   * Add again 3.3.3.3/24 1234 7.7.7.7/16 4321
   */
  args.lcl.fp_addr.ip4 = lcl_ip3;
  args.rmt.fp_addr.ip4 = rmt_ip3;
  args.action_index = action_index++;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "overwrite 3.3.3.3/24 1234 7.7.7.7/16 4321 "
		"action %d", action_index - 1);

  /*
   * Lookup 1.2.3.4/32 1234 5.6.7.8/32 4321, 1.2.2.4/32 1234 5.6.7.9/32 4321
   * and  3.3.3.3 1234 7.7.7.7 4321
   */
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 3),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321 action " "should be 3: %d",
		res);

  lcl_lkup.as_u32 = clib_host_to_net_u32 (0x01020204);
  rmt_lkup.as_u32 = clib_host_to_net_u32 (0x05060709);
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_lkup, &rmt_lkup, lcl_port, rmt_port);
  SESSION_TEST ((res == 1),
		"Lookup 1.2.2.4 1234 5.6.7.9 4321, action " "should be 1: %d",
		res);

  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip3, &rmt_ip3, lcl_port, rmt_port);
  SESSION_TEST ((res == 6),
		"Lookup 3.3.3.3 1234 7.7.7.7 4321, action "
		"should be 6 (updated): %d", res);

  /*
   * Add 1.2.3.4/24 * 5.6.7.8/24 *
   * Lookup 1.2.3.4 1234 5.6.7.8 4321 and 1.2.3.4 1235 5.6.7.8 4321
   */
  args.lcl.fp_addr.ip4 = lcl_ip;
  args.rmt.fp_addr.ip4 = rmt_ip;
  args.lcl.fp_len = 24;
  args.rmt.fp_len = 24;
  args.lcl_port = 0;
  args.rmt_port = 0;
  args.action_index = action_index++;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/24 * 5.6.7.8/24 * action %d",
		action_index - 1);
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 7),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should"
		" be 7 (lpm dst): %d", res);
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port + 1, rmt_port);
  SESSION_TEST ((res == 7),
		"Lookup 1.2.3.4 1235 5.6.7.8 4321, action should " "be 7: %d",
		res);

  /*
   * Del 1.2.3.4/24 * 5.6.7.8/24 *
   * Add 1.2.3.4/16 * 5.6.7.8/16 * and 1.2.3.4/24 1235 5.6.7.8/24 4321
   * Lookup 1.2.3.4 1234 5.6.7.8 4321, 1.2.3.4 1235 5.6.7.8 4321 and
   * 1.2.3.4 1235 5.6.7.8 4322
   */
  args.is_add = 0;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/24 * 5.6.7.8/24 *");

  args.lcl.fp_addr.ip4 = lcl_ip;
  args.rmt.fp_addr.ip4 = rmt_ip;
  args.lcl.fp_len = 16;
  args.rmt.fp_len = 16;
  args.lcl_port = 0;
  args.rmt_port = 0;
  args.action_index = action_index++;
  args.is_add = 1;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/16 * 5.6.7.8/16 * action %d",
		action_index - 1);

  args.lcl.fp_addr.ip4 = lcl_ip;
  args.rmt.fp_addr.ip4 = rmt_ip;
  args.lcl.fp_len = 24;
  args.rmt.fp_len = 24;
  args.lcl_port = lcl_port + 1;
  args.rmt_port = rmt_port;
  args.action_index = action_index++;
  args.is_add = 1;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/24 1235 5.6.7.8/24 4321 action %d",
		action_index - 1);

  if (verbose)
    session_rules_table_cli_dump (vm, st->srtg_handle, TRANSPORT_PROTO_TCP,
				  FIB_PROTOCOL_IP4);

  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 3),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should " "be 3: %d",
		res);
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port + 1, rmt_port);
  SESSION_TEST ((res == 9),
		"Lookup 1.2.3.4 1235 5.6.7.8 4321, action should " "be 9: %d",
		res);
  res =
    session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP, &lcl_ip,
				 &rmt_ip, lcl_port + 1, rmt_port + 1);
  SESSION_TEST ((res == 8),
		"Lookup 1.2.3.4 1235 5.6.7.8 4322, action should " "be 8: %d",
		res);

  /*
   * Delete 1.2.0.0/16 1234 5.6.0.0/16 4321 and 1.2.0.0/16 * 5.6.0.0/16 *
   * Lookup 1.2.3.4 1234 5.6.7.8 4321
   */
  args.lcl_port = 1234;
  args.rmt_port = 4321;
  args.lcl.fp_len = 16;
  args.rmt.fp_len = 16;
  args.is_add = 0;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Del 1.2.0.0/16 1234 5.6.0.0/16 4321");
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 3),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should " "be 3: %d",
		res);

  args.lcl_port = 0;
  args.rmt_port = 0;
  args.is_add = 0;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Del 1.2.0.0/16 * 5.6.0.0/16 *");
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 3),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should " "be 3: %d",
		res);

  /*
   * Delete 1.2.3.4/24 1234 5.6.7.5/24
   */
  args.lcl.fp_addr.ip4 = lcl_ip;
  args.rmt.fp_addr.ip4 = rmt_ip;
  args.lcl.fp_len = 24;
  args.rmt.fp_len = 24;
  args.lcl_port = 1234;
  args.rmt_port = 4321;
  args.is_add = 0;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/24 1234 5.6.7.5/24");
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 2), "Action should be 2: %d", res);

  session_table_free (st, FIB_PROTOCOL_MAX);

  return 0;
}

static int
session_test_rules (vlib_main_t * vm, unformat_input_t * input)
{
  session_endpoint_t server_sep = SESSION_ENDPOINT_NULL;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u16 lcl_port = 1234, rmt_port = 4321;
  u32 server_index, server_index2;
  u32 placeholder_server_api_index = ~0;
  transport_connection_t *tc;
  session_lookup_connection4_result_t lookup_result;
  u32 placeholder_port = 1111;
  u8 is_filtered = 0, *ns_id = format (0, "appns1");
  session_t *listener, *s;
  app_namespace_t *default_ns = app_namespace_get_default ();
  u32 local_ns_index = default_ns->local_table_index;
  int verbose = 0;
  app_namespace_t *app_ns;
  app_listener_t *al;
  int error = 0;
  u64 handle;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  session_test_disable_rt_backend_engine (vm);
  session_test_enable_rule_table_engine (vm);

  server_sep.is_ip4 = 1;
  server_sep.port = placeholder_port;
  clib_memset (options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "session_test"),
  };

  vnet_listen_args_t bind_args = {
    .sep = server_sep,
    .app_index = 0,
  };

  /*
   * Attach server with global and local default scope
   */
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  attach_args.namespace_id = 0;
  attach_args.api_client_index = placeholder_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attached");
  server_index = attach_args.app_index;

  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "server bound to %U/%d", format_ip46_address,
		&server_sep.ip, 1, server_sep.port);
  al = app_listener_get_w_handle (bind_args.handle);
  listener = app_listener_get_session (al);
  ip4_address_t lcl_ip = {
    .as_u32 = clib_host_to_net_u32 (0x01020304),
  };
  ip4_address_t rmt_ip = {
    .as_u32 = clib_host_to_net_u32 (0x05060708),
  };
  fib_prefix_t lcl_pref = {
    .fp_addr.ip4.as_u32 = lcl_ip.as_u32,
    .fp_len = 16,
    .fp_proto = FIB_PROTOCOL_IP4,
  };
  fib_prefix_t rmt_pref = {
    .fp_addr.ip4.as_u32 = rmt_ip.as_u32,
    .fp_len = 16,
    .fp_proto = FIB_PROTOCOL_IP4,
  };

  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc == 0), "optimized lookup should not work (port)");

  /*
   * Add 1.2.3.4/16 1234 5.6.7.8/16 4321 action server_index
   */
  session_rule_add_del_args_t args = {
    .table_args.lcl = lcl_pref,
    .table_args.rmt = rmt_pref,
    .table_args.lcl_port = lcl_port,
    .table_args.rmt_port = rmt_port,
    .table_args.action_index = server_index,
    .table_args.is_add = 1,
    .appns_index = 0,
  };
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/16 1234 5.6.7.8/16 4321 action %d",
		args.table_args.action_index);

  tc = session_lookup_connection4 (0, &lcl_pref.fp_addr.ip4, &rmt_pref.fp_addr.ip4, lcl_port,
				   rmt_port, TRANSPORT_PROTO_TCP);
  SESSION_TEST ((tc->c_index == listener->connection_index),
		"optimized lookup should return the listener");
  error =
    session_lookup_connection4_result (0, &lcl_pref.fp_addr.ip4, &rmt_pref.fp_addr.ip4, lcl_port,
				       rmt_port, TRANSPORT_PROTO_TCP, &lookup_result);
  SESSION_TEST ((error != 0 && lookup_result.type == SESSION_LOOKUP_CONNECTION_TYPE_NONE &&
		 lookup_result.session_handle == SESSION_INVALID_HANDLE &&
		 lookup_result.connection_index == ~0 &&
		 lookup_result.thread_index == CLIB_INVALID_THREAD_INDEX),
		"scalar lookup should not follow a rule action to a listener");
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4, &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0, &is_filtered);
  SESSION_TEST ((tc->c_index == listener->connection_index), "lookup should return the listener");
  s = session_lookup_safe4 (0, &lcl_pref.fp_addr.ip4, &rmt_pref.fp_addr.ip4, lcl_port, rmt_port,
			    TRANSPORT_PROTO_TCP);
  SESSION_TEST ((s->connection_index == listener->connection_index),
		"safe lookup should return the listener");
  session_endpoint_t sep = {
    .ip = rmt_pref.fp_addr,
    .is_ip4 = 1,
    .port = rmt_port,
    .transport_proto = TRANSPORT_PROTO_TCP,
  };
  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle != server_index), "local session endpoint lookup "
					  "should not work (global scope)");

  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4, &rmt_pref.fp_addr.ip4, lcl_port + 1,
				      rmt_port, TRANSPORT_PROTO_TCP, 0, &is_filtered);
  SESSION_TEST ((tc == 0), "optimized lookup for wrong lcl port + 1 should not work");
  lookup_result.session_handle = 0;
  lookup_result.connection_index = 0;
  lookup_result.thread_index = 0;
  lookup_result.transport_proto = ~0;
  lookup_result.type = SESSION_LOOKUP_CONNECTION_TYPE_ESTABLISHED;
  error =
    session_lookup_connection4_result (0, &lcl_pref.fp_addr.ip4, &rmt_pref.fp_addr.ip4,
				       lcl_port + 1, rmt_port, TRANSPORT_PROTO_TCP, &lookup_result);
  SESSION_TEST ((error != 0 && lookup_result.type == SESSION_LOOKUP_CONNECTION_TYPE_NONE &&
		 lookup_result.session_handle == SESSION_INVALID_HANDLE &&
		 lookup_result.connection_index == ~0 &&
		 lookup_result.thread_index == CLIB_INVALID_THREAD_INDEX &&
		 lookup_result.transport_proto == TRANSPORT_PROTO_NONE),
		"failed scalar lookup should invalidate a prior identity");

  /*
   * Add 1.2.3.4/16 * 5.6.7.8/16 4321
   */
  args.table_args.lcl_port = 0;
  args.scope = SESSION_RULE_SCOPE_LOCAL | SESSION_RULE_SCOPE_GLOBAL;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/16 * 5.6.7.8/16 4321 action %d",
		args.table_args.action_index);
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port + 1,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc->c_index == listener->connection_index),
		"optimized lookup for lcl port + 1 should work");
  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == server_index), "local session endpoint lookup "
		"should work (lcl ip was zeroed)");

  /*
   * Add deny rule 1.2.3.4/32 1234 5.6.7.8/32 4321 action -2 (drop)
   */
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 30;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 30;
  args.table_args.action_index = SESSION_RULES_TABLE_ACTION_DROP;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/30 1234 5.6.7.8/30 4321 action %d",
		args.table_args.action_index);

  if (verbose)
    {
      session_lookup_dump_rules_table (0, FIB_PROTOCOL_IP4,
				       TRANSPORT_PROTO_TCP);
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }

  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc == 0), "lookup for 1.2.3.4/32 1234 5.6.7.8/16 4321 "
		"should fail (deny rule)");
  SESSION_TEST ((is_filtered == SESSION_LOOKUP_RESULT_FILTERED),
		"lookup should be filtered (deny)");

  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_DROP_HANDLE), "lookup for 1.2.3.4/32 1234 "
		"5.6.7.8/16 4321 in local table should return deny");

  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port + 1,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc->c_index == listener->connection_index),
		"lookup 1.2.3.4/32 123*5* 5.6.7.8/16 4321 should work");

  /*
   * "Mask" deny rule with more specific allow:
   * Add allow rule 1.2.3.4/32 1234 5.6.7.8/32 4321 action -3 (allow)
   */
  args.table_args.is_add = 1;
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 32;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 32;
  args.table_args.action_index = SESSION_RULES_TABLE_ACTION_ALLOW;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add masking rule 1.2.3.4/30 1234 5.6.7.8/32 "
		"4321 action %d", args.table_args.action_index);

  is_filtered = 0;
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc == 0), "lookup for 1.2.3.4/32 1234 5.6.7.8/16 4321 "
		"should fail (allow without app)");
  SESSION_TEST ((is_filtered == 0), "lookup should NOT be filtered");

  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_INVALID_HANDLE), "lookup for 1.2.3.4/32 "
		"1234 5.6.7.8/32 4321 in local table should return invalid");

  if (verbose)
    {
      vlib_cli_output (vm, "Local rules");
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }

  sep.ip.ip4.as_u32 += 1 << 24;
  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_DROP_HANDLE), "lookup for 1.2.3.4/32 1234"
		" 5.6.7.9/32 4321 in local table should return deny");

  vnet_connect_args_t connect_args = {
    .app_index = attach_args.app_index,
    .api_context = 0,
  };
  clib_memcpy (&connect_args.sep, &sep, sizeof (sep));

  /* Try connecting */
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "connect should fail");
  SESSION_TEST ((error == SESSION_E_FILTERED), "connect should be filtered");

  sep.ip.ip4.as_u32 -= 1 << 24;

  /*
   * Delete masking rule: 1.2.3.4/32 1234 5.6.7.8/32 4321 allow
   */
  args.table_args.is_add = 0;
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 32;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 32;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/32 1234 5.6.7.8/32 4321 allow");


  /*
   * Add local scope rule for 0/0 * 5.6.7.8/16 4321 action server_index
   */
  args.table_args.is_add = 1;
  args.table_args.lcl_port = 0;
  args.table_args.lcl.fp_len = 0;
  args.table_args.rmt.fp_len = 16;
  args.table_args.action_index = -1;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add * * 5.6.7.8/16 4321 action %d",
		args.table_args.action_index);

  if (verbose)
    {
      session_lookup_dump_rules_table (0, FIB_PROTOCOL_IP4,
				       TRANSPORT_PROTO_TCP);
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }

  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_DROP_HANDLE),
		"local session endpoint lookup should return deny");

  /*
   * Delete 1.2.3.4/32 1234 5.6.7.8/32 4321 deny
   */
  args.table_args.is_add = 0;
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 30;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 30;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/32 1234 5.6.7.8/32 4321 deny");

  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_INVALID_HANDLE),
		"local session endpoint lookup should return invalid");

  /*
   * Delete 0/0 * 5.6.7.8/16 4321, 1.2.3.4/16 * 5.6.7.8/16 4321 and
   * 1.2.3.4/16 1234 5.6.7.8/16 4321
   */
  args.table_args.is_add = 0;
  args.table_args.lcl_port = 0;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 0;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 16;
  args.table_args.rmt_port = 4321;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Del 0/0 * 5.6.7.8/16 4321");
  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle != server_index), "local session endpoint lookup "
		"should not work (removed)");

  args.table_args.is_add = 0;
  args.table_args.lcl = lcl_pref;

  args.table_args.is_add = 0;
  args.table_args.lcl_port = 0;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 16;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 16;
  args.table_args.rmt_port = 4321;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/16 * 5.6.7.8/16 4321");
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port + 1,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc == 0),
		"lookup 1.2.3.4/32 123*5* 5.6.7.8/16 4321 should not "
		"work (del)");

  args.table_args.is_add = 0;
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 16;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 16;
  args.table_args.rmt_port = 4321;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/16 1234 5.6.7.8/16 4321");
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc == 0), "lookup 1.2.3.4/32 1234 5.6.7.8/16 4321 should "
		"not work (del + deny)");

  SESSION_TEST ((error == 0), "Del 1.2.3.4/32 1234 5.6.7.8/32 4321 deny");
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc == 0), "lookup 1.2.3.4/32 1234 5.6.7.8/16 4321 should"
		" not work (no-rule)");

  /*
   * Test tags. Add/overwrite/del rule with tag
   */
  args.table_args.is_add = 1;
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 16;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 16;
  args.table_args.rmt_port = 4321;
  args.table_args.tag = format (0, "test_rule");
  args.table_args.action_index = server_index;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/16 1234 5.6.7.8/16 4321 deny "
		"tag test_rule");
  if (verbose)
    {
      session_lookup_dump_rules_table (0, FIB_PROTOCOL_IP4,
				       TRANSPORT_PROTO_TCP);
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc->c_index == listener->connection_index),
		"lookup 1.2.3.4/32 1234 5.6.7.8/16 4321 should work");

  vec_free (args.table_args.tag);
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 16;
  args.table_args.tag = format (0, "test_rule_overwrite");
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0),
		"Overwrite 1.2.3.4/16 1234 5.6.7.8/16 4321 deny tag test_rule"
		" should work");
  if (verbose)
    {
      session_lookup_dump_rules_table (0, FIB_PROTOCOL_IP4,
				       TRANSPORT_PROTO_TCP);
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }

  args.table_args.is_add = 0;
  args.table_args.lcl_port += 1;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/32 1234 5.6.7.8/32 4321 deny "
		"tag %v", args.table_args.tag);
  if (verbose)
    {
      session_lookup_dump_rules_table (0, FIB_PROTOCOL_IP4,
				       TRANSPORT_PROTO_TCP);
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc == 0), "lookup 1.2.3.4/32 1234 5.6.7.8/32 4321 should not"
		" work (del)");


  /*
   * Test local rules with multiple namespaces
   */

  /*
   * Add deny rule 1.2.3.4/32 1234 5.6.7.8/32 0 action -2 (drop)
   */
  args.table_args.is_add = 1;
  args.table_args.lcl_port = 1234;
  args.table_args.rmt_port = 0;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 32;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 32;
  args.table_args.action_index = SESSION_RULES_TABLE_ACTION_DROP;
  args.table_args.tag = 0;
  args.scope = SESSION_RULE_SCOPE_LOCAL;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/32 1234 5.6.7.8/32 4321 action %d",
		args.table_args.action_index);
  /*
   * Add 'white' rule 1.2.3.4/32 1234 5.6.7.8/32 4321 action -2 (drop)
   */
  args.table_args.is_add = 1;
  args.table_args.lcl_port = 1234;
  args.table_args.rmt_port = 4321;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 32;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 32;
  args.table_args.action_index = SESSION_RULES_TABLE_ACTION_ALLOW;
  error = vnet_session_rule_add_del (&args);

  if (verbose)
    {
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }

  vnet_app_namespace_add_del_args_t ns_args = {
    .ns_id = ns_id,
    .secret = 0,
    .sw_if_index = APP_NAMESPACE_INVALID_INDEX,
    .is_add = 1
  };
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %d", error);
  app_ns = app_namespace_get_from_id (ns_id);

  attach_args.namespace_id = ns_id;
  attach_args.api_client_index = placeholder_server_api_index;
  vec_free (attach_args.name);
  attach_args.name = format (0, "server_test2");
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server2 attached");
  server_index2 = attach_args.app_index;

  /*
   * Add deny rule 1.2.3.4/32 1234 5.6.7.8/32 0 action -2 (drop)
   */
  args.table_args.lcl_port = 1234;
  args.table_args.rmt_port = 0;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 32;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 32;
  args.table_args.action_index = SESSION_RULES_TABLE_ACTION_DROP;
  args.appns_index = app_namespace_index (app_ns);

  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/32 1234 5.6.7.8/32 4321 action %d "
		"in test namespace", args.table_args.action_index);
  /*
   * Lookup default namespace
   */
  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_INVALID_HANDLE),
		"lookup for 1.2.3.4/32 1234 5.6.7.8/32 4321 in local table "
		"should return allow (invalid)");

  sep.port += 1;
  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_DROP_HANDLE), "lookup for 1.2.3.4/32 1234 "
		"5.6.7.8/16 432*2* in local table should return deny");


  connect_args.app_index = server_index;
  clib_memcpy (&connect_args.sep, &sep, sizeof (sep));

  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "connect should fail");
  SESSION_TEST ((error == SESSION_E_FILTERED), "connect should be filtered");

  /*
   * Lookup test namespace
   */
  handle = session_lookup_local_endpoint (app_ns->local_table_index, &sep);
  SESSION_TEST ((handle == SESSION_DROP_HANDLE), "lookup for 1.2.3.4/32 1234 "
		"5.6.7.8/16 4321 in local table should return deny");

  connect_args.app_index = server_index;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "connect should fail");
  SESSION_TEST ((error == SESSION_E_FILTERED), "connect should be filtered");

  args.table_args.is_add = 0;
  vnet_session_rule_add_del (&args);

  args.appns_index = 0;
  args.table_args.is_add = 0;
  vnet_session_rule_add_del (&args);

  args.table_args.rmt_port = 4321;
  vnet_session_rule_add_del (&args);
  /*
   * Final Cleanup
   */
  vec_free (args.table_args.tag);
  vnet_app_detach_args_t detach_args = {
    .app_index = server_index,
    .api_client_index = ~0,
  };
  vnet_application_detach (&detach_args);

  detach_args.app_index = server_index2;
  vnet_application_detach (&detach_args);

  ns_args.is_add = 0;
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns delete should succeed: %d", error);

  vec_free (ns_id);
  vec_free (attach_args.name);
  return 0;
}

static int
session_test_tuple_result (vlib_main_t *vm, unformat_input_t *input)
{
  clib_bihash_kv_16_8_t established = {};
  clib_bihash_kv_16_8_t half_open = {};
  session_lookup_connection4_result_t result;
  session_endpoint_t listener_sep = SESSION_ENDPOINT_NULL;
  clib_thread_index_t current_thread = vlib_get_thread_index ();
  clib_thread_index_t foreign_thread = current_thread ? 0 : 1;
  clib_thread_index_t half_open_thread = 7;
  ip4_address_t local = {
    .as_u32 = clib_host_to_net_u32 (0x0a000001),
  };
  ip4_address_t remote = {
    .as_u32 = clib_host_to_net_u32 (0x0a000002),
  };
  session_t *listener;
  session_t *foreign;
  session_t *stale;
  session_handle_t stale_handle;
  session_table_t *table;
  u32 table_index;
  u32 fib_index = 1024;
  u16 local_port = clib_host_to_net_u16 (1234);
  u16 remote_port = clib_host_to_net_u16 (4321);
  int rv;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return -1;

  table_index = session_lookup_get_or_alloc_index_for_fib (FIB_PROTOCOL_IP4, fib_index);
  table = session_table_get (table_index);
  SESSION_TEST ((table != 0), "tuple result test table should exist");

  vec_validate (session_main.wrk, foreign_thread);
  listener = session_alloc (current_thread);
  foreign = session_alloc (foreign_thread);
  listener->connection_index = 11;
  foreign->connection_index = ~0;
  foreign->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_TCP, 1);
  foreign->session_state = SESSION_STATE_READY;

  listener_sep.is_ip4 = 1;
  listener_sep.ip.ip4 = local;
  listener_sep.port = local_port;
  listener_sep.transport_proto = TRANSPORT_PROTO_TCP;
  rv = session_lookup_add_session_endpoint (table_index, &listener_sep, session_handle (listener));
  SESSION_TEST ((rv == 0), "tuple result listener should publish");

  established.key[0] = (u64) remote.as_u32 << 32 | local.as_u32;
  established.key[1] = (u64) TRANSPORT_PROTO_TCP << 32 | (u64) remote_port << 16 | local_port;
  established.value = session_handle (foreign);
  half_open = established;
  half_open.value = transport_connection_make_handle (22, half_open_thread);
  rv = clib_bihash_add_del_16_8 (&table->v4_session_hash, &established, 1);
  SESSION_TEST ((rv == 0), "foreign established tuple should publish");
  rv = clib_bihash_add_del_16_8 (&table->v4_half_open_hash, &half_open, 1);
  SESSION_TEST ((rv == 0), "half-open tuple should publish");

  rv = session_lookup_connection4_result (fib_index, &local, &remote, local_port, remote_port,
					  TRANSPORT_PROTO_TCP, &result);
  SESSION_TEST ((rv == 0 && result.type == SESSION_LOOKUP_CONNECTION_TYPE_ESTABLISHED &&
		 result.session_handle == session_handle (foreign) &&
		 result.connection_index == ~0 && result.thread_index == foreign_thread &&
		 result.transport_proto == TRANSPORT_PROTO_TCP),
		"foreign scalar lookup should not require a transport pointer");
  SESSION_TEST ((session_lookup_connection4_result_validate_owner (&result) != 0 &&
		 result.connection_index == ~0),
		"foreign scalar result should not access the owner session pool");

  rv = clib_bihash_add_del_16_8 (&table->v4_session_hash, &established, 0);
  SESSION_TEST ((rv == 0), "established tuple should unpublish");
  rv = session_lookup_connection4_result (fib_index, &local, &remote, local_port, remote_port,
					  TRANSPORT_PROTO_TCP, &result);
  SESSION_TEST ((rv == 0 && result.type == SESSION_LOOKUP_CONNECTION_TYPE_HALF_OPEN &&
		 result.session_handle == SESSION_INVALID_HANDLE && result.connection_index == 22 &&
		 result.thread_index == half_open_thread &&
		 result.transport_proto == TRANSPORT_PROTO_TCP),
		"half-open tuple should preserve its transport owner");

  rv = clib_bihash_add_del_16_8 (&table->v4_half_open_hash, &half_open, 0);
  SESSION_TEST ((rv == 0), "half-open tuple should unpublish");
  rv = session_lookup_connection4_result (fib_index, &local, &remote, local_port, remote_port,
					  TRANSPORT_PROTO_TCP, &result);
  SESSION_TEST ((rv == 0 && result.type == SESSION_LOOKUP_CONNECTION_TYPE_LISTENER &&
		 result.session_handle == session_handle (listener) &&
		 result.connection_index == ~0 && result.thread_index == current_thread),
		"lookup precedence should fall through to the listener");

  stale = session_alloc (current_thread);
  stale_handle = session_handle (stale);
  session_free (stale);
  established.value = stale_handle;
  rv = clib_bihash_add_del_16_8 (&table->v4_session_hash, &established, 1);
  SESSION_TEST ((rv == 0), "stale established tuple should publish");
  rv = session_lookup_connection4_result (fib_index, &local, &remote, local_port, remote_port,
					  TRANSPORT_PROTO_TCP, &result);
  SESSION_TEST ((rv == 0 && result.type == SESSION_LOOKUP_CONNECTION_TYPE_ESTABLISHED &&
		 result.session_handle == stale_handle && result.connection_index == ~0 &&
		 session_lookup_connection4_result_validate_owner (&result) != 0 &&
		 result.connection_index == ~0),
		"owner validation should reject a stale established identity");

  clib_bihash_add_del_16_8 (&table->v4_session_hash, &established, 0);
  session_lookup_del_session_endpoint (table_index, &listener_sep);
  session_free (foreign);
  session_free (listener);
  return 0;
}

static int
session_test_proxy (vlib_main_t * vm, unformat_input_t * input)
{
  u64 options[APP_OPTIONS_N_OPTIONS];
  char *show_listeners = "sh session listeners tcp verbose";
  char *show_local_listeners = "sh app ns table default";
  unformat_input_t tmp_input;
  u32 server_index, app_index;
  u32 placeholder_server_api_index = ~0, sw_if_index = 0;
  u8 is_filtered = 0;
  session_t *s;
  transport_connection_t *tc;
  u16 lcl_port = 1234, rmt_port = 4321;
  app_namespace_t *app_ns;
  int verbose = 0, error = 0;
  app_listener_t *al;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  ip4_address_t lcl_ip = {
    .as_u32 = clib_host_to_net_u32 (0x01020304),
  };
  ip4_address_t rmt_ip = {
    .as_u32 = clib_host_to_net_u32 (0x05060708),
  };
  fib_prefix_t rmt_pref = {
    .fp_addr.ip4.as_u32 = rmt_ip.as_u32,
    .fp_len = 16,
    .fp_proto = FIB_PROTOCOL_IP4,
  };
  session_endpoint_t sep = {
    .ip = rmt_pref.fp_addr,
    .is_ip4 = 1,
    .port = rmt_port,
    .transport_proto = TRANSPORT_PROTO_TCP,
  };

  /*
   * Create loopback interface
   */
  session_create_lookpback (0, &sw_if_index, &lcl_ip);

  app_ns = app_namespace_get_default ();
  app_ns->sw_if_index = sw_if_index;

  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_ACCEPT_REDIRECT;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_PROXY;
  options[APP_OPTIONS_PROXY_TRANSPORT] = 1 << TRANSPORT_PROTO_TCP;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "session_test"),
  };

  attach_args.api_client_index = placeholder_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attachment should work");
  server_index = attach_args.app_index;

  if (verbose)
    {
      unformat_init_string (&tmp_input, show_listeners,
			    strlen (show_listeners));
      vlib_cli_input (vm, &tmp_input, 0, 0);
      unformat_init_string (&tmp_input, show_local_listeners,
			    strlen (show_local_listeners));
      vlib_cli_input (vm, &tmp_input, 0, 0);
    }

  tc = session_lookup_connection_wt4 (0, &lcl_ip, &rmt_ip, lcl_port, rmt_port,
				      TRANSPORT_PROTO_TCP, 0, &is_filtered);
  SESSION_TEST ((tc != 0), "lookup 1.2.3.4 1234 5.6.7.8 4321 should be "
		"successful");
  s = listen_session_get (tc->s_index);
  al = app_listener_get (s->al_index);
  SESSION_TEST ((al->app_index == server_index), "lookup should return"
						 " the server");

  tc = session_lookup_connection_wt4 (0, &rmt_ip, &rmt_ip, lcl_port, rmt_port,
				      TRANSPORT_PROTO_TCP, 0, &is_filtered);
  SESSION_TEST ((tc == 0), "lookup 5.6.7.8 1234 5.6.7.8 4321 should"
		" not work");

  app_index = session_lookup_local_endpoint (app_ns->local_table_index, &sep);
  SESSION_TEST ((app_index == server_index), "local session endpoint lookup"
		" should work");

  vnet_app_detach_args_t detach_args = {
    .app_index = server_index,
    .api_client_index = ~0,
  };
  vnet_application_detach (&detach_args);

  if (verbose)
    {
      unformat_init_string (&tmp_input, show_listeners,
			    strlen (show_listeners));
      vlib_cli_input (vm, &tmp_input, 0, 0);
      unformat_init_string (&tmp_input, show_local_listeners,
			    strlen (show_local_listeners));
      vlib_cli_input (vm, &tmp_input, 0, 0);
    }

  app_index = session_lookup_local_endpoint (app_ns->local_table_index, &sep);
  SESSION_TEST ((app_index == SESSION_RULES_TABLE_INVALID_INDEX),
		"local session endpoint lookup should not work after detach");
  if (verbose)
    unformat_free (&tmp_input);
  vec_free (attach_args.name);
  session_delete_loopback (sw_if_index);

  /* Revert default appns sw_if_index */
  app_ns = app_namespace_get_default ();
  app_ns->sw_if_index = ~0;

  return 0;
}

static inline void
wait_for_event (svm_msg_q_t * mq, int fd, int epfd, u8 use_eventfd)
{
  if (!use_eventfd)
    {
      svm_msg_q_wait (mq, SVM_MQ_WAIT_EMPTY);
    }
  else
    {
      int __clib_unused n_read, rv;
      struct epoll_event ep_evt;
      u64 buf;

      while (1)
	{
	  rv = epoll_wait (epfd, &ep_evt, 1, -1);
	  if (rv < 0)
	    {
	      ST_DBG ("epoll error");
	      exit (1);
	    }
	  else if (rv > 0 && (ep_evt.events & EPOLLIN))
	    {
	      n_read = read (fd, &buf, sizeof (buf));
	    }
	  else
	    continue;

	  if (!svm_msg_q_is_empty (mq))
	    break;
	}
    }
}

/* Used to be part of application_worker.c prior to adding support for
 * async rx
 */
static int
test_mq_try_lock_and_alloc_msg (svm_msg_q_t *mq, session_mq_rings_e ring,
				svm_msg_q_msg_t *msg)
{
  int rv, n_try = 0;

  while (n_try < 75)
    {
      rv = svm_msg_q_lock_and_alloc_msg_w_ring (mq, ring, SVM_Q_NOWAIT, msg);
      if (!rv)
	return 0;
      /*
       * Break the loop if mq is full, usually this is because the
       * app has crashed or is hanging on somewhere.
       */
      if (rv != -1)
	break;
      n_try += 1;
      usleep (1);
    }

  return -1;
}

/* Used to be part of application_worker.c prior to adding support for
 * async rx and was used for delivering io events over mq
 * NB: removed handling of mq congestion
 */
static inline int
test_app_send_io_evt_rx (app_worker_t *app_wrk, session_t *s)
{
  svm_msg_q_msg_t _mq_msg = { 0 }, *mq_msg = &_mq_msg;
  session_event_t *evt;
  svm_msg_q_t *mq;
  u32 app_session;
  int rv;

  if (app_worker_application_is_builtin (app_wrk))
    return app_worker_rx_notify (app_wrk, s);

  if (svm_fifo_has_event (s->rx_fifo))
    return 0;

  app_session = s->rx_fifo->app_session_index;
  mq = app_wrk->event_queue;

  rv = test_mq_try_lock_and_alloc_msg (mq, SESSION_MQ_IO_EVT_RING, mq_msg);

  if (PREDICT_FALSE (rv))
    {
      clib_warning ("failed to alloc mq message");
      return -1;
    }

  evt = svm_msg_q_msg_data (mq, mq_msg);
  evt->event_type = SESSION_IO_EVT_RX;
  evt->session_index = app_session;

  (void) svm_fifo_set_event (s->rx_fifo);

  svm_msg_q_add_and_unlock (mq, mq_msg);

  return 0;
}

static int
session_test_mq_speed (vlib_main_t * vm, unformat_input_t * input)
{
  int error, __clib_unused verbose, use_eventfd = 0;
  u64 i, n_test_msgs = 1 << 10, *counter;
  u64 options[APP_OPTIONS_N_OPTIONS];
  int epfd = -1, rv, prod_fd = -1;
  svm_fifo_t *rx_fifo, *tx_fifo;
  vl_api_registration_t *reg;
  struct epoll_event ep_evt;
  u32 app_index, api_index;
  app_worker_t *app_wrk;
  segment_manager_t *sm;
  svm_msg_q_msg_t msg;
  application_t *app;
  svm_msg_q_t *mq;
  f64 start, diff;
  svm_queue_t *q;
  session_t s;
  pid_t pid;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "%d", &n_test_msgs))
	;
      else if (unformat (input, "use-eventfd"))
	use_eventfd = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  q = clib_mem_alloc (sizeof (*q));
  api_index = vl_api_memclnt_create_internal ("session_mq_test_api", q);

  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_EVT_QUEUE_SIZE] = 2048;

  reg = vl_api_client_index_to_registration (api_index);
  /* Shut up coverity */
  if (reg == 0)
    abort ();

  vnet_app_attach_args_t attach_args = {
    .api_client_index = api_index,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "session_mq_test"),
  };
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attachment should work");

  app_index = attach_args.app_index;

  app = application_get (app_index);
  app_wrk = application_get_worker (app, 0);
  mq = app_wrk->event_queue;
  if (use_eventfd)
    {
      svm_msg_q_alloc_eventfd (mq);
      prod_fd = svm_msg_q_get_eventfd (mq);
      SESSION_TEST (prod_fd != -1, "mq producer eventd valid %u", prod_fd);
    }

  sm = app_worker_get_connect_segment_manager (app_wrk);
  segment_manager_alloc_session_fifos (sm, 0, &rx_fifo, &tx_fifo);
  s.rx_fifo = rx_fifo;
  s.tx_fifo = tx_fifo;
  s.session_state = SESSION_STATE_READY;
  counter = (u64 *) f_head_cptr (rx_fifo)->data;
  start = vlib_time_now (vm);

  pid = fork ();
  if (pid < 0)
    SESSION_TEST (0, "fork failed");

  if (pid == 0)
    {
      if (use_eventfd)
	{
	  epfd = epoll_create1 (0);
	  SESSION_TEST (epfd != -1, "epfd created");
	  ep_evt.events = EPOLLIN;
	  ep_evt.data.u64 = prod_fd;
	  rv = epoll_ctl (epfd, EPOLL_CTL_ADD, prod_fd, &ep_evt);
	  SESSION_TEST (rv == 0, "epoll returned %d", rv);
	}

      for (i = 0; i < n_test_msgs; i++)
	{
	  wait_for_event (mq, prod_fd, epfd, use_eventfd);
	  svm_msg_q_sub_raw (mq, &msg);
	  svm_msg_q_free_msg (mq, &msg);
	  svm_msg_q_unlock (mq);
	  *counter = *counter + 1;
	  svm_fifo_unset_event (rx_fifo);
	}
      exit (0);
    }
  else
    {
      ST_DBG ("client pid %u", pid);
      for (i = 0; i < n_test_msgs; i++)
	{
	  while (svm_fifo_has_event (rx_fifo))
	    ;
	  test_app_send_io_evt_rx (app_wrk, &s);
	}
    }

  diff = vlib_time_now (vm) - start;
  ST_DBG ("done %u events in %.2f sec: %f evts/s", *counter,
	  diff, *counter / diff);

  vnet_app_detach_args_t detach_args = {
    .app_index = app_index,
    .api_client_index = ~0,
  };
  vnet_application_detach (&detach_args);
  return 0;
}

static int
session_test_mq_basic (vlib_main_t * vm, unformat_input_t * input)
{
  svm_msg_q_cfg_t _cfg, *cfg = &_cfg;
  svm_msg_q_msg_t msg1, msg2, msg[12];
  int __clib_unused verbose, i, rv;
  svm_msg_q_shared_t *smq;
  svm_msg_q_ring_t *ring;
  svm_msg_q_t _mq = { 0 }, *mq = &_mq;
  u8 *rings_ptr;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  svm_msg_q_ring_cfg_t rc[2] = { {8, 8, 0}
  , {8, 16, 0}
  };
  cfg->consumer_pid = ~0;
  cfg->n_rings = 2;
  cfg->q_nitems = 16;
  cfg->ring_cfgs = rc;

  smq = svm_msg_q_alloc (cfg);
  svm_msg_q_attach (mq, smq);
  SESSION_TEST (smq != 0, "svm_msg_q_alloc");
  SESSION_TEST (vec_len (mq->rings) == 2, "ring allocation");
  rings_ptr = (u8 *) mq->rings[0].shr->data;
  vec_foreach (ring, mq->rings)
  {
    SESSION_TEST (ring->shr->data == rings_ptr, "ring data");
    rings_ptr += (uword) ring->nitems * ring->elsize;
    rings_ptr += sizeof (svm_msg_q_ring_shared_t);
  }

  msg1 = svm_msg_q_alloc_msg (mq, 8);
  rv = (mq->rings[0].shr->cursize != 1 || msg1.ring_index != 0 ||
	msg1.elt_index != 0);
  SESSION_TEST (rv == 0, "msg alloc1");

  msg2 = svm_msg_q_alloc_msg (mq, 15);
  rv = (mq->rings[1].shr->cursize != 1 || msg2.ring_index != 1 ||
	msg2.elt_index != 0);
  SESSION_TEST (rv == 0, "msg alloc2");

  svm_msg_q_free_msg (mq, &msg1);
  SESSION_TEST (mq->rings[0].shr->cursize == 0, "free msg");

  for (i = 0; i < 12; i++)
    {
      msg[i] = svm_msg_q_alloc_msg (mq, 7);
      *(u32 *) svm_msg_q_msg_data (mq, &msg[i]) = i;
    }

  rv = (mq->rings[0].shr->cursize != 8 || mq->rings[1].shr->cursize != 5);
  SESSION_TEST (rv == 0, "msg alloc3");

  *(u32 *) svm_msg_q_msg_data (mq, &msg2) = 123;
  svm_msg_q_add (mq, &msg2, SVM_Q_NOWAIT);
  for (i = 0; i < 12; i++)
    svm_msg_q_add (mq, &msg[i], SVM_Q_NOWAIT);

  rv = svm_msg_q_sub (mq, &msg2, SVM_Q_NOWAIT, 0);
  SESSION_TEST (rv == 0, "dequeue1");

  SESSION_TEST (msg2.ring_index == 1 && msg2.elt_index == 0,
		"dequeue1 result");
  rv = (*(u32 *) svm_msg_q_msg_data (mq, &msg2) == 123);
  SESSION_TEST (rv, "dequeue 1 data");

  svm_msg_q_free_msg (mq, &msg2);

  for (i = 0; i < 12; i++)
    {
      if (svm_msg_q_sub (mq, &msg[i], SVM_Q_NOWAIT, 0))
	SESSION_TEST (0, "dequeue2");
      if (i < 8)
	{
	  if (msg[i].ring_index != 0 || msg[i].elt_index != (i + 1) % 8)
	    SESSION_TEST (0, "dequeue2 result2");
	}
      else
	{
	  if (msg[i].ring_index != 1 || msg[i].elt_index != (i - 8) + 1)
	    SESSION_TEST (0, "dequeue2 result3");
	}
      if (*(u32 *) svm_msg_q_msg_data (mq, &msg[i]) != i)
	SESSION_TEST (0, "dequeue2 wrong data");
      svm_msg_q_free_msg (mq, &msg[i]);
    }
  rv = (mq->rings[0].shr->cursize == 0 && mq->rings[1].shr->cursize == 0);
  SESSION_TEST (rv, "post dequeue");

  return 0;
}

static f32
session_get_memory_usage (void)
{
  clib_mem_heap_t *heap = clib_mem_get_heap ();
  u8 *s = 0;
  char *ss;
  f32 used = 0.0;

  s = format (s, "%U\n", format_clib_mem_heap, heap, 0);
  ss = strstr ((char *) s, "used:");
  if (ss)
    {
      if (sscanf (ss, "used: %f", &used) != 1)
	clib_warning ("invalid 'used' value");
    }
  else
    clib_warning ("substring 'used:' not found from show memory");
  vec_free (s);
  return (used);
}

static int
session_test_enable_disable (vlib_main_t *vm, unformat_input_t *input)
{
  u32 iteration = 100, i, n_sessions = 0;
  uword was_enabled;
  f32 was_using, now_using;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "repeat %d", &iteration))
	;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  for (int thread_index = 0; thread_index <= vlib_num_workers ();
       thread_index++)
    n_sessions += pool_elts (session_main.wrk[thread_index].sessions);

  was_enabled = clib_mem_trace_enable_disable (0);
  /* warm up */
  for (i = 0; i < 10; i++)
    {
      session_test_disable_rt_backend_engine (vm);
      session_test_enable_sdl_engine (vm);
      session_test_disable_rt_backend_engine (vm);
      session_test_enable_rule_table_engine (vm);
    }
  was_using = session_get_memory_usage ();

  for (i = 0; i < iteration; i++)
    {
      session_test_disable_rt_backend_engine (vm);
      session_test_enable_sdl_engine (vm);
      session_test_disable_rt_backend_engine (vm);
      session_test_enable_rule_table_engine (vm);
    }
  now_using = session_get_memory_usage ();

  clib_mem_trace_enable_disable (was_enabled);
  if (n_sessions)
    SESSION_TEST ((now_using < was_using + (1 << 15)),
		  "was using %.2fM, now using %.2fM", was_using, now_using);
  else
    SESSION_TEST ((was_using == now_using), "was using %.2fM, now using %.2fM",
		  was_using, now_using);

  return 0;
}

static int
session_test_sdl (vlib_main_t *vm, unformat_input_t *input)
{
  session_table_t *st = session_table_alloc ();
  u16 lcl_port = 0, rmt_port = 0;
  u32 action_index = 1, res;
  int verbose = 0, error;
  ip4_address_t rmt_ip;
  const char ip_str_1234[] = "1.2.3.4";
  inet_pton (AF_INET, ip_str_1234, &rmt_ip);
  ip4_address_t lcl_ip = {
    .as_u32 = clib_host_to_net_u32 (0x0),
  };
  ip6_address_t lcl_ip6 = {
    .as_u64 = { 0, 0 },
  };
  fib_prefix_t rmt_pref = {
    .fp_addr.ip4.as_u32 = rmt_ip.as_u32,
    .fp_len = 16,
    .fp_proto = FIB_PROTOCOL_IP4,
  };
  fib_prefix_t lcl_pref = {
    .fp_addr.ip4.as_u32 = lcl_ip.as_u32,
    .fp_len = 0,
    .fp_proto = 0,
  };
  session_rule_table_add_del_args_t args = {
    .lcl = lcl_pref,
    .rmt = rmt_pref,
    .lcl_port = lcl_port,
    .rmt_port = rmt_port,
    .action_index = action_index++,
    .is_add = 1,
  };
  const char ip_str_1200[] = "1.2.0.0";
  const char ip_str_1230[] = "1.2.3.0";
  const char ip_str_1111[] = "1.1.1.1";
  const char ip6_str[] = "2501:0db8:85a3:0000:0000:8a2e:0371:1";
  const char ip6_str2[] = "2501:0db8:85a3:0000:0000:8a2e:0372:1";
  u32 walk_count;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  session_test_disable_rt_backend_engine (vm);
  session_test_enable_sdl_engine (vm);

  session_table_init (st, FIB_PROTOCOL_MAX);
  vec_add1 (st->appns_index,
	    app_namespace_index (app_namespace_get_default ()));
  session_rules_table_init (st, FIB_PROTOCOL_MAX);

  /* Add 1.2.0.0/16 */
  args.rmt.fp_len = 16;
  inet_pton (AF_INET, ip_str_1200, &args.rmt.fp_addr.ip4.as_u32);
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add %s/%d action %d", ip_str_1200,
		args.rmt.fp_len, action_index - 1);

  /* Lookup 1.2.3.4 */
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == action_index - 1),
		"Lookup %s, action should "
		"be 1: %d",
		ip_str_1234, action_index - 1);

  /*
   * Add 1.2.3.0/24
   */
  args.rmt.fp_len = 24;
  inet_pton (AF_INET, ip_str_1230, &args.rmt.fp_addr.ip4.as_u32);
  args.action_index = action_index++;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add %s/%d action %d", ip_str_1230,
		args.rmt.fp_len, action_index - 1);

  /* Lookup 1.2.3.4 */
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == action_index - 1),
		"Lookup %s, action should "
		"be 2: %d",
		ip_str_1234, action_index - 1);

  /* look up 1.1.1.1, should be -1 (invalid index) */
  inet_pton (AF_INET, ip_str_1111, &rmt_ip);
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == SESSION_TABLE_INVALID_INDEX),
		"Lookup %s, action should "
		"be -1: %d",
		ip_str_1111, res);

  /* Add again 1.2.0.0/16, should be rejected */
  args.rmt.fp_len = 16;
  inet_pton (AF_INET, ip_str_1200, &args.rmt.fp_addr.ip4.as_u32);
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == SESSION_E_IPINUSE), "Add %s/%d action %d",
		ip_str_1200, args.rmt.fp_len, error);
  /*
   * Add 0.0.0.0/0, should get an error
   */
  args.rmt.fp_len = 0;
  args.rmt.fp_addr.ip4.as_u32 = 0;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == SESSION_E_IPINUSE), "Add 0.0.0.0/%d action %d",
		args.rmt.fp_len, error);

  /* delete 0.0.0.0 should be rejected */
  args.is_add = 0;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == SESSION_E_NOROUTE), "Del 0.0.0.0/%d action %d",
		args.rmt.fp_len, error);

  /*
   * Add an exact tagged rule and exercise SDL dump, show-one, walk and
   * duplicate-tag rejection paths.
   */
  args.is_add = 1;
  args.rmt.fp_len = 32;
  args.rmt.fp_proto = FIB_PROTOCOL_IP4;
  inet_pton (AF_INET, ip_str_1234, &args.rmt.fp_addr.ip4.as_u32);
  args.action_index = action_index++;
  args.tag = format (0, "sdl-exact-ip4");
  error = session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add %s/%d tag %v", ip_str_1234, args.rmt.fp_len, args.tag);

  walk_count = 0;
  session_sdl_table_walk4 (st->srtg_handle, session_test_sdl_walk_cb, &walk_count);
  SESSION_TEST ((walk_count >= 3), "SDL ip4 walk should find rules: %u", walk_count);

  ip46_address_t show_ip = { .ip4 = args.rmt.fp_addr.ip4 };
  session_rules_table_show_rule (vm, st->srtg_handle, TRANSPORT_PROTO_TCP, 0, 0, &show_ip, 0, 1);
  session_rules_table_cli_dump (vm, st->srtg_handle, TRANSPORT_PROTO_TCP, FIB_PROTOCOL_IP4);

  error = session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == SESSION_E_INVALID), "Add duplicate SDL tag should fail");

  args.is_add = 0;
  args.rmt.fp_len = 0;
  args.rmt.fp_addr.ip4.as_u32 = 0;
  error = session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Del SDL rule by tag %v", args.tag);
  vec_free (args.tag);
  args.tag = 0;
  if (verbose)
    session_rules_table_cli_dump (vm, st->srtg_handle, TRANSPORT_PROTO_TCP,
				  FIB_PROTOCOL_IP4);

  /*
   * Clean up
   * Delete 1.2.0.0/16
   * Delete 1.2.3.0/24
   */
  inet_pton (AF_INET, ip_str_1200, &args.rmt.fp_addr.ip4.as_u32);
  args.rmt.fp_len = 16;
  args.is_add = 0;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Del %s/%d should 0: %d", ip_str_1200,
		args.rmt.fp_len, error);

  inet_pton (AF_INET, ip_str_1230, &args.rmt.fp_addr.ip4.as_u32);
  args.rmt.fp_len = 24;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Del %s/%d, should be 0: %d", ip_str_1230,
		args.rmt.fp_len, error);
  if (verbose)
    session_rules_table_cli_dump (vm, st->srtg_handle, TRANSPORT_PROTO_TCP,
				  FIB_PROTOCOL_IP4);

  /* ip6 tests */

  /*
   * Add ip6 2001:0db8:85a3:0000:0000:8a2e:0371:1/124
   */
  ip6_address_t lcl_lkup;
  inet_pton (AF_INET6, ip6_str, &args.rmt.fp_addr.ip6);
  args.rmt.fp_len = 124;
  args.rmt.fp_proto = FIB_PROTOCOL_IP6;
  args.action_index = action_index++;
  args.is_add = 1;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add %s/%d action %d", ip6_str, args.rmt.fp_len,
		action_index - 1);
  if (verbose)
    session_rules_table_cli_dump (vm, st->srtg_handle, TRANSPORT_PROTO_TCP,
				  FIB_PROTOCOL_IP6);

  /* Lookup 2001:0db8:85a3:0000:0000:8a2e:0371:1 */
  res = session_rules_table_lookup6 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip6, &args.rmt.fp_addr.ip6, lcl_port,
				     rmt_port);
  SESSION_TEST ((res == action_index - 1),
		"Lookup %s action should "
		"be 3: %d",
		ip6_str, action_index - 1);

  walk_count = 0;
  session_sdl_table_walk6 (st->srtg_handle, session_test_sdl_walk_cb, &walk_count);
  SESSION_TEST ((walk_count >= 1), "SDL ip6 walk should find rules: %u", walk_count);

  show_ip.ip6 = args.rmt.fp_addr.ip6;
  session_rules_table_show_rule (vm, st->srtg_handle, TRANSPORT_PROTO_TCP, 0, 0, &show_ip, 0, 0);
  session_rules_table_cli_dump (vm, st->srtg_handle, TRANSPORT_PROTO_TCP, FIB_PROTOCOL_IP6);

  /* Lookup 2001:0db8:85a3:0000:0000:8a2e:0372:1 */
  inet_pton (AF_INET6, ip6_str2, &lcl_lkup);
  res = session_rules_table_lookup6 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip6, &lcl_lkup, lcl_port, rmt_port);
  SESSION_TEST ((res == SESSION_TABLE_INVALID_INDEX),
		"Lookup %s action should "
		"be -1: %d",
		ip6_str2, res);

  /*
   * del ip6 2001:0db8:85a3:0000:0000:8a2e:0371:1/124
   */
  args.is_add = 0;
  args.rmt.fp_len = 124;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "del %s/%d, should be 0: %d", ip6_str,
		args.rmt.fp_len, error);
  if (verbose)
    session_rules_table_cli_dump (vm, st->srtg_handle, TRANSPORT_PROTO_TCP,
				  FIB_PROTOCOL_IP6);

  session_table_free (st, FIB_PROTOCOL_MAX);

  return 0;
}

static int
session_test_ext_cfg (vlib_main_t *vm, unformat_input_t *input)
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  transport_endpt_ext_cfg_t *ext_cfg;

  ext_cfg = session_endpoint_add_ext_cfg (&sep, TRANSPORT_ENDPT_EXT_CFG_HTTP,
					  sizeof (ext_cfg->opaque));
  ext_cfg->opaque = 60;

  ext_cfg =
    session_endpoint_add_ext_cfg (&sep, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
				  sizeof (transport_endpt_crypto_cfg_t));
  ext_cfg->crypto.ckpair_index = 1;

  ext_cfg = session_endpoint_add_ext_cfg (&sep, TRANSPORT_ENDPT_EXT_CFG_NONE,
					  sizeof (ext_cfg->opaque));
  ext_cfg->opaque = 345;

  ext_cfg = session_endpoint_get_ext_cfg (&sep, TRANSPORT_ENDPT_EXT_CFG_HTTP);
  SESSION_TEST ((ext_cfg != 0),
		"TRANSPORT_ENDPT_EXT_CFG_HTTP should be present");
  SESSION_TEST ((ext_cfg->opaque == 60),
		"TRANSPORT_ENDPT_EXT_CFG_HTTP opaque value should be 60: %u",
		ext_cfg->opaque);
  ext_cfg =
    session_endpoint_get_ext_cfg (&sep, TRANSPORT_ENDPT_EXT_CFG_CRYPTO);
  SESSION_TEST ((ext_cfg != 0),
		"TRANSPORT_ENDPT_EXT_CFG_CRYPTO should be present");
  SESSION_TEST (
    (ext_cfg->crypto.ckpair_index == 1),
    "TRANSPORT_ENDPT_EXT_CFG_HTTP ckpair_index value should be 1: %u",
    ext_cfg->crypto.ckpair_index);
  ext_cfg = session_endpoint_get_ext_cfg (&sep, TRANSPORT_ENDPT_EXT_CFG_NONE);
  SESSION_TEST ((ext_cfg != 0),
		"TRANSPORT_ENDPT_EXT_CFG_NONE should be present");
  SESSION_TEST ((ext_cfg->opaque == 345),
		"TRANSPORT_ENDPT_EXT_CFG_HTTP opaque value should be 345: %u",
		ext_cfg->opaque);
  session_endpoint_free_ext_cfgs (&sep);

  return 0;
}

static int
session_test_app_crypto (vlib_main_t *vm, unformat_input_t *input)
{
  app_crypto_async_req_ticket_t ticket;
  app_crypto_ca_trust_int_ctx_t *cti;
  app_crypto_ca_trust_t *ca_trust;
  app_tls_profile_t *tls_profile;
  u64 options[APP_OPTIONS_N_OPTIONS];
  app_worker_t *app_wrk;
  application_t *app;
  u32 app_index, ck0, ck1;
  u8 cert0[] = "cert0";
  u8 cert1[] = "cert1";
  u8 key0[] = "key0";
  u8 key1[] = "key1";
  u8 *cmd;
  int error;

  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "session_test_app_crypto"),
  };

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "app crypto test app attached: %U", format_session_error, error);
  app_index = attach_args.app_index;
  vec_free (attach_args.name);

  app = application_get (app_index);
  app_wrk = application_get_worker (app, 0);
  SESSION_TEST ((app_wrk != 0), "app crypto test worker exists");

  session_test_cli_input (vm, "show session states");
  session_test_cli_input (vm, "show session protos");
  session_test_cli_input (vm, "show session transport");
  session_test_cli_input (vm, "show session rt-backend");
  session_test_cli_input (vm, "show session lookup");
  session_test_cli_input (vm, "show session lookup table 0");

  vnet_app_add_cert_key_pair_args_t ck_args = {
    .cert = cert0,
    .key = key0,
    .cert_len = sizeof (cert0),
    .key_len = sizeof (key0),
  };
  error = vnet_app_add_cert_key_pair (&ck_args);
  SESSION_TEST ((error == 0), "add cert/key pair 0");
  ck0 = ck_args.index;
  SESSION_TEST ((app_cert_key_pair_get_default () != 0), "default cert/key pair exists");

  ck_args.cert = cert1;
  ck_args.key = key1;
  ck_args.cert_len = sizeof (cert1);
  ck_args.key_len = sizeof (key1);
  error = vnet_app_add_cert_key_pair (&ck_args);
  SESSION_TEST ((error == 0), "add cert/key pair 1");
  ck1 = ck_args.index;

  session_test_cli_input (vm, "show app certificate");

  error = vnet_app_del_cert_key_pair (ck1);
  SESSION_TEST ((error == 0), "delete cert/key pair 1");
  SESSION_TEST ((app_cert_key_pair_get_if_valid (ck1) == 0), "deleted cert/key pair is invalid");
  error = vnet_app_del_cert_key_pair (ck1);
  SESSION_TEST ((error == SESSION_E_INVALID), "delete invalid cert/key pair should fail");
  if (ck0 != 0)
    {
      error = vnet_app_del_cert_key_pair (ck0);
      SESSION_TEST ((error == 0), "delete non-default cert/key pair 0");
    }

  app_ca_trust_add_args_t ca_args = {
    .ca_chain = format (0, "test-ca-chain"),
    .crl = format (0, "old-crl"),
  };
  error = app_crypto_add_ca_trust (app_index, &ca_args);
  SESSION_TEST ((error == 0), "add ca trust store");
  ca_trust = app_crypto_get_wrk_ca_trust (app_wrk->wrk_index, ca_args.index);
  SESSION_TEST ((ca_trust != 0), "get worker ca trust store");
  SESSION_TEST ((app_crypto_get_int_ca_trust (ca_trust, vlib_num_workers () + 1) == 0),
		"out-of-range ca trust internal context should be invalid");

  session_test_ca_update_count = 0;
  cti = app_crypto_alloc_int_ca_trust (ca_trust, vlib_get_thread_index ());
  cti->update_cb = session_test_ca_update_cb;

  app_ca_trust_update_crl_args_t crl_args = {
    .ca_trust_index = ca_args.index,
    .crl = format (0, "new-crl"),
  };
  error = app_crypto_update_ca_trust_crl (app_index, &crl_args);
  SESSION_TEST ((error == 0), "update ca trust crl");
  SESSION_TEST ((session_test_ca_update_count == 1 &&
		 session_test_ca_update_type == APP_CA_TRUST_UPDATE_TYPE_CRL),
		"ca trust crl update callback should run");

  crl_args.crl = format (0, "invalid-app-crl");
  error = app_crypto_update_ca_trust_crl (APP_INVALID_INDEX, &crl_args);
  SESSION_TEST ((error == SESSION_E_INVALID), "ca trust crl update with invalid app should fail");
  vec_free (crl_args.crl);

  crl_args.ca_trust_index = ~0;
  crl_args.crl = format (0, "invalid-index-crl");
  error = app_crypto_update_ca_trust_crl (app_index, &crl_args);
  SESSION_TEST ((error == SESSION_E_INVALID),
		"ca trust crl update with invalid trust index should fail");
  vec_free (crl_args.crl);

  app_tls_profile_add_args_t profile_args = {
    .cipher_list = format (0, "AES128-SHA"),
    .ciphersuites = format (0, "TLS_AES_128_GCM_SHA256"),
    .groups = format (0, "X25519"),
    .min_version = APP_TLS_VERSION_SSL3,
    .max_version = APP_TLS_VERSION_1_3,
  };
  error = app_crypto_add_tls_profile (app_index, &profile_args);
  SESSION_TEST ((error == 0), "add tls profile");
  tls_profile = app_crypto_get_tls_profile (app_wrk->wrk_index, profile_args.index);
  SESSION_TEST ((tls_profile != 0 && tls_profile->profile_index == profile_args.index),
		"get tls profile");
  app_crypto_del_tls_profile (app_index, profile_args.index + 1);

  cmd = format (0, "show app tls-profile app %u%c", app_index, 0);
  session_test_cli_input (vm, (char *) cmd);
  vec_free (cmd);

  cmd = format (0,
		"app crypto add tls-profile app %u min-version ssl3 "
		"max-version 1.1%c",
		app_index, 0);
  session_test_cli_input (vm, (char *) cmd);
  vec_free (cmd);

  cmd = format (0, "show app tls-profile app %u%c", app_index, 0);
  session_test_cli_input (vm, (char *) cmd);
  vec_free (cmd);

  session_test_crypto_async_count = 0;
  session_test_crypto_async_reply_count = 0;
  session_test_crypto_async_last_req = 0;
  app_crypto_async_req_t async_req = {
    .req_type = APP_CRYPTO_ASYNC_REQ_TYPE_CERT,
    .handle = { .opaque = 0xfeedface, .thread_index = vlib_get_thread_index () },
    .cb = session_test_crypto_async_reply_cb,
    .app_wrk_index = app_wrk->wrk_index,
  };

  ticket = app_crypto_async_req (&async_req);
  SESSION_TEST ((ticket.as_u64 == APP_CRYPTO_ASYNC_INVALID_TICKET.as_u64),
		"async crypto request without callback should fail");

  app->cb_fns.app_crypto_async = session_test_crypto_async_cb;
  ticket = app_crypto_async_req (&async_req);
  SESSION_TEST ((ticket.as_u64 != APP_CRYPTO_ASYNC_INVALID_TICKET.as_u64),
		"async crypto request should allocate ticket");
  SESSION_TEST ((session_test_crypto_async_count == 1 && session_test_crypto_async_last_req != 0),
		"async crypto callback should receive request");

  app_crypto_async_reply_t reply = {
    .app_index = app_index,
    .req_index = ticket.req_index,
    .handle = { .thread_index = vlib_get_thread_index () },
    .req_type = APP_CRYPTO_ASYNC_REQ_TYPE_CERT,
  };
  app_crypto_async_reply (&reply);
  SESSION_TEST ((session_test_crypto_async_reply_count == 1 &&
		 session_test_crypto_async_reply_handle.opaque == 0xfeedface),
		"async crypto reply callback should run");

  async_req.handle.opaque = 0xbaadf00d;
  ticket = app_crypto_async_req (&async_req);
  SESSION_TEST ((ticket.as_u64 != APP_CRYPTO_ASYNC_INVALID_TICKET.as_u64),
		"async crypto request to cancel should allocate ticket");
  app_crypto_async_cancel_req (ticket);
  reply.req_index = ticket.req_index;
  app_crypto_async_reply (&reply);
  SESSION_TEST ((session_test_crypto_async_reply_count == 1),
		"cancelled async crypto request should not call reply callback");
  app_crypto_async_cancel_req (ticket);

  vnet_app_detach_args_t detach_args = {
    .app_index = app_index,
    .api_client_index = ~0,
  };
  vnet_application_detach (&detach_args);
  SESSION_TEST ((session_test_ca_update_count == 2 &&
		 session_test_ca_update_type == APP_CA_TRUST_UPDATE_TYPE_DEL),
		"ca trust delete callback should run on detach");

  return 0;
}

static int
session_test_reconn_while_closed (vlib_main_t *vm, unformat_input_t *input)
{
  u64 options[APP_OPTIONS_N_OPTIONS], placeholder_secret = 1234;
  u32 server_index, client_index, sw_if_index[2], tries = 0;
  u16 placeholder_server_port = 1234, placeholder_client_port = 5678;
  session_endpoint_cfg_t server_sep = SESSION_ENDPOINT_CFG_NULL;
  session_endpoint_cfg_t client_sep = SESSION_ENDPOINT_CFG_NULL;
  u32 client_vrf = 0, server_vrf = 1;
  ip4_address_t intf_addr[2];
  u8 *appns_id;
  int error;

  ST_DBG ("session_test_reconn_while_closed");

  /* Reset global state */
  connected_session_index = connected_session_thread = ~0;
  accepted_session_index = accepted_session_thread = ~0;
  placeholder_accept = 0;
  app_session_error = 0;

  /* Create the loopbacks */
  intf_addr[0].as_u32 = clib_host_to_net_u32 (0x03030303);
  session_create_lookpback (client_vrf, &sw_if_index[0], &intf_addr[0]);
  intf_addr[1].as_u32 = clib_host_to_net_u32 (0x04040404);
  session_create_lookpback (server_vrf, &sw_if_index[1], &intf_addr[1]);
  session_add_del_route_via_lookup_in_table (
    client_vrf, server_vrf, &intf_addr[1], 32, 1 /* is_add */);
  session_add_del_route_via_lookup_in_table (
    server_vrf, client_vrf, &intf_addr[0], 32, 1 /* is_add */);

  /* Insert namespace */
  appns_id = format (0, "appns_server");
  vnet_app_namespace_add_del_args_t ns_args = { .ns_id = appns_id,
						.secret = placeholder_secret,
						.sw_if_index = sw_if_index[1],
						.ip4_fib_id = 0,
						.is_add = 1 };
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %d", error);

  /* Attach client/server */
  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "session_test_client"),
  };

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "client app attached: %U", format_session_error,
		error);
  client_index = attach_args.app_index;
  vec_free (attach_args.name);

  attach_args.name = format (0, "session_test_server");
  attach_args.namespace_id = appns_id;
  attach_args.options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 32 << 20;
  attach_args.options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server app attached: %U", format_session_error,
		error);
  vec_free (attach_args.name);
  server_index = attach_args.app_index;

  /* Listen on server */
  server_sep.is_ip4 = 1;
  server_sep.port = placeholder_server_port;
  vnet_listen_args_t bind_args = {
    .sep_ext = server_sep,
    .app_index = server_index,
  };
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "server is listening");

  /* First connection: Connect with fixed 5-tuple */
  client_sep.is_ip4 = 1;
  client_sep.ip.ip4.as_u32 = intf_addr[1].as_u32;
  client_sep.port = placeholder_server_port;
  client_sep.peer.is_ip4 = 1;
  client_sep.peer.ip.ip4.as_u32 = intf_addr[0].as_u32;
  client_sep.peer.port = placeholder_client_port;
  client_sep.transport_proto = TRANSPORT_PROTO_TCP;

  vnet_connect_args_t connect_args = {
    .sep_ext = client_sep,
    .app_index = client_index,
  };

  connected_session_index = connected_session_thread = ~0;
  accepted_session_index = accepted_session_thread = ~0;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error == 0), "connecting first session");

  /* Wait for connection establishment */
  tries = 0;
  while (placeholder_accept == 0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  SESSION_TEST ((accepted_session_index != ~0),
		"first session is accepted: %u", accepted_session_index);
  while (connected_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  SESSION_TEST ((connected_session_index != ~0),
		"first session is connected: %u", connected_session_index);

  /* Acquire server side connections prior to disconnect for later use */
  transport_connection_t *tc = session_get_transport (
    session_get (accepted_session_index, accepted_session_thread));

  /* Close the first connection from server side */
  vnet_disconnect_args_t disconnect_args = {
    .handle =
      session_make_handle (accepted_session_index, accepted_session_thread),
    .app_index = server_index,
  };
  error = vnet_disconnect_session (&disconnect_args);
  SESSION_TEST ((error == 0), "first session is being disconnected by server");

  /* Wait for disconnection of client */
  tries = 0;
  while (connected_session_index != ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  SESSION_TEST ((connected_session_index == ~0),
		"the client connection is disconnected");

  /* force server side to get CLOSED state */
  transport_reset (tc->proto, tc->c_index, tc->thread_index);
  tcp_connection_t *tcp = tcp_connection_get_if_valid (tc->c_index, tc->thread_index);
  SESSION_TEST ((tcp && tcp->state == TCP_STATE_CLOSED),
		"the server connection is in CLOSED");

  /* Second connection: attempt to reconnect with same 5-tuple */
  ST_DBG ("Trying to reconnect to CLOSED Server session");
  placeholder_accept = 0;

  /* Use identical 5-tuple */
  error = vnet_connect (&connect_args);
  SESSION_TEST (error == 0, "immediate second connect should not fail: %U",
		format_session_error, error);
  /* If connect succeeds, wait a bit to see if connection actually establishes
   */
  tries = 0;
  while (connected_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 10e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  SESSION_TEST (connected_session_index != ~0,
		"immediate second connection should establish");

  /* Clean up the second connection */
  if (connected_session_index != ~0)
    {
      disconnect_args.handle = session_make_handle (connected_session_index,
						    connected_session_thread);
      disconnect_args.app_index = client_index;
      error = vnet_disconnect_session (&disconnect_args);
      SESSION_TEST ((error == 0), "second disconnect should work");
    }

  /* Cleanup */
  vnet_app_detach_args_t detach_args = {
    .app_index = server_index,
    .api_client_index = ~0,
  };
  vnet_application_detach (&detach_args);
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  ns_args.is_add = 0;
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns delete should succeed: %d", error);

  /* Allow cleanup to finish */
  vlib_process_suspend (vm, 100e-3);

  session_add_del_route_via_lookup_in_table (
    client_vrf, server_vrf, &intf_addr[1], 32, 0 /* is_add */);
  session_add_del_route_via_lookup_in_table (
    server_vrf, client_vrf, &intf_addr[0], 32, 0 /* is_add */);

  session_delete_loopback (sw_if_index[0]);
  session_delete_loopback (sw_if_index[1]);

  vec_free (appns_id);

  return 0;
}

typedef struct
{
  u32 session_index;
  clib_thread_index_t thread_index;
  u32 opaque;
} session_test_iter_record_t;

typedef struct
{
  /* value copies of every session the callback was invoked for, in visit
   * order; never a pointer into the live session pool */
  session_test_iter_record_t *records;
  u32 n_calls;
  u32 stop_after;
  u32 error_after;
  u8 saw_wrong_pointer;
} session_test_iter_ctx_t;

static session_table_iter_result_t
session_test_iter_cb (const session_t *s, clib_thread_index_t thread_index, void *arg)
{
  session_test_iter_ctx_t *ctx = arg;
  session_test_iter_record_t rec;
  const session_t *expected;

  ctx->n_calls++;

  /* the session handed to the callback must be the live pool entry for the
   * requested worker, addressable only for the duration of this call */
  expected = pool_elt_at_index (session_main.wrk[thread_index].sessions, s->session_index);
  if (expected != s || s->thread_index != thread_index)
    ctx->saw_wrong_pointer = 1;

  rec.session_index = s->session_index;
  rec.thread_index = s->thread_index;
  rec.opaque = s->opaque;
  vec_add1 (ctx->records, rec);

  if (ctx->error_after && ctx->n_calls == ctx->error_after)
    return SESSION_TABLE_ITER_ERROR;
  if (ctx->stop_after && ctx->n_calls == ctx->stop_after)
    return SESSION_TABLE_ITER_STOP;
  return SESSION_TABLE_ITER_CONTINUE;
}

static int
session_test_table_iteration (vlib_main_t *vm, unformat_input_t *input)
{
  clib_thread_index_t wrk_a = vlib_num_workers () + 41;
  clib_thread_index_t wrk_b = vlib_num_workers () + 42;
  clib_thread_index_t wrk_c = vlib_num_workers () + 43;
  clib_thread_index_t wrk_empty = vlib_num_workers () + 44;
  u32 idx[6], idx_b[2], idx_c[3], saved_opaque_c[3];
  session_test_iter_ctx_t ctx;
  session_t *s;
  u32 visited, next;
  int rv, i;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return -1;

  /* a fresh, private set of worker pools nothing else in this binary
   * touches, so every scenario below is self-contained and order-independent */
  vec_validate (session_main.wrk, wrk_empty);

  /* empty pool: nothing allocated, callback must never run */
  clib_memset (&ctx, 0, sizeof (ctx));
  visited = next = ~0;
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_empty, 0, 1, session_test_iter_cb, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == 0 && visited == 0 && next == 0 && ctx.n_calls == 0),
		"table-iteration: empty pool visits nothing");

  /* allocate six sessions, then free two of them to leave holes both before
   * (index 0) and between (index 3) the remaining allocated entries {1,2,4,5} */
  for (i = 0; i < 6; i++)
    {
      s = session_alloc (wrk_a);
      s->opaque = 1000 + i;
      idx[i] = s->session_index;
      SESSION_TEST ((idx[i] == (u32) i),
		    "table-iteration: fresh pool allocates index %d in order", i);
    }
  session_free (pool_elt_at_index (session_main.wrk[wrk_a].sessions, idx[0]));
  session_free (pool_elt_at_index (session_main.wrk[wrk_a].sessions, idx[3]));

  /* full walk from 0: holes are skipped and do not consume max_count */
  clib_memset (&ctx, 0, sizeof (ctx));
  visited = next = ~0;
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_a, 0, 10, session_test_iter_cb, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == 0 && visited == 4 && next == 6 && ctx.n_calls == 4 &&
		 vec_len (ctx.records) == 4 && !ctx.saw_wrong_pointer),
		"table-iteration: holes are skipped and not counted");
  SESSION_TEST ((ctx.records[0].session_index == idx[1] && ctx.records[0].opaque == 1001 &&
		 ctx.records[1].session_index == idx[2] && ctx.records[1].opaque == 1002 &&
		 ctx.records[2].session_index == idx[4] && ctx.records[2].opaque == 1004 &&
		 ctx.records[3].session_index == idx[5] && ctx.records[3].opaque == 1005 &&
		 ctx.records[0].thread_index == wrk_a && ctx.records[3].thread_index == wrk_a),
		"table-iteration: walk visits allocated entries in index order on the right worker");
  vec_free (ctx.records);

  /* nonzero start on an allocated entry */
  clib_memset (&ctx, 0, sizeof (ctx));
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_a, 2, 10, session_test_iter_cb, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == 0 && visited == 3 && next == 6 && vec_len (ctx.records) == 3 &&
		 ctx.records[0].session_index == idx[2] && ctx.records[2].session_index == idx[5]),
		"table-iteration: nonzero start skips earlier entries");
  vec_free (ctx.records);

  /* start index that lands exactly on a hole must resume at the next
   * allocated entry, not skip an extra one */
  clib_memset (&ctx, 0, sizeof (ctx));
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_a, 3, 10, session_test_iter_cb, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == 0 && visited == 2 && next == 6 && vec_len (ctx.records) == 2 &&
		 ctx.records[0].session_index == idx[4] && ctx.records[1].session_index == idx[5]),
		"table-iteration: a start index on a hole resumes at the next allocated entry");
  vec_free (ctx.records);

  /* start past the pool end visits nothing and leaves next_session_index
   * equal to the requested start */
  clib_memset (&ctx, 0, sizeof (ctx));
  visited = next = ~0;
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_a, 1000, 10, session_test_iter_cb, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == 0 && visited == 0 && next == 1000 && ctx.n_calls == 0),
		"table-iteration: a start past the pool end visits nothing");

  /* exact max_count bounds: 1, a partial 2, and the exact remaining count 4 */
  clib_memset (&ctx, 0, sizeof (ctx));
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_a, 0, 1, session_test_iter_cb, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == 0 && visited == 1 && next == 2 && ctx.records[0].session_index == idx[1]),
		"table-iteration: max_count 1 stops after the first accepted entry");
  vec_free (ctx.records);

  clib_memset (&ctx, 0, sizeof (ctx));
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_a, 0, 2, session_test_iter_cb, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == 0 && visited == 2 && next == 3),
		"table-iteration: max_count 2 stops exactly there");
  vec_free (ctx.records);

  clib_memset (&ctx, 0, sizeof (ctx));
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_a, 0, 4, session_test_iter_cb, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == 0 && visited == 4 && next == 6),
		"table-iteration: max_count exactly matching the available count visits all of them");
  vec_free (ctx.records);

  /* callback-requested stop: a successful, deterministic early exit */
  clib_memset (&ctx, 0, sizeof (ctx));
  ctx.stop_after = 2;
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_a, 0, 10, session_test_iter_cb, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == 0 && visited == 2 && next == 3 && ctx.n_calls == 2),
		"table-iteration: callback stop ends the walk successfully");
  vec_free (ctx.records);

  /* callback-requested error: the erroring entry is not counted as visited,
   * the walk stops immediately, and the failure is reported distinctly
   * from a successful stop or an invalid precondition */
  clib_memset (&ctx, 0, sizeof (ctx));
  ctx.error_after = 2;
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_a, 0, 10, session_test_iter_cb, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == -2 && visited == 1 && next == 3 && ctx.n_calls == 2 &&
		 vec_len (ctx.records) == 2),
		"table-iteration: callback error stops the walk and is not counted as visited");
  vec_free (ctx.records);

  /* invalid preconditions: iter_fn is never invoked and the walk reports
   * a distinct failure from a callback-reported error */
  clib_memset (&ctx, 0, sizeof (ctx));
  visited = next = ~0;
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (vec_len (session_main.wrk), 0, 10, session_test_iter_cb, &ctx,
				&visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == -1 && visited == 0 && next == 0 && ctx.n_calls == 0),
		"table-iteration: an out-of-range worker index is rejected without calling back");

  visited = next = ~0;
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_a, 5, 10, 0, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == -1 && visited == 0 && next == 5),
		"table-iteration: a null callback is rejected without a crash");

  clib_memset (&ctx, 0, sizeof (ctx));
  visited = next = ~0;
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_a, 0, 0, session_test_iter_cb, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == -1 && visited == 0 && next == 0 && ctx.n_calls == 0),
		"table-iteration: a zero max_count is rejected without calling back");

  /* multi-worker selection: a second, independent worker pool must be read
   * on its own, never mixing in another worker's sessions */
  s = session_alloc (wrk_b);
  s->opaque = 2000;
  idx_b[0] = s->session_index;
  s = session_alloc (wrk_b);
  s->opaque = 2001;
  idx_b[1] = s->session_index;

  clib_memset (&ctx, 0, sizeof (ctx));
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_b, 0, 10, session_test_iter_cb, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == 0 && visited == 2 && vec_len (ctx.records) == 2 && !ctx.saw_wrong_pointer &&
		 ctx.records[0].thread_index == wrk_b && ctx.records[1].thread_index == wrk_b &&
		 ctx.records[0].session_index == idx_b[0] && ctx.records[1].session_index == idx_b[1] &&
		 ctx.records[0].opaque == 2000 && ctx.records[1].opaque == 2001),
		"table-iteration: worker selection reads only the requested worker's own pool");
  vec_free (ctx.records);
  session_free (pool_elt_at_index (session_main.wrk[wrk_b].sessions, idx_b[0]));
  session_free (pool_elt_at_index (session_main.wrk[wrk_b].sessions, idx_b[1]));

  /* no pointer is used after the iterator returns: the callback below only
   * ever copies session_index/thread_index/opaque by value into ctx.records.
   * Free (and, under CLIB_DEBUG, poison with 0xFA) every visited session
   * right after the barrier-protected call returns; the previously copied
   * values must be unaffected, proving they are independent copies and not
   * live pointers or cached state carried across the call boundary. */
  for (i = 0; i < 3; i++)
    {
      s = session_alloc (wrk_c);
      s->opaque = 9000 + i;
      idx_c[i] = s->session_index;
      saved_opaque_c[i] = s->opaque;
    }

  clib_memset (&ctx, 0, sizeof (ctx));
  vlib_worker_thread_barrier_sync (vm);
  rv = session_table_iteration (wrk_c, 0, 10, session_test_iter_cb, &ctx, &visited, &next);
  vlib_worker_thread_barrier_release (vm);
  SESSION_TEST ((rv == 0 && visited == 3 && vec_len (ctx.records) == 3 && !ctx.saw_wrong_pointer),
		"table-iteration: pointer-proof setup collects three live records");

  for (i = 0; i < 3; i++)
    session_free (pool_elt_at_index (session_main.wrk[wrk_c].sessions, idx_c[i]));

  for (i = 0; i < 3; i++)
    SESSION_TEST ((ctx.records[i].session_index == idx_c[i] &&
		   ctx.records[i].opaque == saved_opaque_c[i]),
		  "table-iteration: copied record %d survives freeing the live session", i);
  vec_free (ctx.records);

  return 0;
}

static clib_error_t *
session_test (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  int res = 0;

  session_test_enable_rule_table_engine (vm);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "basic"))
	res = session_test_basic (vm, input);
      else if (unformat (input, "preconnect-cancel"))
	res = session_test_preconnect_cancel (vm, input);
      else if (unformat (input, "namespace"))
	res = session_test_namespace (vm, input);
      else if (unformat (input, "rules-table"))
	res = session_test_rule_table (vm, input);
      else if (unformat (input, "rules"))
	res = session_test_rules (vm, input);
      else if (unformat (input, "tuple-result"))
	res = session_test_tuple_result (vm, input);
      else if (unformat (input, "table-iteration"))
	res = session_test_table_iteration (vm, input);
      else if (unformat (input, "proxy"))
	res = session_test_proxy (vm, input);
      else if (unformat (input, "endpt-cfg"))
	res = session_test_endpoint_cfg (vm, input);
      else if (unformat (input, "mq-speed"))
	res = session_test_mq_speed (vm, input);
      else if (unformat (input, "mq-basic"))
	res = session_test_mq_basic (vm, input);
      else if (unformat (input, "enable-disable"))
	res = session_test_enable_disable (vm, input);
      else if (unformat (input, "sdl"))
	res = session_test_sdl (vm, input);
      else if (unformat (input, "ext-cfg"))
	res = session_test_ext_cfg (vm, input);
      else if (unformat (input, "app-crypto"))
	res = session_test_app_crypto (vm, input);
      else if (unformat (input, "reconn-while-closed"))
	res = session_test_reconn_while_closed (vm, input);
      else if (unformat (input, "all"))
	{
	  if ((res = session_test_basic (vm, input)))
	    goto done;
	  if ((res = session_test_namespace (vm, input)))
	    goto done;
	  if ((res = session_test_rule_table (vm, input)))
	    goto done;
	  if ((res = session_test_rules (vm, input)))
	    goto done;
	  if ((res = session_test_tuple_result (vm, input)))
	    goto done;
	  if ((res = session_test_table_iteration (vm, input)))
	    goto done;
	  if ((res = session_test_proxy (vm, input)))
	    goto done;
	  if ((res = session_test_endpoint_cfg (vm, input)))
	    goto done;
	  if ((res = session_test_mq_speed (vm, input)))
	    goto done;
	  if ((res = session_test_mq_basic (vm, input)))
	    goto done;
	  if ((res = session_test_sdl (vm, input)))
	    goto done;
	  if ((res = session_test_ext_cfg (vm, input)))
	    goto done;
	  if ((res = session_test_app_crypto (vm, input)))
	    goto done;
	  if ((res = session_test_enable_disable (vm, input)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "Session unit test failed");

  vlib_cli_output (vm, "SUCCESS");
  return 0;
}

VLIB_CLI_COMMAND (session_test_command, static) = {
  .path = "test session",
  .short_help = "internal session unit tests",
  .function = session_test,
};
