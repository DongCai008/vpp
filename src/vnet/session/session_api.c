/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015-2019 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/application_local.h>
#include <vnet/session/session.h>
#include <vnet/session/session_table.h>
#include <vnet/session/session_rules_table.h>
#include <vnet/session/session_sdl.h>
#include <vnet/ip/ip_types_api.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <vnet/format_fns.h>
#include <vnet/session/session.api_enum.h>
#include <vnet/session/session.api_types.h>

#define REPLY_MSG_ID_BASE session_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

VLIB_REGISTER_LOG_CLASS (session_api_log, static) = { .class_name = "session",
						      .subclass_name = "api" };

#define log_debug(fmt, ...)                                                                        \
  vlib_log_debug (session_api_log.class, "%s: " fmt, __func__, __VA_ARGS__)
#define log_warn(fmt, ...) vlib_log_warn (session_api_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...)  vlib_log_err (session_api_log.class, fmt, __VA_ARGS__)

static int
verify_message_len (void *mp, u64 expected_len, char *where)
{
  u32 supplied_len = vl_msg_api_get_msg_length (mp);

  if (supplied_len < expected_len)
    {
      log_err ("%s: Supplied message length %d is less than expected %d", where, supplied_len,
	       expected_len);
      return 0;
    }
  else
    {
      return 1;
    }
}

static void
vl_api_session_sdl_add_del_v2_t_handler (vl_api_session_sdl_add_del_v2_t *mp)
{
  vl_api_session_sdl_add_del_v2_reply_t *rmp;
  session_rule_add_del_args_t args;
  session_rule_table_add_del_args_t *table_args = &args.table_args;
  int rv = 0;
  u32 count = clib_net_to_host_u32 (mp->count);
  u64 expected_len = sizeof (*mp) + count * sizeof (mp->r[0]);

  if ((session_main.is_enabled == 0) || (session_sdl_is_enabled () == 0))
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  if (!verify_message_len (mp, expected_len, "session_sdl_add_del_v2"))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  clib_memset (&args, 0, sizeof (args));
  table_args->is_add = mp->is_add;
  args.scope = SESSION_RULE_SCOPE_GLOBAL;
  args.appns_index = clib_net_to_host_u32 (mp->appns_index);
  for (int i = 0; i < count; i++)
    {
      mp->r[i].tag[sizeof (mp->r[i].tag) - 1] = 0;
      table_args->tag = format (0, "%s", mp->r[i].tag);
      ip_prefix_decode (&mp->r[i].rmt, &table_args->rmt);
      table_args->action_index = clib_net_to_host_u32 (mp->r[i].action_index);

      rv = vnet_session_rule_add_del (&args);
      vec_free (table_args->tag);
      if (rv)
	{
	  log_err ("session_sdl add del returned on %U @index %d: %U", format_ip46_address,
		   &table_args->rmt.fp_addr, IP46_TYPE_ANY, i, format_session_error, rv);

	  /* roll back */
	  table_args->is_add = !mp->is_add;
	  for (int j = i - 1; j >= 0; j--)
	    {
	      mp->r[j].tag[sizeof (mp->r[j].tag) - 1] = 0;
	      table_args->tag = format (0, "%s", mp->r[j].tag);
	      ip_prefix_decode (&mp->r[j].rmt, &table_args->rmt);
	      table_args->action_index = clib_net_to_host_u32 (mp->r[j].action_index);
	      int rv2 = vnet_session_rule_add_del (&args);
	      vec_free (table_args->tag);
	      if (rv2)
		log_err ("rollback session_sdl add del returned on %U "
			 "@index %d: %U",
			 format_ip46_address, &table_args->rmt.fp_addr, IP46_TYPE_ANY, j,
			 format_session_error, rv2);
	    }
	  break;
	}
    }

done:
  REPLY_MACRO (VL_API_SESSION_SDL_ADD_DEL_V2_REPLY);
}

static void
vl_api_session_sdl_add_del_t_handler (vl_api_session_sdl_add_del_t *mp)
{
  vl_api_session_sdl_add_del_reply_t *rmp;
  session_rule_add_del_args_t args;
  session_rule_table_add_del_args_t *table_args = &args.table_args;
  int rv = 0;
  u32 count = clib_net_to_host_u32 (mp->count);
  u64 expected_len = sizeof (*mp) + count * sizeof (mp->r[0]);

  if ((session_main.is_enabled == 0) || (session_sdl_is_enabled () == 0))
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  if (!verify_message_len (mp, expected_len, "session_sdl_add_del"))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  clib_memset (&args, 0, sizeof (args));
  table_args->is_add = mp->is_add;
  args.scope = SESSION_RULE_SCOPE_GLOBAL;
  args.appns_index = clib_net_to_host_u32 (mp->appns_index);
  for (int i = 0; i < count; i++)
    {
      mp->r[i].tag[sizeof (mp->r[i].tag) - 1] = 0;
      table_args->tag = format (0, "%s", mp->r[i].tag);
      ip_prefix_decode (&mp->r[i].lcl, &table_args->lcl);
      /*
       * Need to set fp_proto for vnet_session_rule_add_del to find the
       * correct table
       */
      table_args->rmt.fp_proto = table_args->lcl.fp_proto;
      table_args->action_index = clib_net_to_host_u32 (mp->r[i].action_index);

      rv = vnet_session_rule_add_del (&args);
      vec_free (table_args->tag);
      if (rv)
	{
	  log_err ("session_sdl add del returned on %U @index %d: %U", format_ip46_address,
		   &table_args->lcl.fp_addr, IP46_TYPE_ANY, i, format_session_error, rv);

	  /* roll back */
	  table_args->is_add = !mp->is_add;
	  for (int j = i - 1; j >= 0; j--)
	    {
	      mp->r[j].tag[sizeof (mp->r[j].tag) - 1] = 0;
	      table_args->tag = format (0, "%s", mp->r[j].tag);
	      ip_prefix_decode (&mp->r[j].lcl, &table_args->lcl);
	      table_args->rmt.fp_proto = table_args->lcl.fp_proto;
	      table_args->action_index = clib_net_to_host_u32 (mp->r[j].action_index);
	      int rv2 = vnet_session_rule_add_del (&args);
	      vec_free (table_args->tag);
	      if (rv2)
		log_err ("rollback session_sdl add del returned on %U "
			 "@index %d: %U",
			 format_ip46_address, &table_args->lcl.fp_addr, IP46_TYPE_ANY, j,
			 format_session_error, rv2);
	    }
	  break;
	}
    }

done:
  REPLY_MACRO (VL_API_SESSION_SDL_ADD_DEL_REPLY);
}

static transport_proto_t
api_session_transport_proto_decode (const vl_api_transport_proto_t *api_tp)
{
  switch (*api_tp)
    {
    case TRANSPORT_PROTO_API_TCP:
      return TRANSPORT_PROTO_TCP;
    case TRANSPORT_PROTO_API_UDP:
      return TRANSPORT_PROTO_UDP;
    case TRANSPORT_PROTO_API_TLS:
      return TRANSPORT_PROTO_TLS;
    case TRANSPORT_PROTO_API_QUIC:
      return TRANSPORT_PROTO_QUIC;
    default:
      return TRANSPORT_PROTO_NONE;
    }
}

static vl_api_transport_proto_t
api_session_transport_proto_encode (const transport_proto_t tp)
{
  switch (tp)
    {
    case TRANSPORT_PROTO_TCP:
      return TRANSPORT_PROTO_API_TCP;
    case TRANSPORT_PROTO_UDP:
      return TRANSPORT_PROTO_API_UDP;
    case TRANSPORT_PROTO_TLS:
      return TRANSPORT_PROTO_API_TLS;
    case TRANSPORT_PROTO_QUIC:
      return TRANSPORT_PROTO_API_QUIC;
    default:
      return TRANSPORT_PROTO_API_NONE;
    }
}

static int
session_send_fds (vl_api_registration_t *reg, int fds[], int n_fds)
{
  clib_error_t *error;
  if (vl_api_registration_file_index (reg) == VL_API_INVALID_FI)
    return SESSION_E_BAPI_NO_FD;
  error = vl_api_send_fd_msg (reg, fds, n_fds);
  if (error)
    {
      clib_error_report (error);
      return SESSION_E_BAPI_SEND_FD;
    }
  return 0;
}

static int
mq_send_session_accepted_cb (session_t *s)
{
  app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
  session_accepted_msg_t m = { 0 };
  fifo_segment_t *eq_seg;
  session_t *listener;
  application_t *app;

  app = application_get (app_wrk->app_index);

  m.context = app->app_index;
  m.server_rx_fifo = fifo_segment_fifo_offset (s->rx_fifo);
  m.server_tx_fifo = fifo_segment_fifo_offset (s->tx_fifo);
  m.segment_handle = session_segment_handle (s);
  m.flags = s->flags;

  eq_seg = application_get_rx_mqs_segment (app);

  if (session_has_transport (s))
    {
      listener = listen_session_get_from_handle (s->listener_handle);
      m.listener_handle = app_listen_session_handle (listener);
      if (application_is_proxy (app))
	{
	  listener = app_worker_first_listener (app_wrk, session_get_fib_proto (s),
						session_get_transport_proto (s));
	  if (listener)
	    m.listener_handle = listen_session_get_handle (listener);
	}
      m.vpp_event_queue_address = fifo_segment_msg_q_offset (eq_seg, s->thread_index);
      m.mq_index = s->thread_index;
      m.handle = session_handle (s);

      session_get_endpoint (s, &m.rmt, &m.lcl);
    }
  else
    {
      ct_connection_t *ct;

      ct = (ct_connection_t *) session_get_transport (s);
      listener = listen_session_get_from_handle (s->listener_handle);
      m.listener_handle = app_listen_session_handle (listener);
      m.rmt.is_ip4 = session_type_is_ip4 (listener->session_type);
      m.rmt.port = ct->c_rmt_port;
      m.lcl.port = ct->c_lcl_port;
      m.handle = session_handle (s);
      m.vpp_event_queue_address = fifo_segment_msg_q_offset (eq_seg, s->thread_index);
      m.mq_index = s->thread_index;
    }

  if (application_original_dst_is_enabled (app))
    {
      session_get_original_dst (&m.lcl, &m.rmt, session_get_transport_proto (s),
				&m.original_dst_ip4, &m.original_dst_port);
    }

  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_ACCEPTED, &m, sizeof (m));

  return 0;
}

static inline void
mq_send_session_close_evt (app_worker_t *app_wrk, session_handle_t sh, session_evt_type_t evt_type)
{
  session_disconnected_msg_t m = { 0 };

  m.handle = sh;
  m.context = app_wrk->api_client_index;

  app_wrk_send_ctrl_evt (app_wrk, evt_type, &m, sizeof (m));
}

static inline void
mq_notify_close_subscribers (u32 app_index, session_handle_t sh, svm_fifo_t *f,
			     session_evt_type_t evt_type)
{
  app_worker_t *app_wrk;
  application_t *app;
  int i;

  app = application_get (app_index);
  if (!app)
    return;

  for (i = 0; i < f->signals->n_subscribers; i++)
    {
      if (!(app_wrk = application_get_worker (app, f->signals->subscribers[i])))
	continue;
      mq_send_session_close_evt (app_wrk, sh, SESSION_CTRL_EVT_DISCONNECTED);
    }
}

static void
mq_send_session_disconnected_cb (session_t *s)
{
  app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
  session_handle_t sh = session_handle (s);

  mq_send_session_close_evt (app_wrk, session_handle (s), SESSION_CTRL_EVT_DISCONNECTED);

  if (svm_fifo_n_subscribers (s->rx_fifo))
    mq_notify_close_subscribers (app_wrk->app_index, sh, s->rx_fifo, SESSION_CTRL_EVT_DISCONNECTED);
}

static void
mq_send_session_reset_cb (session_t *s)
{
  app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
  session_handle_t sh = session_handle (s);

  mq_send_session_close_evt (app_wrk, sh, SESSION_CTRL_EVT_RESET);

  if (svm_fifo_n_subscribers (s->rx_fifo))
    mq_notify_close_subscribers (app_wrk->app_index, sh, s->rx_fifo, SESSION_CTRL_EVT_RESET);
}

int
mq_send_session_connected_cb (u32 app_wrk_index, u32 api_context, session_t *s, session_error_t err)
{
  session_connected_msg_t m = { 0 };
  fifo_segment_t *eq_seg;
  app_worker_t *app_wrk;
  application_t *app;

  app_wrk = app_worker_get (app_wrk_index);

  m.context = api_context;
  m.retval = err;

  if (err)
    goto snd_msg;

  app = application_get (app_wrk->app_index);
  eq_seg = application_get_rx_mqs_segment (app);

  if (session_has_transport (s))
    {
      m.handle = session_handle (s);
      m.vpp_event_queue_address = fifo_segment_msg_q_offset (eq_seg, s->thread_index);

      session_get_endpoint (s, NULL, &m.lcl);

      m.server_rx_fifo = fifo_segment_fifo_offset (s->rx_fifo);
      m.server_tx_fifo = fifo_segment_fifo_offset (s->tx_fifo);
      m.segment_handle = session_segment_handle (s);
      m.mq_index = s->thread_index;
    }
  else
    {
      ct_connection_t *cct;

      cct = (ct_connection_t *) session_get_transport (s);
      m.handle = session_handle (s);
      m.lcl.port = cct->c_lcl_port;
      m.lcl.is_ip4 = cct->c_is_ip4;
      m.vpp_event_queue_address = fifo_segment_msg_q_offset (eq_seg, s->thread_index);
      m.server_rx_fifo = fifo_segment_fifo_offset (s->rx_fifo);
      m.server_tx_fifo = fifo_segment_fifo_offset (s->tx_fifo);
      m.segment_handle = session_segment_handle (s);
      m.mq_index = s->thread_index;
      m.ct_rx_fifo = fifo_segment_fifo_offset (cct->client_rx_fifo);
      m.ct_tx_fifo = fifo_segment_fifo_offset (cct->client_tx_fifo);
      m.ct_segment_handle = cct->segment_handle;
    }

  /* Setup app session index based on api_context */
  s->rx_fifo->app_session_index = api_context;
  s->tx_fifo->app_session_index = api_context;

snd_msg:

  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_CONNECTED, &m, sizeof (m));

  return 0;
}

static int
mq_send_session_bound_cb (u32 app_wrk_index, u32 api_context, session_handle_t handle, int rv)
{
  session_bound_msg_t m = { 0 };
  transport_connection_t *ltc;
  fifo_segment_t *eq_seg;
  app_worker_t *app_wrk;
  application_t *app;
  app_listener_t *al;
  session_t *ls = 0;

  app_wrk = app_worker_get (app_wrk_index);

  m.context = api_context;
  m.retval = rv;

  if (rv)
    goto snd_msg;

  m.handle = handle;
  al = app_listener_get_w_handle (handle);
  if (al->session_index != SESSION_INVALID_INDEX)
    ls = app_listener_get_session (al);
  else
    ls = app_listener_get_local_session (al);

  ltc = session_get_transport (ls);
  m.lcl_port = ltc->lcl_port;
  m.lcl_is_ip4 = ltc->is_ip4;
  clib_memcpy_fast (m.lcl_ip, &ltc->lcl_ip, sizeof (m.lcl_ip));
  app = application_get (app_wrk->app_index);
  eq_seg = application_get_rx_mqs_segment (app);
  m.vpp_evt_q = fifo_segment_msg_q_offset (eq_seg, ls->thread_index);
  m.mq_index = ls->thread_index;

  if (transport_connection_is_cless (ltc))
    {
      session_t *wrk_ls;
      m.mq_index = transport_cl_thread ();
      m.vpp_evt_q = fifo_segment_msg_q_offset (eq_seg, m.mq_index);
      wrk_ls = app_listener_get_wrk_cl_session (al, app_wrk->wrk_map_index);
      m.rx_fifo = fifo_segment_fifo_offset (wrk_ls->rx_fifo);
      m.tx_fifo = fifo_segment_fifo_offset (wrk_ls->tx_fifo);
      m.segment_handle = session_segment_handle (wrk_ls);
      m.cl_sh_handle = session_handle (wrk_ls);

      /* Keep pointer to app session */
      wrk_ls->rx_fifo->app_session_index = api_context;
      wrk_ls->tx_fifo->app_session_index = api_context;
    }

snd_msg:

  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_BOUND, &m, sizeof (m));

  return 0;
}

static void
mq_send_unlisten_cb (u32 app_wrk_index, session_handle_t sh, u32 context, int rv)
{
  session_unlisten_reply_msg_t m = { 0 };
  app_worker_t *app_wrk;

  app_wrk = app_worker_get (app_wrk_index);

  m.context = context;
  m.handle = sh;
  m.retval = rv;
  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_UNLISTEN_REPLY, &m, sizeof (m));
}

static void
mq_send_session_migrate_cb (session_t *s, session_handle_t new_sh)
{
  session_migrated_msg_t m = { 0 };
  fifo_segment_t *eq_seg;
  app_worker_t *app_wrk;
  application_t *app;
  clib_thread_index_t thread_index;

  thread_index = session_thread_from_handle (new_sh);
  app_wrk = app_worker_get (s->app_wrk_index);
  app = application_get (app_wrk->app_index);
  eq_seg = application_get_rx_mqs_segment (app);

  m.handle = session_handle (s);
  m.new_handle = new_sh;
  m.vpp_thread_index = thread_index;
  m.vpp_evt_q = fifo_segment_msg_q_offset (eq_seg, thread_index);
  m.segment_handle = SESSION_INVALID_HANDLE;

  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_MIGRATED, &m, sizeof (m));
}

static int
mq_send_add_segment_cb (u32 app_wrk_index, u64 segment_handle)
{
  session_app_add_segment_msg_t m = { 0 };
  vl_api_registration_t *reg;
  app_worker_t *app_wrk;
  fifo_segment_t *fs;
  ssvm_private_t *sp;
  u8 fd_flags = 0;

  app_wrk = app_worker_get (app_wrk_index);

  reg = vl_mem_api_client_index_to_registration (app_wrk->api_client_index);
  if (!reg)
    {
      clib_warning ("no api registration for client: %u", app_wrk->api_client_index);
      return -1;
    }

  fs = segment_manager_get_segment_w_handle (segment_handle);
  sp = &fs->ssvm;
  if (ssvm_type (sp) == SSVM_SEGMENT_MEMFD)
    {
      if (vl_api_registration_file_index (reg) == VL_API_INVALID_FI)
	{
	  clib_warning ("can't send memfd fd");
	  return -1;
	}

      fd_flags |= SESSION_FD_F_MEMFD_SEGMENT;
    }

  m.segment_size = sp->ssvm_size;
  m.fd_flags = fd_flags;
  m.segment_handle = segment_handle;
  strncpy ((char *) m.segment_name, (char *) sp->name, sizeof (m.segment_name) - 1);

  return app_wrk_send_ctrl_evt_fd (app_wrk, SESSION_CTRL_EVT_APP_ADD_SEGMENT, &m, sizeof (m),
				   sp->fd);
}

static int
mq_send_del_segment_cb (u32 app_wrk_index, u64 segment_handle)
{
  session_app_del_segment_msg_t m = { 0 };
  vl_api_registration_t *reg;
  app_worker_t *app_wrk;

  app_wrk = app_worker_get (app_wrk_index);
  reg = vl_mem_api_client_index_to_registration (app_wrk->api_client_index);
  if (!reg)
    {
      clib_warning ("no registration: %u", app_wrk->api_client_index);
      return -1;
    }

  m.segment_handle = segment_handle;

  return app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_APP_DEL_SEGMENT, &m, sizeof (m));
}

static void
mq_send_session_cleanup_cb (session_t *s, session_cleanup_ntf_t ntf)
{
  session_cleanup_msg_t m = { 0 };
  app_worker_t *app_wrk;

  /* Propagate transport cleanup notifications only if app didn't close */
  if (ntf == SESSION_CLEANUP_TRANSPORT && s->session_state != SESSION_STATE_TRANSPORT_DELETED)
    return;

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (!app_wrk)
    return;

  m.handle = session_handle (s);
  m.type = ntf;

  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_CLEANUP, &m, sizeof (m));
}

static int
mq_send_io_rx_event (session_t *s)
{
  session_event_t *mq_evt;
  svm_msg_q_msg_t mq_msg;
  app_worker_t *app_wrk;
  svm_msg_q_t *mq;

  if (svm_fifo_has_event (s->rx_fifo))
    return 0;

  app_wrk = app_worker_get (s->app_wrk_index);
  mq = app_wrk->event_queue;

  mq_msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
  mq_evt = svm_msg_q_msg_data (mq, &mq_msg);

  mq_evt->event_type = SESSION_IO_EVT_RX;
  mq_evt->session_index = s->rx_fifo->app_session_index;

  (void) svm_fifo_set_event (s->rx_fifo);

  svm_msg_q_add_raw (mq, &mq_msg);

  return 0;
}

static int
mq_send_io_tx_event (session_t *s)
{
  app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
  svm_msg_q_t *mq = app_wrk->event_queue;
  session_event_t *mq_evt;
  svm_msg_q_msg_t mq_msg;

  mq_msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
  mq_evt = svm_msg_q_msg_data (mq, &mq_msg);

  mq_evt->event_type = SESSION_IO_EVT_TX;
  mq_evt->session_index = s->tx_fifo->app_session_index;

  svm_msg_q_add_raw (mq, &mq_msg);

  return 0;
}

static session_cb_vft_t session_mq_cb_vft = {
  .session_accept_callback = mq_send_session_accepted_cb,
  .session_disconnect_callback = mq_send_session_disconnected_cb,
  .session_connected_callback = mq_send_session_connected_cb,
  .session_reset_callback = mq_send_session_reset_cb,
  .session_migrate_callback = mq_send_session_migrate_cb,
  .session_cleanup_callback = mq_send_session_cleanup_cb,
  .session_listened_callback = mq_send_session_bound_cb,
  .session_unlistened_callback = mq_send_unlisten_cb,
  .add_segment_callback = mq_send_add_segment_cb,
  .del_segment_callback = mq_send_del_segment_cb,
  .builtin_app_rx_callback = mq_send_io_rx_event,
  .builtin_app_tx_callback = mq_send_io_tx_event,
};

static void
vl_api_session_enable_disable_t_handler (vl_api_session_enable_disable_t *mp)
{
  vl_api_session_enable_disable_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;
  session_enable_disable_args_t args;

  args.is_en = mp->is_enable;
  if (mp->is_enable)
    args.rt_engine_type = RT_BACKEND_ENGINE_RULE_TABLE;
  else
    args.rt_engine_type = RT_BACKEND_ENGINE_DISABLE;

  if (vnet_session_enable_disable (vm, &args))
    rv = VNET_API_ERROR_INVALID_ARGUMENT;
  REPLY_MACRO (VL_API_SESSION_ENABLE_DISABLE_REPLY);
}

static void
vl_api_session_enable_disable_v2_t_handler (vl_api_session_enable_disable_v2_t *mp)
{
  vl_api_session_enable_disable_v2_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;
  session_enable_disable_args_t args;

  STATIC_ASSERT ((session_rt_engine_type_t) RT_BACKEND_ENGINE_API_DISABLE ==
		   RT_BACKEND_ENGINE_DISABLE,
		 "API value mismatch");
  STATIC_ASSERT ((session_rt_engine_type_t) RT_BACKEND_ENGINE_API_NONE == RT_BACKEND_ENGINE_NONE,
		 "API value mismatch");
  STATIC_ASSERT ((session_rt_engine_type_t) RT_BACKEND_ENGINE_API_RULE_TABLE ==
		   RT_BACKEND_ENGINE_RULE_TABLE,
		 "API value mismatch");
  STATIC_ASSERT ((session_rt_engine_type_t) RT_BACKEND_ENGINE_API_SDL == RT_BACKEND_ENGINE_SDL,
		 "API value mismatch");

  args.rt_engine_type = (session_rt_engine_type_t) mp->rt_engine_type;
  if (args.rt_engine_type == RT_BACKEND_ENGINE_DISABLE)
    args.is_en = 0;
  else
    args.is_en = 1;

  if (vnet_session_enable_disable (vm, &args))
    rv = VNET_API_ERROR_INVALID_VALUE;

  REPLY_MACRO (VL_API_SESSION_ENABLE_DISABLE_V2_REPLY);
}

static void
vl_api_session_sapi_enable_disable_t_handler (vl_api_session_sapi_enable_disable_t *mp)
{
  vl_api_session_sapi_enable_disable_reply_t *rmp;
  int rv = 0;

  rv = appns_sapi_enable_disable (mp->is_enable);
  REPLY_MACRO (VL_API_SESSION_SAPI_ENABLE_DISABLE_REPLY);
}

/* The socket and generated-BAPI front ends share the VPP-owned attachment
 * lifetime.  These are defined with the socket API implementation below. */
typedef struct sapi_observability_attachment_ sapi_observability_attachment_t;
static int
sapi_observability_attachment_create_for_bapi (app_worker_t *app_wrk, int *fd,
					       session_observability_descriptor_t *descriptor);
static int sapi_observability_attachment_control_for_bapi (
  u32 client_index, u32 association, const session_observability_descriptor_t *descriptor,
  session_observability_header_state_t state);
static void
sapi_observability_descriptor_to_api (vl_api_app_observability_attachment_descriptor_v2_t *dst,
				      const session_observability_descriptor_t *src);
static sapi_observability_attachment_t *
sapi_observability_attachment_find (u32 association,
				    const session_observability_descriptor_t *descriptor);
static void sapi_observability_attachment_destroy (sapi_observability_attachment_t *attachment);
int session_observability_dispatch_prepare_with_completion (
  session_observability_owner_t *owner, const session_observability_event_t *event,
  session_observability_dispatch_t *dispatch, session_observability_completion_fn_t completion,
  void *completion_context);

static void
vl_api_app_attach_t_handler (vl_api_app_attach_t *mp)
{
  int rv = 0, *fds = 0, n_fds = 0, n_workers, i;
  fifo_segment_t *segp, *rx_mqs_seg = 0;
  vnet_app_attach_args_t _a, *a = &_a;
  vl_api_app_attach_reply_t *rmp;
  u8 fd_flags = 0, ctrl_thread;
  vl_api_registration_t *reg;
  svm_msg_q_t *rx_mq;
  application_t *app;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  n_workers = vlib_num_workers ();
  if (!session_main_is_enabled () || appns_sapi_enabled ())
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }
  /* Only support binary api with socket transport */
  if (vl_api_registration_file_index (reg) == VL_API_INVALID_FI)
    {
      rv = VNET_API_ERROR_APP_UNSUPPORTED_CFG;
      goto done;
    }

  STATIC_ASSERT (sizeof (u64) * APP_OPTIONS_N_OPTIONS <= sizeof (mp->options),
		 "Out of options, fix api message definition");

  clib_memset (a, 0, sizeof (*a));
  a->api_client_index = mp->client_index;
  a->options = mp->options;
  a->session_cb_vft = &session_mq_cb_vft;
  a->namespace_id = vl_api_from_api_to_new_vec (mp, &mp->namespace_id);

  if ((rv = vnet_application_attach (a)))
    {
      clib_warning ("attach returned: %U", format_session_error, rv);
      rv = VNET_API_ERROR_UNSPECIFIED;
      vec_free (a->namespace_id);
      goto done;
    }
  vec_free (a->namespace_id);

  vec_validate (fds, 3 /* segs + tx evtfd */ + n_workers);

  /* Send rx mqs segment */
  app = application_get (a->app_index);
  rx_mqs_seg = application_get_rx_mqs_segment (app);

  fd_flags |= SESSION_FD_F_VPP_MQ_SEGMENT;
  fds[n_fds] = rx_mqs_seg->ssvm.fd;
  n_fds += 1;

  /* Send fifo segment fd if needed */
  if (ssvm_type (a->segment) == SSVM_SEGMENT_MEMFD)
    {
      fd_flags |= SESSION_FD_F_MEMFD_SEGMENT;
      fds[n_fds] = a->segment->fd;
      n_fds += 1;
    }
  if (a->options[APP_OPTIONS_FLAGS] & APP_OPTIONS_FLAGS_EVT_MQ_USE_EVENTFD)
    {
      fd_flags |= SESSION_FD_F_MQ_EVENTFD;
      fds[n_fds] = svm_msg_q_get_eventfd (a->app_evt_q);
      n_fds += 1;
    }

  if (application_use_private_rx_mqs ())
    {
      fd_flags |= SESSION_FD_F_VPP_MQ_EVENTFD;
      for (i = 0; i < n_workers + 1; i++)
	{
	  rx_mq = application_rx_mq_get (app, i);
	  fds[n_fds] = svm_msg_q_get_eventfd (rx_mq);
	  n_fds += 1;
	}
    }

done:
  REPLY_MACRO3 (VL_API_APP_ATTACH_REPLY,
		((!rv) ? vec_len (((fifo_segment_t *) a->segment)->ssvm.name) : 0), ({
		  if (!rv)
		    {
		      ctrl_thread = n_workers ? 1 : 0;
		      segp = (fifo_segment_t *) a->segment;
		      rmp->app_index = clib_host_to_net_u32 (a->app_index);
		      rmp->app_mq = fifo_segment_msg_q_offset (segp, 0);
		      rmp->vpp_ctrl_mq = fifo_segment_msg_q_offset (rx_mqs_seg, ctrl_thread);
		      rmp->vpp_ctrl_mq_thread = ctrl_thread;
		      rmp->n_fds = n_fds;
		      rmp->fd_flags = fd_flags;
		      if (vec_len (segp->ssvm.name))
			{
			  vl_api_vec_to_api_string (segp->ssvm.name, &rmp->segment_name);
			}
		      rmp->segment_size = segp->ssvm.ssvm_size;
		      rmp->segment_handle = clib_host_to_net_u64 (a->segment_handle);
		    }
		}));

  if (n_fds)
    session_send_fds (reg, fds, n_fds);
  vec_free (fds);
}

static void
vl_api_app_worker_add_del_t_handler (vl_api_app_worker_add_del_t *mp)
{
  int rv = 0, fds[SESSION_N_FD_TYPE], n_fds = 0;
  vl_api_app_worker_add_del_reply_t *rmp;
  vl_api_registration_t *reg;
  application_t *app;
  u8 fd_flags = 0;

  if (!session_main_is_enabled () || appns_sapi_enabled ())
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  app = application_get_if_valid (clib_net_to_host_u32 (mp->app_index));
  if (!app)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  vnet_app_worker_add_del_args_t args = { .app_index = app->app_index,
					  .wrk_map_index = clib_net_to_host_u32 (mp->wrk_index),
					  .api_client_index = mp->client_index,
					  .is_add = mp->is_add };
  rv = vnet_app_worker_add_del (&args);
  if (rv)
    {
      clib_warning ("app worker add/del returned: %U", format_session_error, rv);
      rv = VNET_API_ERROR_UNSPECIFIED;
      goto done;
    }

  if (!mp->is_add)
    goto done;

  /* Send fifo segment fd if needed */
  if (ssvm_type (args.segment) == SSVM_SEGMENT_MEMFD)
    {
      fd_flags |= SESSION_FD_F_MEMFD_SEGMENT;
      fds[n_fds] = args.segment->fd;
      n_fds += 1;
    }
  if (application_segment_manager_properties (app)->use_mq_eventfd)
    {
      fd_flags |= SESSION_FD_F_MQ_EVENTFD;
      fds[n_fds] = svm_msg_q_get_eventfd (args.evt_q);
      n_fds += 1;
    }

done:
  REPLY_MACRO3 (VL_API_APP_WORKER_ADD_DEL_REPLY,
		((!rv && mp->is_add) ? vec_len (args.segment->name) : 0), ({
		  rmp->is_add = mp->is_add;
		  rmp->wrk_index = mp->wrk_index;
		  if (!rv && mp->is_add)
		    {
		      rmp->wrk_index = clib_host_to_net_u32 (args.wrk_map_index);
		      rmp->segment_handle = clib_host_to_net_u64 (args.segment_handle);
		      rmp->app_event_queue_address =
			fifo_segment_msg_q_offset ((fifo_segment_t *) args.segment, 0);
		      rmp->n_fds = n_fds;
		      rmp->fd_flags = fd_flags;
		      if (vec_len (args.segment->name))
			{
			  vl_api_vec_to_api_string (args.segment->name, &rmp->segment_name);
			}
		    }
		}));

  if (n_fds)
    session_send_fds (reg, fds, n_fds);
}

static void
vl_api_app_attach_v2_t_handler (vl_api_app_attach_v2_t *mp)
{
  int rv = 0, *fds = 0, n_fds = 0, n_workers, i, attachment_fd = -1;
  fifo_segment_t *segp = 0, *rx_mqs_seg = 0;
  vnet_app_attach_args_t args = { 0 };
  vl_api_app_attach_v2_reply_t *rmp;
  vl_api_registration_t *reg;
  application_t *app;
  app_worker_t *app_wrk;
  session_observability_descriptor_t descriptor = { 0 };
  u8 fd_flags = 0, ctrl_thread = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  n_workers = vlib_num_workers ();
  if (!session_main_is_enabled () || appns_sapi_enabled ())
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }
  if (vl_api_registration_file_index (reg) == VL_API_INVALID_FI ||
      clib_net_to_host_u16 (mp->observability_abi) != SESSION_OBSERVABILITY_ABI_VERSION ||
      mp->observability_flags)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  args.api_client_index = mp->client_index;
  args.options = mp->options;
  args.session_cb_vft = &session_mq_cb_vft;
  args.namespace_id = vl_api_from_api_to_new_vec (mp, &mp->namespace_id);
  rv = vnet_application_attach (&args);
  vec_free (args.namespace_id);
  if (rv)
    {
      rv = VNET_API_ERROR_UNSPECIFIED;
      goto done;
    }

  app = application_get (args.app_index);
  app_wrk = application_get_worker (app, 0);
  if (!app_wrk ||
      sapi_observability_attachment_create_for_bapi (app_wrk, &attachment_fd, &descriptor))
    {
      vnet_app_detach_args_t detach_args = {
	.app_index = args.app_index,
	.api_client_index = mp->client_index,
      };

      vnet_application_detach (&detach_args);
      rv = VNET_API_ERROR_UNSPECIFIED;
      goto done;
    }
  vec_validate (fds, 4 + n_workers);
  rx_mqs_seg = application_get_rx_mqs_segment (app);
  fd_flags |= SESSION_FD_F_VPP_MQ_SEGMENT;
  fds[n_fds++] = rx_mqs_seg->ssvm.fd;
  if (ssvm_type (args.segment) == SSVM_SEGMENT_MEMFD)
    {
      fd_flags |= SESSION_FD_F_MEMFD_SEGMENT;
      fds[n_fds++] = args.segment->fd;
    }
  fd_flags |= SESSION_FD_F_OBSERVABILITY_ATTACHMENT;
  fds[n_fds++] = attachment_fd;
  if (args.options[APP_OPTIONS_FLAGS] & APP_OPTIONS_FLAGS_EVT_MQ_USE_EVENTFD)
    {
      fd_flags |= SESSION_FD_F_MQ_EVENTFD;
      fds[n_fds++] = svm_msg_q_get_eventfd (args.app_evt_q);
    }
  if (application_use_private_rx_mqs ())
    {
      fd_flags |= SESSION_FD_F_VPP_MQ_EVENTFD;
      for (i = 0; i < n_workers + 1; i++)
	fds[n_fds++] = svm_msg_q_get_eventfd (application_rx_mq_get (app, i));
    }

done:
  REPLY_MACRO3 (
    VL_API_APP_ATTACH_V2_REPLY,
    (!rv && args.segment ? vec_len (((fifo_segment_t *) args.segment)->ssvm.name) : 0), ({
      rmp->observability_abi = clib_host_to_net_u16 (SESSION_OBSERVABILITY_ABI_VERSION);
      if (!rv)
	{
	  ctrl_thread = n_workers ? 1 : 0;
	  segp = (fifo_segment_t *) args.segment;
	  rmp->app_index = clib_host_to_net_u32 (args.app_index);
	  rmp->app_mq = fifo_segment_msg_q_offset (segp, 0);
	  rmp->vpp_ctrl_mq = fifo_segment_msg_q_offset (rx_mqs_seg, ctrl_thread);
	  rmp->vpp_ctrl_mq_thread = ctrl_thread;
	  rmp->n_fds = n_fds;
	  rmp->fd_flags = fd_flags;
	  rmp->segment_size = segp->ssvm.ssvm_size;
	  rmp->segment_handle = clib_host_to_net_u64 (args.segment_handle);
	  rmp->vcl_application_association =
	    clib_host_to_net_u32 (app_wrk->observability_association);
	  sapi_observability_descriptor_to_api (&rmp->attachment_descriptor, &descriptor);
	  if (vec_len (segp->ssvm.name))
	    vl_api_vec_to_api_string (segp->ssvm.name, &rmp->segment_name);
	}
    }));
  if (n_fds)
    session_send_fds (reg, fds, n_fds);
  vec_free (fds);
}

static void
vl_api_app_worker_add_del_v2_t_handler (vl_api_app_worker_add_del_v2_t *mp)
{
  int rv = 0, n_fds = 0, attachment_fd = -1;
  int fds[SESSION_N_FD_TYPE];
  vl_api_app_worker_add_del_v2_reply_t *rmp;
  vl_api_registration_t *reg;
  application_t *app;
  app_worker_t *app_wrk = 0;
  vnet_app_worker_add_del_args_t args = { 0 };
  session_observability_descriptor_t descriptor = { 0 };
  u8 fd_flags = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  if (!session_main_is_enabled () || appns_sapi_enabled () ||
      vl_api_registration_file_index (reg) == VL_API_INVALID_FI ||
      clib_net_to_host_u16 (mp->observability_abi) != SESSION_OBSERVABILITY_ABI_VERSION ||
      mp->observability_flags)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  app = application_get_if_valid (clib_net_to_host_u32 (mp->app_index));
  if (!app || application_lookup (mp->client_index) != app)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  args.app_index = app->app_index;
  args.wrk_map_index = clib_net_to_host_u32 (mp->wrk_index);
  args.api_client_index = mp->client_index;
  args.is_add = mp->is_add;
  if ((rv = vnet_app_worker_add_del (&args)))
    {
      rv = VNET_API_ERROR_UNSPECIFIED;
      goto done;
    }
  if (!mp->is_add)
    goto done;
  app_wrk = application_get_worker (app, args.wrk_map_index);
  if (sapi_observability_attachment_create_for_bapi (app_wrk, &attachment_fd, &descriptor))
    {
      args.is_add = 0;
      (void) vnet_app_worker_add_del (&args);
      rv = VNET_API_ERROR_UNSPECIFIED;
      goto done;
    }
  if (ssvm_type (args.segment) == SSVM_SEGMENT_MEMFD)
    {
      fd_flags |= SESSION_FD_F_MEMFD_SEGMENT;
      fds[n_fds++] = args.segment->fd;
    }
  fd_flags |= SESSION_FD_F_OBSERVABILITY_ATTACHMENT;
  fds[n_fds++] = attachment_fd;
  if (application_segment_manager_properties (app)->use_mq_eventfd)
    {
      fd_flags |= SESSION_FD_F_MQ_EVENTFD;
      fds[n_fds++] = svm_msg_q_get_eventfd (args.evt_q);
    }

done:
  REPLY_MACRO3 (
    VL_API_APP_WORKER_ADD_DEL_V2_REPLY, (!rv && mp->is_add ? vec_len (args.segment->name) : 0), ({
      rmp->is_add = mp->is_add;
      rmp->wrk_index = mp->wrk_index;
      rmp->observability_abi = clib_host_to_net_u16 (SESSION_OBSERVABILITY_ABI_VERSION);
      if (!rv && mp->is_add)
	{
	  rmp->wrk_index = clib_host_to_net_u32 (args.wrk_map_index);
	  rmp->segment_handle = clib_host_to_net_u64 (args.segment_handle);
	  rmp->app_event_queue_address =
	    fifo_segment_msg_q_offset ((fifo_segment_t *) args.segment, 0);
	  rmp->n_fds = n_fds;
	  rmp->fd_flags = fd_flags;
	  rmp->vcl_application_association =
	    clib_host_to_net_u32 (app_wrk->observability_association);
	  sapi_observability_descriptor_to_api (&rmp->attachment_descriptor, &descriptor);
	  if (vec_len (args.segment->name))
	    vl_api_vec_to_api_string (args.segment->name, &rmp->segment_name);
	}
    }));
  if (n_fds)
    session_send_fds (reg, fds, n_fds);
}

static void
vl_api_app_observability_control_v2_t_handler_common (
  u32 client_index, u32 association,
  const vl_api_app_observability_attachment_descriptor_v2_t *api_descriptor,
  session_observability_header_state_t state, i32 *rv)
{
  session_observability_descriptor_t descriptor = {
    .abi = clib_net_to_host_u16 (api_descriptor->abi),
    .bytes = clib_net_to_host_u16 (api_descriptor->bytes),
    .layout_hash = clib_net_to_host_u32 (api_descriptor->layout_hash),
    .segment_handle = clib_net_to_host_u64 (api_descriptor->segment_handle),
    .attachment_instance = clib_net_to_host_u64 (api_descriptor->attachment_instance),
    .attach_generation = clib_net_to_host_u64 (api_descriptor->attach_generation),
    .queue_identity = clib_net_to_host_u64 (api_descriptor->queue_identity),
    .queue_generation = clib_net_to_host_u64 (api_descriptor->queue_generation),
    .segment_bytes = clib_net_to_host_u32 (api_descriptor->segment_bytes),
    .binding_index = clib_net_to_host_u32 (api_descriptor->binding_index),
    .binding_nonce = clib_net_to_host_u64 (api_descriptor->binding_nonce),
  };

  if (sapi_observability_attachment_control_for_bapi (client_index, association, &descriptor,
						      state))
    *rv = VNET_API_ERROR_INVALID_VALUE;
}

static void
vl_api_app_observability_attach_ack_v2_t_handler (vl_api_app_observability_attach_ack_v2_t *mp)
{
  vl_api_app_observability_attach_ack_v2_reply_t *rmp;
  i32 rv = 0;

  vl_api_app_observability_control_v2_t_handler_common (
    mp->client_index, clib_net_to_host_u32 (mp->vcl_application_association),
    &mp->attachment_descriptor, SESSION_OBSERVABILITY_HEADER_MAP_VALID, &rv);
  REPLY_MACRO2 (VL_API_APP_OBSERVABILITY_ATTACH_ACK_V2_REPLY,
		({ rmp->vcl_application_association = mp->vcl_application_association; }));
}

static void
vl_api_app_observability_detach_v2_t_handler (vl_api_app_observability_detach_v2_t *mp)
{
  vl_api_app_observability_detach_v2_reply_t *rmp;
  i32 rv = 0;

  vl_api_app_observability_control_v2_t_handler_common (
    mp->client_index, clib_net_to_host_u32 (mp->vcl_application_association),
    &mp->attachment_descriptor, SESSION_OBSERVABILITY_HEADER_DETACHING, &rv);
  REPLY_MACRO2 (VL_API_APP_OBSERVABILITY_DETACH_V2_REPLY,
		({ rmp->vcl_application_association = mp->vcl_application_association; }));
}

static void
vl_api_app_observability_done_v2_t_handler (vl_api_app_observability_done_v2_t *mp)
{
  vl_api_app_observability_done_v2_reply_t *rmp;
  i32 rv = 0;

  vl_api_app_observability_control_v2_t_handler_common (
    mp->client_index, clib_net_to_host_u32 (mp->vcl_application_association),
    &mp->attachment_descriptor, SESSION_OBSERVABILITY_HEADER_DEAD, &rv);
  REPLY_MACRO2 (VL_API_APP_OBSERVABILITY_DONE_V2_REPLY,
		({ rmp->vcl_application_association = mp->vcl_application_association; }));
  if (!rv)
    sapi_observability_attachment_destroy (sapi_observability_attachment_find (
      clib_net_to_host_u32 (mp->vcl_application_association), 0));
}

static void
vl_api_application_detach_t_handler (vl_api_application_detach_t *mp)
{
  vl_api_application_detach_reply_t *rmp;
  int rv = VNET_API_ERROR_INVALID_VALUE_2;
  vnet_app_detach_args_t _a, *a = &_a;
  application_t *app;

  if (!session_main_is_enabled () || appns_sapi_enabled ())
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      a->app_index = app->app_index;
      a->api_client_index = mp->client_index;
      rv = vnet_application_detach (a);
      if (rv)
	{
	  clib_warning ("vnet_application_detach: %U", format_session_error, rv);
	  rv = VNET_API_ERROR_UNSPECIFIED;
	}
    }

done:
  REPLY_MACRO (VL_API_APPLICATION_DETACH_REPLY);
}

static int
session_observability_admission_gate_get (session_observability_directory_t *d)
{
  u32 current, next;

  do
    {
      current = clib_atomic_load_acq_n (&d->admission_gate);
      if ((current & SESSION_OBSERVABILITY_ADMISSION_CLOSED) ||
	  (current & SESSION_OBSERVABILITY_ADMISSION_COUNT_MASK) ==
	    SESSION_OBSERVABILITY_ADMISSION_COUNT_MASK)
	return -1;
      next = current + 1;
    }
  while (!clib_atomic_cmp_and_swap_acq_relax_n (&d->admission_gate, &current, next, 0));
  return 0;
}

static int
session_observability_owner_get (session_observability_owner_t *owner)
{
  u32 current, next;

  do
    {
      if (clib_atomic_load_acq_n (&owner->fenced))
	return -1;
      current = clib_atomic_load_acq_n (&owner->references);
      if (!current)
	return -1;
      next = current + 1;
    }
  while (!clib_atomic_cmp_and_swap_acq_relax_n (&owner->references, &current, next, 0));
  return 0;
}

static void
session_observability_producer_release (session_observability_admission_t *a)
{
  session_observability_directory_t *d = a->directory;

  clib_atomic_fetch_sub_rel (&d->admission_gate, 1);
  clib_atomic_fetch_sub_rel (&d->admissions, 1);
  clib_atomic_fetch_sub_rel (&d->reservations, 1);
  clib_atomic_fetch_sub_rel (&d->references, 1);
  clib_atomic_fetch_sub_rel (&a->cell->references, 1);
  clib_atomic_fetch_sub_rel (&a->cell->cell_references, 1);
  clib_atomic_store_rel_n (&a->cell->admission_pin, 0);
  clib_atomic_store_rel_n (&a->cell->reservation_pin, 0);
  clib_atomic_fetch_sub_rel (&a->sidecar->references, 1);
  clib_memset (a->sidecar, 0, sizeof (*a->sidecar));
  clib_atomic_store_rel_n (&a->sidecar->ticket_state, SESSION_OBSERVABILITY_TICKET_FREE);
  if (!clib_atomic_load_acq_n (&d->references))
    {
      clib_memset (d, 0, sizeof (*d));
      clib_atomic_store_rel_n (&d->lifecycle, SESSION_OBSERVABILITY_DIRECTORY_FREE);
    }
  session_observability_owner_release (a->owner);
}

static session_observability_result_t
session_observability_queue_result (svm_msg_q_observability_reservation_result_t rv)
{
  switch (rv)
    {
    case SVM_MSG_Q_OBSERVABILITY_BUSY:
      return SESSION_OBSERVABILITY_RESULT_QUEUE_BUSY;
    case SVM_MSG_Q_OBSERVABILITY_DESCRIPTOR_FULL:
      return SESSION_OBSERVABILITY_RESULT_DESCRIPTOR_FULL;
    case SVM_MSG_Q_OBSERVABILITY_RING_FULL:
      return SESSION_OBSERVABILITY_RESULT_RING_FULL;
    case SVM_MSG_Q_OBSERVABILITY_OWNER_DEAD:
      return SESSION_OBSERVABILITY_RESULT_OWNER_DEAD;
    default:
      return SESSION_OBSERVABILITY_RESULT_QUEUE_BROKEN;
    }
}

static void
vl_api_app_observability_request_v2_t_handler (vl_api_app_observability_request_v2_t *mp)
{
  vl_api_app_observability_request_v2_reply_t *rmp;
  app_worker_t *app_wrk;
  application_t *app;
  session_observability_segment_t *segment;
  session_observability_directory_t *directory;
  session_observability_admission_t admission = { 0 };
  svm_msg_q_observability_ticket_t queue_ticket;
  session_observability_dispatch_t dispatch = { 0 };
  svm_msg_q_msg_t msg;
  svm_msg_q_observability_reservation_result_t queue_rv;
  session_handle_t session_handle;
  u64 token, request_id, ticket = 0;
  u32 association, slot = 0, expected;
  int rv = VNET_API_ERROR_INVALID_VALUE;

  app = application_lookup (mp->client_index);
  if (!app)
    goto done;
  association = clib_net_to_host_u32 (mp->application_association);
  app_wrk = application_get_worker (app, 0);
  if (!app_wrk || !app_wrk->observability_owner ||
      app_wrk->observability_association != association)
    goto done;
  segment = app_wrk->observability_segment;
  if (!segment ||
      clib_atomic_load_acq_n (&segment->header.lifecycle) != SESSION_OBSERVABILITY_HEADER_MAP_VALID)
    goto done;
  slot = clib_net_to_host_u32 (mp->attachment_slot);
  if (slot >= SESSION_OBSERVABILITY_SLOT_COUNT)
    goto done;
  session_handle = clib_net_to_host_u64 (mp->session_handle);
  token = clib_net_to_host_u64 (mp->association_token);
  request_id = clib_net_to_host_u64 (mp->request_id);
  ticket = clib_atomic_fetch_add_rel (&segment->header.ticket_sequence_next, 1);
  if (!ticket || !token)
    goto done;

  admission.owner = app_wrk->observability_owner;
  admission.directory = directory = &segment->directory[slot];
  admission.cell = &segment->cell[slot];
  admission.sidecar = &segment->sidecar[slot];
  admission.event = (session_observability_event_t){
    .opcode = 1,
    .abi = SESSION_OBSERVABILITY_ABI_VERSION,
    .attachment_slot = slot,
    .allocation_nonce = ticket,
    .association_token = token,
    .session_handle = session_handle,
    .directory_nonce = ticket,
    .attachment_instance = segment->header.attachment_instance,
    .binding_generation = segment->header.attach_generation,
    .request_id = request_id,
    .owner_thread = ((session_handle_tu_t){ .handle = session_handle }).thread_index,
    .vcl_application_association = association,
    .ticket_sequence = ticket,
  };

  expected = SESSION_OBSERVABILITY_DIRECTORY_FREE;
  if (clib_atomic_cmp_and_swap_acq_relax_n (&directory->lifecycle, &expected,
					    SESSION_OBSERVABILITY_DIRECTORY_INITIALIZING, 0))
    {
      clib_memset (directory, 0, sizeof (*directory));
      directory->entry_nonce = ticket;
      directory->association_token = token;
      directory->session_handle = session_handle;
      directory->attachment_instance = admission.event.attachment_instance;
      directory->binding_generation = admission.event.binding_generation;
      directory->owner_thread = admission.event.owner_thread;
      directory->vcl_application_association = association;
      clib_atomic_store_rel_n (&directory->lifecycle, SESSION_OBSERVABILITY_DIRECTORY_LIVE);
    }
  else if (expected != SESSION_OBSERVABILITY_DIRECTORY_LIVE ||
	   directory->association_token != token || directory->session_handle != session_handle ||
	   directory->attachment_instance != admission.event.attachment_instance ||
	   directory->binding_generation != admission.event.binding_generation ||
	   directory->owner_thread != admission.event.owner_thread ||
	   directory->vcl_application_association != association)
    goto done;
  admission.event.directory_nonce = directory->entry_nonce;
  if (session_observability_admission_gate_get (directory))
    goto done;
  if (session_observability_owner_get (admission.owner))
    {
      clib_atomic_fetch_sub_rel (&directory->admission_gate, 1);
      goto done;
    }

  expected = SESSION_OBSERVABILITY_CELL_FREE;
  if (!clib_atomic_cmp_and_swap_acq_relax_n (&admission.cell->cell_state, &expected,
					     SESSION_OBSERVABILITY_CELL_INITIALIZING, 0))
    {
      if (expected != SESSION_OBSERVABILITY_CELL_COMPLETED ||
	  clib_atomic_load_acq_n (&admission.cell->references) ||
	  clib_atomic_load_acq_n (&admission.sidecar->references) ||
	  clib_atomic_load_acq_n (&admission.sidecar->ticket_state) !=
	    SESSION_OBSERVABILITY_TICKET_FREE)
	{
	  clib_atomic_fetch_sub_rel (&directory->admission_gate, 1);
	  session_observability_owner_release (admission.owner);
	  goto done;
	}
    }

  clib_memset (admission.cell, 0, sizeof (*admission.cell));
  clib_memset (admission.sidecar, 0, sizeof (*admission.sidecar));
  admission.cell->allocation_nonce = ticket;
  admission.cell->request_id = request_id;
  admission.cell->directory_nonce = admission.event.directory_nonce;
  admission.cell->attachment_instance = admission.event.attachment_instance;
  admission.cell->binding_generation = admission.event.binding_generation;
  admission.cell->association_token = token;
  admission.cell->session_handle = session_handle;
  admission.cell->owner_thread = admission.event.owner_thread;
  admission.cell->request_vcl_application_association = association;
  admission.cell->ticket_sequence = ticket;
  admission.sidecar->queue_identity = segment->header.queue_identity;
  admission.sidecar->queue_generation = segment->header.queue_generation;
  admission.sidecar->ticket_sequence = ticket;
  admission.sidecar->allocation_nonce = ticket;
  admission.sidecar->directory_nonce = admission.event.directory_nonce;
  admission.sidecar->attachment_instance = admission.event.attachment_instance;
  admission.sidecar->binding_generation = admission.event.binding_generation;
  admission.sidecar->attachment_slot = slot;
  clib_atomic_store_rel_n (&directory->admissions, 1);
  clib_atomic_store_rel_n (&directory->reservations, 1);
  clib_atomic_store_rel_n (&directory->references, 1);
  clib_atomic_store_rel_n (&admission.cell->references, 1);
  clib_atomic_store_rel_n (&admission.cell->cell_references, 1);
  clib_atomic_store_rel_n (&admission.cell->admission_pin, 1);
  clib_atomic_store_rel_n (&admission.cell->reservation_pin, 1);
  clib_atomic_store_rel_n (&admission.sidecar->references, 1);
  clib_atomic_store_rel_n (&admission.sidecar->ticket_state,
			   SESSION_OBSERVABILITY_TICKET_LOCAL_RESERVED);
  clib_atomic_store_rel_n (&admission.cell->cell_state, SESSION_OBSERVABILITY_CELL_RESERVED);
  queue_ticket = (svm_msg_q_observability_ticket_t){
    .state = &admission.sidecar->ticket_state,
    .cancellation = &admission.cell->cancellation,
    .ring_index = &admission.sidecar->ring_index,
    .ring_element_index = &admission.sidecar->ring_element_index,
    .descriptor_element_index = &admission.sidecar->descriptor_element_index,
  };
  if (session_observability_dispatch_prepare (admission.owner, &admission.event, &dispatch))
    {
      session_observability_cell_complete (admission.cell,
					   SESSION_OBSERVABILITY_RESULT_QUEUE_BROKEN);
      session_observability_producer_release (&admission);
      goto done;
    }
  queue_rv = svm_msg_q_observability_try_reserve_commit (
    admission.owner->queue, 0, &queue_ticket, &admission.event, sizeof (admission.event), &msg);
  if (queue_rv != SVM_MSG_Q_OBSERVABILITY_COMMITTED_NOTIFIED &&
      queue_rv != SVM_MSG_Q_OBSERVABILITY_COMMITTED_NOTIFY_DEFERRED)
    {
      session_observability_cell_complete (admission.cell,
					   session_observability_queue_result (queue_rv));
      session_observability_dispatch_cancel (&dispatch);
      session_observability_producer_release (&admission);
      goto done;
    }
  clib_atomic_store_rel_n (&admission.cell->cell_state, SESSION_OBSERVABILITY_CELL_QUEUED);
  if (session_observability_dispatch_commit (&dispatch))
    {
      /* The ticket is already visible.  Cancellation wins the callback
       * boundary and the owner node drains/releases it after prior RPCs. */
      (void) svm_msg_q_observability_cancel (&queue_ticket);
      session_observability_dispatch_retry (&dispatch);
      rv = VNET_API_ERROR_QUEUE_FULL;
      goto done;
    }
  rv = 0;

done:
  REPLY_MACRO2 (VL_API_APP_OBSERVABILITY_REQUEST_V2_REPLY, ({
		  rmp->attachment_slot = clib_host_to_net_u32 (slot);
		  rmp->ticket_sequence = clib_host_to_net_u64 (ticket);
		}));
}

static void
vl_api_app_namespace_add_del_t_handler (vl_api_app_namespace_add_del_t *mp)
{
  vl_api_app_namespace_add_del_reply_t *rmp;
  u32 appns_index = 0;
  u8 *ns_id = 0;
  int rv = 0;
  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  ns_id = vl_api_from_api_to_new_vec (mp, &mp->namespace_id);

  vnet_app_namespace_add_del_args_t args = { .ns_id = ns_id,
					     .sock_name = 0,
					     .secret = clib_net_to_host_u64 (mp->secret),
					     .sw_if_index = clib_net_to_host_u32 (mp->sw_if_index),
					     .ip4_fib_id = clib_net_to_host_u32 (mp->ip4_fib_id),
					     .ip6_fib_id = clib_net_to_host_u32 (mp->ip6_fib_id),
					     .is_add = 1 };
  rv = vnet_app_namespace_add_del (&args);
  if (!rv)
    {
      appns_index = app_namespace_index_from_id (ns_id);
      if (appns_index == APP_NAMESPACE_INVALID_INDEX)
	{
	  clib_warning ("app ns lookup failed");
	  rv = VNET_API_ERROR_UNSPECIFIED;
	}
    }
  vec_free (ns_id);

done:
  REPLY_MACRO2 (VL_API_APP_NAMESPACE_ADD_DEL_REPLY, ({
		  if (!rv)
		    rmp->appns_index = clib_host_to_net_u32 (appns_index);
		}));
}

static void
vl_api_app_namespace_add_del_v2_t_handler (vl_api_app_namespace_add_del_v2_t *mp)
{
  vl_api_app_namespace_add_del_v2_reply_t *rmp;
  u8 *ns_id = 0;
  u32 appns_index = 0;
  int rv = 0;

  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  mp->namespace_id[sizeof (mp->namespace_id) - 1] = 0;
  ns_id = format (0, "%s", &mp->namespace_id);

  vnet_app_namespace_add_del_args_t args = { .ns_id = ns_id,
					     .sock_name = 0,
					     .secret = clib_net_to_host_u64 (mp->secret),
					     .sw_if_index = clib_net_to_host_u32 (mp->sw_if_index),
					     .ip4_fib_id = clib_net_to_host_u32 (mp->ip4_fib_id),
					     .ip6_fib_id = clib_net_to_host_u32 (mp->ip6_fib_id),
					     .is_add = 1 };
  rv = vnet_app_namespace_add_del (&args);
  if (!rv)
    {
      appns_index = app_namespace_index_from_id (ns_id);
      if (appns_index == APP_NAMESPACE_INVALID_INDEX)
	{
	  clib_warning ("app ns lookup failed id:%s", ns_id);
	  rv = VNET_API_ERROR_UNSPECIFIED;
	}
    }
  vec_free (ns_id);

done:
  REPLY_MACRO2 (VL_API_APP_NAMESPACE_ADD_DEL_V2_REPLY, ({
		  if (!rv)
		    rmp->appns_index = clib_host_to_net_u32 (appns_index);
		}));
}

static void
vl_api_app_namespace_add_del_v4_t_handler (vl_api_app_namespace_add_del_v4_t *mp)
{
  vl_api_app_namespace_add_del_v4_reply_t *rmp;
  u8 *ns_id = 0, *sock_name = 0;
  u32 appns_index = 0;
  int rv = 0;
  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }
  mp->namespace_id[sizeof (mp->namespace_id) - 1] = 0;
  ns_id = format (0, "%s", &mp->namespace_id);
  sock_name = vl_api_from_api_to_new_vec (mp, &mp->sock_name);
  vnet_app_namespace_add_del_args_t args = {
    .ns_id = ns_id,
    .sock_name = sock_name,
    .secret = clib_net_to_host_u64 (mp->secret),
    .sw_if_index = clib_net_to_host_u32 (mp->sw_if_index),
    .ip4_fib_id = clib_net_to_host_u32 (mp->ip4_fib_id),
    .ip6_fib_id = clib_net_to_host_u32 (mp->ip6_fib_id),
    .is_add = mp->is_add,
  };
  rv = vnet_app_namespace_add_del (&args);
  if (!rv && mp->is_add)
    {
      appns_index = app_namespace_index_from_id (ns_id);
      if (appns_index == APP_NAMESPACE_INVALID_INDEX)
	{
	  clib_warning ("app ns lookup failed id:%s", ns_id);
	  rv = VNET_API_ERROR_UNSPECIFIED;
	}
    }
  vec_free (ns_id);
  vec_free (sock_name);
done:
  REPLY_MACRO2 (VL_API_APP_NAMESPACE_ADD_DEL_V4_REPLY, ({
		  if (!rv)
		    rmp->appns_index = clib_host_to_net_u32 (appns_index);
		}));
}

static void
vl_api_app_namespace_add_del_v3_t_handler (vl_api_app_namespace_add_del_v3_t *mp)
{
  vl_api_app_namespace_add_del_v3_reply_t *rmp;
  u8 *ns_id = 0, *sock_name = 0, *api_sock_name = 0;
  u32 appns_index = 0;
  int rv = 0;
  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }
  mp->namespace_id[sizeof (mp->namespace_id) - 1] = 0;
  ns_id = format (0, "%s", &mp->namespace_id);
  api_sock_name = vl_api_from_api_to_new_vec (mp, &mp->sock_name);
  mp->netns[sizeof (mp->netns) - 1] = 0;
  if (strlen ((char *) mp->netns) != 0)
    {
      sock_name = format (0, "abstract:%v,netns_name=%s", api_sock_name, &mp->netns);
    }
  else
    {
      sock_name = api_sock_name;
      api_sock_name = 0; // for vec_free
    }

  vnet_app_namespace_add_del_args_t args = {
    .ns_id = ns_id,
    .sock_name = sock_name,
    .secret = clib_net_to_host_u64 (mp->secret),
    .sw_if_index = clib_net_to_host_u32 (mp->sw_if_index),
    .ip4_fib_id = clib_net_to_host_u32 (mp->ip4_fib_id),
    .ip6_fib_id = clib_net_to_host_u32 (mp->ip6_fib_id),
    .is_add = mp->is_add,
  };
  rv = vnet_app_namespace_add_del (&args);
  if (!rv && mp->is_add)
    {
      appns_index = app_namespace_index_from_id (ns_id);
      if (appns_index == APP_NAMESPACE_INVALID_INDEX)
	{
	  clib_warning ("app ns lookup failed id:%s", ns_id);
	  rv = VNET_API_ERROR_UNSPECIFIED;
	}
    }
  vec_free (ns_id);
  vec_free (sock_name);
  vec_free (api_sock_name);
done:
  REPLY_MACRO2 (VL_API_APP_NAMESPACE_ADD_DEL_V3_REPLY, ({
		  if (!rv)
		    rmp->appns_index = clib_host_to_net_u32 (appns_index);
		}));
}

static void
vl_api_session_rule_add_del_t_handler (vl_api_session_rule_add_del_t *mp)
{
  vl_api_session_rule_add_del_reply_t *rmp;
  session_rule_add_del_args_t args;
  session_rule_table_add_del_args_t *table_args = &args.table_args;
  int rv = 0;

  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  clib_memset (&args, 0, sizeof (args));

  ip_prefix_decode (&mp->lcl, &table_args->lcl);
  ip_prefix_decode (&mp->rmt, &table_args->rmt);

  table_args->lcl_port = clib_net_to_host_u16 (mp->lcl_port);
  table_args->rmt_port = clib_net_to_host_u16 (mp->rmt_port);
  table_args->action_index = clib_net_to_host_u32 (mp->action_index);
  table_args->is_add = mp->is_add;
  mp->tag[sizeof (mp->tag) - 1] = 0;
  table_args->tag = format (0, "%s", mp->tag);
  args.appns_index = clib_net_to_host_u32 (mp->appns_index);
  args.scope = mp->scope;
  args.transport_proto =
    api_session_transport_proto_decode (&mp->transport_proto) == TRANSPORT_PROTO_UDP ? 1 : 0;

  rv = vnet_session_rule_add_del (&args);
  if (rv)
    {
      clib_warning ("rule add del returned: %U", format_session_error, rv);
      rv = VNET_API_ERROR_UNSPECIFIED;
    }
  vec_free (table_args->tag);
done:
  REPLY_MACRO (VL_API_SESSION_RULE_ADD_DEL_REPLY);
}

static void
send_session_rule_details4 (mma_rule_16_t *rule, u8 is_local, u8 transport_proto, u32 appns_index,
			    u8 *tag, vl_api_registration_t *reg, u32 context)
{
  vl_api_session_rules_details_t *rmp = 0;
  session_mask_or_match_4_t *match = (session_mask_or_match_4_t *) &rule->match;
  session_mask_or_match_4_t *mask = (session_mask_or_match_4_t *) &rule->mask;
  fib_prefix_t lcl, rmt;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SESSION_RULES_DETAILS);
  rmp->context = context;

  clib_memset (&lcl, 0, sizeof (lcl));
  clib_memset (&rmt, 0, sizeof (rmt));
  ip_set (&lcl.fp_addr, &match->lcl_ip, 1);
  ip_set (&rmt.fp_addr, &match->rmt_ip, 1);
  lcl.fp_len = ip4_mask_to_preflen (&mask->lcl_ip);
  rmt.fp_len = ip4_mask_to_preflen (&mask->rmt_ip);
  lcl.fp_proto = FIB_PROTOCOL_IP4;
  rmt.fp_proto = FIB_PROTOCOL_IP4;

  ip_prefix_encode (&lcl, &rmp->lcl);
  ip_prefix_encode (&rmt, &rmp->rmt);
  rmp->lcl_port = clib_host_to_net_u16 (match->lcl_port);
  rmp->rmt_port = clib_host_to_net_u16 (match->rmt_port);
  rmp->action_index = clib_host_to_net_u32 (rule->action_index);
  rmp->scope = is_local ? SESSION_RULE_SCOPE_API_LOCAL : SESSION_RULE_SCOPE_API_GLOBAL;
  rmp->transport_proto = api_session_transport_proto_encode (transport_proto);
  rmp->appns_index = clib_host_to_net_u32 (appns_index);
  if (tag)
    {
      clib_memcpy_fast (rmp->tag, tag, vec_len (tag));
      rmp->tag[vec_len (tag)] = 0;
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_session_rule_details6 (mma_rule_40_t *rule, u8 is_local, u8 transport_proto, u32 appns_index,
			    u8 *tag, vl_api_registration_t *reg, u32 context)
{
  vl_api_session_rules_details_t *rmp = 0;
  session_mask_or_match_6_t *match = (session_mask_or_match_6_t *) &rule->match;
  session_mask_or_match_6_t *mask = (session_mask_or_match_6_t *) &rule->mask;
  fib_prefix_t lcl, rmt;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SESSION_RULES_DETAILS);
  rmp->context = context;

  clib_memset (&lcl, 0, sizeof (lcl));
  clib_memset (&rmt, 0, sizeof (rmt));
  ip_set (&lcl.fp_addr, &match->lcl_ip, 0);
  ip_set (&rmt.fp_addr, &match->rmt_ip, 0);
  lcl.fp_len = ip6_mask_to_preflen (&mask->lcl_ip);
  rmt.fp_len = ip6_mask_to_preflen (&mask->rmt_ip);
  lcl.fp_proto = FIB_PROTOCOL_IP6;
  rmt.fp_proto = FIB_PROTOCOL_IP6;

  ip_prefix_encode (&lcl, &rmp->lcl);
  ip_prefix_encode (&rmt, &rmp->rmt);
  rmp->lcl_port = clib_host_to_net_u16 (match->lcl_port);
  rmp->rmt_port = clib_host_to_net_u16 (match->rmt_port);
  rmp->action_index = clib_host_to_net_u32 (rule->action_index);
  rmp->scope = is_local ? SESSION_RULE_SCOPE_API_LOCAL : SESSION_RULE_SCOPE_API_GLOBAL;
  rmp->transport_proto = api_session_transport_proto_encode (transport_proto);
  rmp->appns_index = clib_host_to_net_u32 (appns_index);
  if (tag)
    {
      clib_memcpy_fast (rmp->tag, tag, vec_len (tag));
      rmp->tag[vec_len (tag)] = 0;
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_session_rules_table_details (session_rules_table_t *srt, u8 fib_proto, u8 tp, u8 is_local,
				  u32 appns_index, vl_api_registration_t *reg, u32 context)
{
  mma_rule_16_t *rule16;
  mma_rule_40_t *rule40;
  mma_rules_table_16_t *srt16;
  mma_rules_table_40_t *srt40;
  u32 ri;

  if (is_local || fib_proto == FIB_PROTOCOL_IP4)
    {
      u8 *tag = 0;
      srt16 = &srt->session_rules_tables_16;
      pool_foreach (rule16, srt16->rules)
	{
	  ri = mma_rules_table_rule_index_16 (srt16, rule16);
	  tag = session_rules_table_rule_tag (srt, ri, 1);
	  send_session_rule_details4 (rule16, is_local, tp, appns_index, tag, reg, context);
	}
    }
  if (is_local || fib_proto == FIB_PROTOCOL_IP6)
    {
      u8 *tag = 0;
      srt40 = &srt->session_rules_tables_40;
      pool_foreach (rule40, srt40->rules)
	{
	  ri = mma_rules_table_rule_index_40 (srt40, rule40);
	  tag = session_rules_table_rule_tag (srt, ri, 1);
	  send_session_rule_details6 (rule40, is_local, tp, appns_index, tag, reg, context);
	}
    }
}

static void
vl_api_session_rules_dump_t_handler (vl_api_session_rules_dump_t *mp)
{
  vl_api_registration_t *reg;
  session_table_t *st;
  u8 tp;
  u32 appns_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  session_table_foreach (
    st, ({
      if (st->srtg_handle != SESSION_SRTG_HANDLE_INVALID)
	for (tp = 0; tp < TRANSPORT_N_PROTOS; tp++)
	  {
	    session_rules_table_t *srt = srtg_handle_to_srt (st->srtg_handle, tp);
	    appns_index = *vec_elt_at_index (st->appns_index, vec_len (st->appns_index) - 1);
	    send_session_rules_table_details (srt, st->active_fib_proto, tp, st->is_local,
					      appns_index, reg, mp->context);
	  }
    }));
}

/*
 * session_rules_v2_dunp handler
 */
static void
send_session_rule_v2_details4 (mma_rule_16_t *rule, u8 is_local, u8 transport_proto,
			       u32 *appns_index, u8 *tag, vl_api_registration_t *reg, u32 context)
{
  vl_api_session_rules_v2_details_t *rmp = 0;
  session_mask_or_match_4_t *match = (session_mask_or_match_4_t *) &rule->match;
  session_mask_or_match_4_t *mask = (session_mask_or_match_4_t *) &rule->mask;
  fib_prefix_t lcl, rmt;
  u32 i, appns_index_count = vec_len (appns_index);

  rmp = vl_msg_api_alloc (sizeof (*rmp) + appns_index_count * sizeof (*appns_index));
  if (!rmp)
    return;
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SESSION_RULES_V2_DETAILS);
  rmp->context = context;

  rmp->count = clib_host_to_net_u32 (appns_index_count);
  vec_foreach_index (i, appns_index)
    {
      u32 index = *vec_elt_at_index (appns_index, i);
      rmp->appns_index[i] = clib_host_to_net_u32 (index);
    }

  clib_memset (&lcl, 0, sizeof (lcl));
  clib_memset (&rmt, 0, sizeof (rmt));
  ip_set (&lcl.fp_addr, &match->lcl_ip, 1);
  ip_set (&rmt.fp_addr, &match->rmt_ip, 1);
  lcl.fp_len = ip4_mask_to_preflen (&mask->lcl_ip);
  rmt.fp_len = ip4_mask_to_preflen (&mask->rmt_ip);
  lcl.fp_proto = FIB_PROTOCOL_IP4;
  rmt.fp_proto = FIB_PROTOCOL_IP4;

  ip_prefix_encode (&lcl, &rmp->lcl);
  ip_prefix_encode (&rmt, &rmp->rmt);
  rmp->lcl_port = clib_host_to_net_u16 (match->lcl_port);
  rmp->rmt_port = clib_host_to_net_u16 (match->rmt_port);
  rmp->action_index = clib_host_to_net_u32 (rule->action_index);
  rmp->scope = is_local ? SESSION_RULE_SCOPE_API_LOCAL : SESSION_RULE_SCOPE_API_GLOBAL;
  rmp->transport_proto = api_session_transport_proto_encode (transport_proto);
  if (tag)
    {
      clib_memcpy_fast (rmp->tag, tag, vec_len (tag));
      rmp->tag[vec_len (tag)] = 0;
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_session_rule_v2_details6 (mma_rule_40_t *rule, u8 is_local, u8 transport_proto,
			       u32 *appns_index, u8 *tag, vl_api_registration_t *reg, u32 context)
{
  vl_api_session_rules_v2_details_t *rmp = 0;
  session_mask_or_match_6_t *match = (session_mask_or_match_6_t *) &rule->match;
  session_mask_or_match_6_t *mask = (session_mask_or_match_6_t *) &rule->mask;
  fib_prefix_t lcl, rmt;
  u32 i, appns_index_count = vec_len (appns_index);

  rmp = vl_msg_api_alloc (sizeof (*rmp) + appns_index_count * sizeof (*appns_index));
  if (!rmp)
    return;
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SESSION_RULES_V2_DETAILS);
  rmp->context = context;

  rmp->count = clib_host_to_net_u32 (appns_index_count);
  vec_foreach_index (i, appns_index)
    {
      u32 index = *vec_elt_at_index (appns_index, i);
      rmp->appns_index[i] = clib_host_to_net_u32 (index);
    }

  clib_memset (&lcl, 0, sizeof (lcl));
  clib_memset (&rmt, 0, sizeof (rmt));
  ip_set (&lcl.fp_addr, &match->lcl_ip, 0);
  ip_set (&rmt.fp_addr, &match->rmt_ip, 0);
  lcl.fp_len = ip6_mask_to_preflen (&mask->lcl_ip);
  rmt.fp_len = ip6_mask_to_preflen (&mask->rmt_ip);
  lcl.fp_proto = FIB_PROTOCOL_IP6;
  rmt.fp_proto = FIB_PROTOCOL_IP6;

  ip_prefix_encode (&lcl, &rmp->lcl);
  ip_prefix_encode (&rmt, &rmp->rmt);
  rmp->lcl_port = clib_host_to_net_u16 (match->lcl_port);
  rmp->rmt_port = clib_host_to_net_u16 (match->rmt_port);
  rmp->action_index = clib_host_to_net_u32 (rule->action_index);
  rmp->scope = is_local ? SESSION_RULE_SCOPE_API_LOCAL : SESSION_RULE_SCOPE_API_GLOBAL;
  rmp->transport_proto = api_session_transport_proto_encode (transport_proto);
  if (tag)
    {
      clib_memcpy_fast (rmp->tag, tag, vec_len (tag));
      rmp->tag[vec_len (tag)] = 0;
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_session_rules_table_v2_details (session_rules_table_t *srt, u8 fib_proto, u8 tp, u8 is_local,
				     u32 *appns_index, vl_api_registration_t *reg, u32 context)
{
  mma_rule_16_t *rule16;
  mma_rule_40_t *rule40;
  mma_rules_table_16_t *srt16;
  mma_rules_table_40_t *srt40;
  u32 ri;

  if (is_local || fib_proto == FIB_PROTOCOL_IP4)
    {
      u8 *tag = 0;
      srt16 = &srt->session_rules_tables_16;
      pool_foreach (rule16, srt16->rules)
	{
	  ri = mma_rules_table_rule_index_16 (srt16, rule16);
	  tag = session_rules_table_rule_tag (srt, ri, 1);
	  send_session_rule_v2_details4 (rule16, is_local, tp, appns_index, tag, reg, context);
	}
    }
  if (is_local || fib_proto == FIB_PROTOCOL_IP6)
    {
      u8 *tag = 0;
      srt40 = &srt->session_rules_tables_40;
      pool_foreach (rule40, srt40->rules)
	{
	  ri = mma_rules_table_rule_index_40 (srt40, rule40);
	  tag = session_rules_table_rule_tag (srt, ri, 1);
	  send_session_rule_v2_details6 (rule40, is_local, tp, appns_index, tag, reg, context);
	}
    }
}

static void
vl_api_session_rules_v2_dump_t_handler (vl_api_session_rules_dump_t *mp)
{
  vl_api_registration_t *reg;
  session_table_t *st;
  u8 tp;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  session_table_foreach (
    st, ({
      if (st->srtg_handle != SESSION_SRTG_HANDLE_INVALID)
	for (tp = 0; tp < TRANSPORT_N_PROTOS; tp++)
	  {
	    session_rules_table_t *srt = srtg_handle_to_srt (st->srtg_handle, tp);
	    send_session_rules_table_v2_details (srt, st->active_fib_proto, tp, st->is_local,
						 st->appns_index, reg, mp->context);
	  }
    }));
}

typedef struct session_sdl_table_walk_ctx_
{
  vl_api_registration_t *reg;
  u32 mp_context;
  u32 *appns_index;
} session_sdl_table_walk_ctx;

static void
send_session_sdl_v2_details (u32 fei, ip46_address_t *rmt_ip, u16 fp_len, u32 action_index,
			     u32 fp_proto, u8 *tag, void *args)
{
  session_sdl_table_walk_ctx *ctx = args;
  vl_api_registration_t *reg = ctx->reg;
  u32 appns_index = *vec_elt_at_index (ctx->appns_index, vec_len (ctx->appns_index) - 1);
  u32 context = ctx->mp_context;
  vl_api_session_sdl_v2_details_t *rmp = 0;
  fib_prefix_t rmt;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SESSION_SDL_V2_DETAILS);
  rmp->context = context;

  clib_memset (&rmt, 0, sizeof (rmt));
  if (fp_proto == FIB_PROTOCOL_IP4)
    ip_set (&rmt.fp_addr, &rmt_ip->ip4, 1);
  else
    ip_set (&rmt.fp_addr, &rmt_ip->ip6, 0);
  rmt.fp_len = fp_len;
  rmt.fp_proto = fp_proto,

  ip_prefix_encode (&rmt, &rmp->rmt);
  rmp->action_index = clib_host_to_net_u32 (action_index);
  rmp->appns_index = clib_host_to_net_u32 (appns_index);
  if (tag)
    {
      clib_memcpy_fast (rmp->tag, tag, vec_len (tag));
      rmp->tag[vec_len (tag)] = 0;
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_session_sdl_v2_dump_t_handler (vl_api_session_sdl_v2_dump_t *mp)
{
  vl_api_registration_t *reg;
  session_table_t *st;
  session_sdl_table_walk_ctx ctx;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  ctx.reg = reg;
  ctx.mp_context = mp->context;

  session_table_foreach (
    st, ({
      if (st->srtg_handle != SESSION_SRTG_HANDLE_INVALID)
	{
	  ctx.appns_index = st->appns_index;
	  if (st->active_fib_proto == FIB_PROTOCOL_IP4)
	    session_sdl_table_walk4 (st->srtg_handle, send_session_sdl_v2_details, &ctx);
	  else
	    session_sdl_table_walk6 (st->srtg_handle, send_session_sdl_v2_details, &ctx);
	}
    }));
}

static void
send_session_sdl_v3_details (u32 fei, ip46_address_t *rmt_ip, u16 fp_len, u32 action_index,
			     u32 fp_proto, u8 *tag, void *args)
{
  session_sdl_table_walk_ctx *ctx = args;
  vl_api_registration_t *reg = ctx->reg;
  u32 context = ctx->mp_context;
  vl_api_session_sdl_v3_details_t *rmp = 0;
  fib_prefix_t rmt;
  u32 appns_index_count, appns_index, i;

  appns_index_count = vec_len (ctx->appns_index);
  rmp = vl_msg_api_alloc (sizeof (*rmp) + appns_index_count * sizeof (appns_index));
  if (!rmp)
    return;
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SESSION_SDL_V3_DETAILS);
  rmp->context = context;

  rmp->count = clib_host_to_net_u32 (appns_index_count);
  vec_foreach_index (i, ctx->appns_index)
    {
      appns_index = *vec_elt_at_index (ctx->appns_index, i);
      rmp->appns_index[i] = clib_host_to_net_u32 (appns_index);
    }

  clib_memset (&rmt, 0, sizeof (rmt));
  if (fp_proto == FIB_PROTOCOL_IP4)
    ip_set (&rmt.fp_addr, &rmt_ip->ip4, 1);
  else
    ip_set (&rmt.fp_addr, &rmt_ip->ip6, 0);
  rmt.fp_len = fp_len;
  rmt.fp_proto = fp_proto,

  ip_prefix_encode (&rmt, &rmp->rmt);
  rmp->action_index = clib_host_to_net_u32 (action_index);

  if (tag)
    {
      clib_memcpy_fast (rmp->tag, tag, vec_len (tag));
      rmp->tag[vec_len (tag)] = 0;
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_session_sdl_v3_dump_t_handler (vl_api_session_sdl_v2_dump_t *mp)
{
  vl_api_registration_t *reg;
  session_table_t *st;
  session_sdl_table_walk_ctx ctx;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  ctx.reg = reg;
  ctx.mp_context = mp->context;

  session_table_foreach (
    st, ({
      if (st->srtg_handle != SESSION_SRTG_HANDLE_INVALID)
	{
	  ctx.appns_index = st->appns_index;
	  if (st->active_fib_proto == FIB_PROTOCOL_IP4)
	    session_sdl_table_walk4 (st->srtg_handle, send_session_sdl_v3_details, &ctx);
	  else
	    session_sdl_table_walk6 (st->srtg_handle, send_session_sdl_v3_details, &ctx);
	}
    }));
}

static void
send_session_sdl_details (u32 fei, ip46_address_t *lcl_ip, u16 fp_len, u32 action_index,
			  u32 fp_proto, u8 *tag, void *args)
{
  session_sdl_table_walk_ctx *ctx = args;
  vl_api_registration_t *reg = ctx->reg;
  u32 appns_index = *vec_elt_at_index (ctx->appns_index, vec_len (ctx->appns_index) - 1);
  u32 context = ctx->mp_context;
  vl_api_session_sdl_details_t *rmp = 0;
  fib_prefix_t lcl;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SESSION_SDL_DETAILS);
  rmp->context = context;

  clib_memset (&lcl, 0, sizeof (lcl));
  if (fp_proto == FIB_PROTOCOL_IP4)
    ip_set (&lcl.fp_addr, &lcl_ip->ip4, 1);
  else
    ip_set (&lcl.fp_addr, &lcl_ip->ip6, 0);
  lcl.fp_len = fp_len;
  lcl.fp_proto = fp_proto,

  ip_prefix_encode (&lcl, &rmp->lcl);
  rmp->action_index = clib_host_to_net_u32 (action_index);
  rmp->appns_index = clib_host_to_net_u32 (appns_index);
  if (tag)
    {
      clib_memcpy_fast (rmp->tag, tag, vec_len (tag));
      rmp->tag[vec_len (tag)] = 0;
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_session_sdl_dump_t_handler (vl_api_session_sdl_dump_t *mp)
{
  vl_api_registration_t *reg;
  session_table_t *st;
  session_sdl_table_walk_ctx ctx;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  ctx.reg = reg;
  ctx.mp_context = mp->context;

  session_table_foreach (
    st, ({
      if (st->srtg_handle != SESSION_SRTG_HANDLE_INVALID)
	{
	  ctx.appns_index = st->appns_index;
	  if (st->active_fib_proto == FIB_PROTOCOL_IP4)
	    session_sdl_table_walk4 (st->srtg_handle, send_session_sdl_details, &ctx);
	  else
	    session_sdl_table_walk6 (st->srtg_handle, send_session_sdl_details, &ctx);
	}
    }));
}

static void
vl_api_app_add_cert_key_pair_t_handler (vl_api_app_add_cert_key_pair_t *mp)
{
  vl_api_app_add_cert_key_pair_reply_t *rmp;
  vnet_app_add_cert_key_pair_args_t _a, *a = &_a;
  u32 certkey_len, key_len, cert_len;
  int rv = 0;
  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  cert_len = clib_net_to_host_u16 (mp->cert_len);
  if (cert_len > 10000)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  certkey_len = clib_net_to_host_u16 (mp->certkey_len);
  if (certkey_len < cert_len)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  key_len = certkey_len - cert_len;
  if (key_len > 10000)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  clib_memset (a, 0, sizeof (*a));
  a->cert = mp->certkey;
  a->key = mp->certkey + cert_len;
  a->cert_len = cert_len;
  a->key_len = key_len;
  rv = vnet_app_add_cert_key_pair (a);

done:
  REPLY_MACRO2 (VL_API_APP_ADD_CERT_KEY_PAIR_REPLY, ({
		  if (!rv)
		    rmp->index = clib_host_to_net_u32 (a->index);
		}));
}

static void
vl_api_app_del_cert_key_pair_t_handler (vl_api_app_del_cert_key_pair_t *mp)
{
  vl_api_app_del_cert_key_pair_reply_t *rmp;
  u32 ckpair_index;
  int rv = 0;
  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }
  ckpair_index = clib_net_to_host_u32 (mp->index);
  rv = vnet_app_del_cert_key_pair (ckpair_index);
  if (rv)
    {
      clib_warning ("vnet_app_del_cert_key_pair: %U", format_session_error, rv);
      rv = VNET_API_ERROR_UNSPECIFIED;
    }

done:
  REPLY_MACRO (VL_API_APP_DEL_CERT_KEY_PAIR_REPLY);
}

static clib_error_t *
application_reaper_cb (u32 client_index)
{
  application_t *app = application_lookup (client_index);
  vnet_app_detach_args_t _a, *a = &_a;
  if (app)
    {
      a->app_index = app->app_index;
      a->api_client_index = client_index;
      vnet_application_detach (a);
    }
  return 0;
}

VL_MSG_API_REAPER_FUNCTION (application_reaper_cb);

/*
 * Socket api functions
 */

static int
mq_send_add_segment_sapi_cb (u32 app_wrk_index, u64 segment_handle)
{
  session_app_add_segment_msg_t m = { 0 };
  app_worker_t *app_wrk;
  fifo_segment_t *fs;
  ssvm_private_t *sp;
  u8 fd_flags = 0;

  app_wrk = app_worker_get (app_wrk_index);

  fs = segment_manager_get_segment_w_handle (segment_handle);
  sp = &fs->ssvm;
  ASSERT (ssvm_type (sp) == SSVM_SEGMENT_MEMFD);

  fd_flags |= SESSION_FD_F_MEMFD_SEGMENT;

  m.segment_size = sp->ssvm_size;
  m.fd_flags = fd_flags;
  m.segment_handle = segment_handle;
  strncpy ((char *) m.segment_name, (char *) sp->name, sizeof (m.segment_name) - 1);

  return app_wrk_send_ctrl_evt_fd (app_wrk, SESSION_CTRL_EVT_APP_ADD_SEGMENT, &m, sizeof (m),
				   sp->fd);
}

static int
mq_send_del_segment_sapi_cb (u32 app_wrk_index, u64 segment_handle)
{
  session_app_del_segment_msg_t m = { 0 };
  app_worker_t *app_wrk;

  app_wrk = app_worker_get (app_wrk_index);

  m.segment_handle = segment_handle;

  return app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_APP_DEL_SEGMENT, &m, sizeof (m));
}

static session_cb_vft_t session_mq_sapi_cb_vft = {
  .session_accept_callback = mq_send_session_accepted_cb,
  .session_disconnect_callback = mq_send_session_disconnected_cb,
  .session_connected_callback = mq_send_session_connected_cb,
  .session_reset_callback = mq_send_session_reset_cb,
  .session_migrate_callback = mq_send_session_migrate_cb,
  .session_cleanup_callback = mq_send_session_cleanup_cb,
  .session_listened_callback = mq_send_session_bound_cb,
  .session_unlistened_callback = mq_send_unlisten_cb,
  .add_segment_callback = mq_send_add_segment_sapi_cb,
  .del_segment_callback = mq_send_del_segment_sapi_cb,
  .builtin_app_rx_callback = mq_send_io_rx_event,
  .builtin_app_tx_callback = mq_send_io_tx_event,
};

typedef struct sapi_observability_attachment_
{
  u32 app_wrk_index;
  int fd;
  session_observability_segment_t *segment;
  svm_msg_q_t *queue;
  session_observability_owner_t owner;
  session_observability_descriptor_t descriptor;
  clib_socket_t *control_socket;
  u8 detach_pending;
} sapi_observability_attachment_t;

static sapi_observability_attachment_t *sapi_observability_attachments;
static u64 sapi_observability_next_identity = 1;

static void sapi_observability_attachment_destroy (sapi_observability_attachment_t *attachment);
int session_observability_test_attachment_create (u32 app_wrk_index);
int session_observability_test_socket_control (clib_socket_t *cs, app_sapi_msg_t *msg,
					       u32 app_wrk_index);
void session_observability_test_bapi_request (vl_api_app_observability_request_v2_t *mp);
void session_observability_test_peer_dead (u32 app_wrk_index);

static void
sapi_observability_attachment_reap (sapi_observability_attachment_t *attachment)
{
  app_sapi_msg_t done = { 0 };

  if (!attachment || !attachment->detach_pending ||
      clib_atomic_load_acq_n (&attachment->owner.references) != 1 ||
      clib_atomic_load_acq_n (&attachment->segment->header.lifecycle) !=
	SESSION_OBSERVABILITY_HEADER_DETACHING)
    return;

  /* Every fenced ticket has now drained and released its pins.  VPP keeps
   * its mapping through DONE so VCL cannot reconnect to a recycled image. */
  clib_memset (attachment->segment, 0, sizeof (*attachment->segment));
  clib_atomic_store_rel_n (&attachment->segment->header.lifecycle,
			   SESSION_OBSERVABILITY_HEADER_DEAD);
  done.type = APP_SAPI_MSG_TYPE_OBS_DONE_V2;
  done.observability_control_v2.association = attachment->app_wrk_index;
  done.observability_control_v2.descriptor = attachment->descriptor;
  if (!attachment->control_socket ||
      clib_socket_sendmsg (attachment->control_socket, &done, sizeof (done), 0, 0))
    sapi_observability_attachment_destroy (attachment);
}

static void
sapi_observability_attachment_drained (session_observability_owner_t *owner)
{
  sapi_observability_attachment_t *attachment =
    (sapi_observability_attachment_t *) ((u8 *) owner -
					 STRUCT_OFFSET_OF (sapi_observability_attachment_t, owner));

  if (!attachment->detach_pending)
    return;
  /* This is called by the last owner-worker ticket release.  Reap directly:
   * a second best-effort RPC could itself be rejected by a full main-worker
   * event queue and leave a fenced, detached mapping permanently live. */
  sapi_observability_attachment_reap (attachment);
}

static void
sapi_observability_attachment_release (session_observability_owner_t *owner)
{
  sapi_observability_attachment_t *attachment =
    (sapi_observability_attachment_t *) ((u8 *) owner -
					 STRUCT_OFFSET_OF (sapi_observability_attachment_t, owner));
  app_worker_t *app_wrk = app_worker_get_if_valid (attachment->app_wrk_index);

  if (app_wrk && app_wrk->observability_owner == owner)
    {
      app_wrk->observability_segment = 0;
      app_wrk->observability_queue = 0;
      app_wrk->observability_owner = 0;
      app_wrk->observability_association = 0;
      clib_memset (&app_wrk->observability_descriptor, 0,
		   sizeof (app_wrk->observability_descriptor));
    }
  clib_atomic_store_rel_n (&attachment->segment->header.lifecycle,
			   SESSION_OBSERVABILITY_HEADER_RETIRED);
  if (attachment->queue)
    svm_msg_q_free (attachment->queue);
  if (attachment->segment)
    clib_mem_vm_unmap (attachment->segment);
  if (attachment->fd >= 0)
    close (attachment->fd);
  pool_put (sapi_observability_attachments, attachment);
}

static void
sapi_observability_attachment_destroy (sapi_observability_attachment_t *attachment)
{
  if (!attachment)
    return;
  if (!clib_atomic_load_acq_n (&attachment->owner.fenced))
    session_observability_fence_owner (&attachment->owner, SESSION_OBSERVABILITY_RESULT_OWNER_DEAD);
  clib_atomic_store_rel_n (&attachment->segment->header.lifecycle,
			   SESSION_OBSERVABILITY_HEADER_RETIRED);
  session_observability_owner_release (&attachment->owner);
}

static sapi_observability_attachment_t *
sapi_observability_attachment_create (app_worker_t *app_wrk)
{
  sapi_observability_attachment_t *attachment;
  session_observability_segment_t *segment;
  svm_msg_q_ring_cfg_t ring_cfg = {
    .nitems = SESSION_OBSERVABILITY_SLOT_COUNT,
    .elsize = sizeof (session_observability_event_t),
  };
  svm_msg_q_cfg_t queue_cfg = {
    .consumer_pid = ~0,
    .q_nitems = SESSION_OBSERVABILITY_SLOT_COUNT,
    .n_rings = 1,
    .ring_cfgs = &ring_cfg,
  };
  svm_msg_q_shared_t *shared_queue = 0;
  u64 identity;
  int fd = -1;

  pool_get_zero (sapi_observability_attachments, attachment);
  fd = clib_mem_vm_create_fd (CLIB_MEM_PAGE_SZ_DEFAULT, "session-observability-%u",
			      app_wrk->wrk_index);
  if (fd < 0 || ftruncate (fd, SESSION_OBSERVABILITY_SEGMENT_BYTES))
    goto error;
#ifdef F_ADD_SEALS
  if (fcntl (fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL))
    goto error;
#endif
  segment = clib_mem_vm_map_shared (0, SESSION_OBSERVABILITY_SEGMENT_BYTES, fd, 0,
				    "session-observability-%u", app_wrk->wrk_index);
  if (segment == MAP_FAILED)
    goto error;
  identity = clib_atomic_fetch_add_rel (&sapi_observability_next_identity, 1);
  if (!identity)
    goto error_map;

  shared_queue = svm_msg_q_alloc (&queue_cfg);
  attachment->queue = clib_mem_alloc_aligned (sizeof (*attachment->queue), CLIB_CACHE_LINE_BYTES);
  if (!shared_queue || !attachment->queue)
    goto error_queue;
  clib_memset (attachment->queue, 0, sizeof (*attachment->queue));
  svm_msg_q_attach (attachment->queue, shared_queue);

  clib_memset (segment, 0, sizeof (*segment));
  segment->header.magic = 0x3256545441504354ULL;
  segment->header.abi = SESSION_OBSERVABILITY_ABI_VERSION;
  segment->header.header_bytes = sizeof (segment->header);
  segment->header.little_endian_marker = 0x01020304;
  segment->header.layout_hash = SESSION_OBSERVABILITY_LAYOUT_HASH;
  segment->header.total_bytes = sizeof (*segment);
  segment->header.directory_offset = offsetof (session_observability_segment_t, directory);
  segment->header.directory_count = SESSION_OBSERVABILITY_SLOT_COUNT;
  segment->header.directory_stride = sizeof (segment->directory[0]);
  segment->header.cell_offset = offsetof (session_observability_segment_t, cell);
  segment->header.cell_count = SESSION_OBSERVABILITY_SLOT_COUNT;
  segment->header.cell_stride = sizeof (segment->cell[0]);
  segment->header.sidecar_offset = offsetof (session_observability_segment_t, sidecar);
  segment->header.sidecar_count = SESSION_OBSERVABILITY_SLOT_COUNT;
  segment->header.sidecar_stride = sizeof (segment->sidecar[0]);
  segment->header.event_bytes = 80;
  segment->header.descriptor_bytes = sizeof (attachment->descriptor);
  segment->header.segment_handle = identity;
  segment->header.attachment_instance = identity;
  segment->header.attach_generation = identity;
  segment->header.queue_identity = identity;
  segment->header.queue_generation = identity;
  segment->header.ticket_sequence_next = 1;
  clib_atomic_store_rel_n (&segment->header.lifecycle, SESSION_OBSERVABILITY_HEADER_CREATED);

  attachment->app_wrk_index = app_wrk->wrk_index;
  attachment->fd = fd;
  attachment->segment = segment;
  attachment->owner = (session_observability_owner_t){
    .segment = segment,
    .queue = attachment->queue,
    .references = 1,
    .drained = sapi_observability_attachment_drained,
    .release = sapi_observability_attachment_release,
  };
  attachment->descriptor = (session_observability_descriptor_t){
    .abi = SESSION_OBSERVABILITY_ABI_VERSION,
    .bytes = sizeof (attachment->descriptor),
    .layout_hash = SESSION_OBSERVABILITY_LAYOUT_HASH,
    .segment_handle = identity,
    .attachment_instance = identity,
    .attach_generation = identity,
    .queue_identity = identity,
    .queue_generation = identity,
    .segment_bytes = sizeof (*segment),
    .binding_index = app_wrk->wrk_index,
    .binding_nonce = identity,
  };
  app_wrk->observability_segment = segment;
  app_wrk->observability_queue = attachment->queue;
  app_wrk->observability_owner = &attachment->owner;
  app_wrk->observability_descriptor = attachment->descriptor;
  app_wrk->observability_association = app_wrk->wrk_index;
  return attachment;

error_queue:
  if (attachment->queue)
    {
      clib_mem_free (attachment->queue);
      attachment->queue = 0;
    }
  if (shared_queue)
    clib_mem_free (shared_queue);
error_map:
  clib_mem_vm_unmap (segment);
error:
  if (fd >= 0)
    close (fd);
  pool_put (sapi_observability_attachments, attachment);
  return 0;
}

static sapi_observability_attachment_t *
sapi_observability_attachment_find (u32 association,
				    const session_observability_descriptor_t *descriptor)
{
  sapi_observability_attachment_t *attachment;

  pool_foreach (attachment, sapi_observability_attachments)
    {
      if (attachment->app_wrk_index == association &&
	  (!descriptor || !memcmp (&attachment->descriptor, descriptor, sizeof (*descriptor))))
	return attachment;
    }
  return 0;
}

static void
sapi_observability_descriptor_to_api (vl_api_app_observability_attachment_descriptor_v2_t *dst,
				      const session_observability_descriptor_t *src)
{
  dst->abi = clib_host_to_net_u16 (src->abi);
  dst->bytes = clib_host_to_net_u16 (src->bytes);
  dst->layout_hash = clib_host_to_net_u32 (src->layout_hash);
  dst->segment_handle = clib_host_to_net_u64 (src->segment_handle);
  dst->attachment_instance = clib_host_to_net_u64 (src->attachment_instance);
  dst->attach_generation = clib_host_to_net_u64 (src->attach_generation);
  dst->queue_identity = clib_host_to_net_u64 (src->queue_identity);
  dst->queue_generation = clib_host_to_net_u64 (src->queue_generation);
  dst->segment_bytes = clib_host_to_net_u32 (src->segment_bytes);
  dst->binding_index = clib_host_to_net_u32 (src->binding_index);
  dst->binding_nonce = clib_host_to_net_u64 (src->binding_nonce);
}

static int
sapi_observability_attachment_create_for_bapi (app_worker_t *app_wrk, int *fd,
					       session_observability_descriptor_t *descriptor)
{
  sapi_observability_attachment_t *attachment;

  if (!app_wrk || !fd || !descriptor || app_wrk->observability_owner)
    return -1;
  attachment = sapi_observability_attachment_create (app_wrk);
  if (!attachment)
    return -1;
  *fd = attachment->fd;
  *descriptor = attachment->descriptor;
  return 0;
}

static int
sapi_observability_attachment_control_for_bapi (
  u32 client_index, u32 association, const session_observability_descriptor_t *descriptor,
  session_observability_header_state_t state)
{
  sapi_observability_attachment_t *attachment;
  app_worker_t *app_wrk;
  u32 current;

  if (!session_observability_descriptor_is_valid (descriptor))
    return -1;
  attachment = sapi_observability_attachment_find (association, descriptor);
  if (!attachment)
    return -1;
  app_wrk = app_worker_get_if_valid (attachment->app_wrk_index);
  if (!app_wrk || (client_index != APP_INVALID_INDEX && app_wrk->api_client_index != client_index))
    return -1;
  current = clib_atomic_load_acq_n (&attachment->segment->header.lifecycle);
  if (state == SESSION_OBSERVABILITY_HEADER_MAP_VALID &&
      current == SESSION_OBSERVABILITY_HEADER_CREATED)
    {
      clib_atomic_store_rel_n (&attachment->segment->header.lifecycle, state);
      return 0;
    }
  if (state == SESSION_OBSERVABILITY_HEADER_DETACHING &&
      current == SESSION_OBSERVABILITY_HEADER_MAP_VALID)
    {
      session_observability_fence_owner (&attachment->owner,
					 SESSION_OBSERVABILITY_RESULT_OWNER_DEAD);
      clib_atomic_store_rel_n (&attachment->segment->header.lifecycle, state);
      return 0;
    }
  if (state == SESSION_OBSERVABILITY_HEADER_DEAD &&
      current == SESSION_OBSERVABILITY_HEADER_DETACHING)
    {
      clib_atomic_store_rel_n (&attachment->segment->header.lifecycle, state);
      return 0;
    }
  return -1;
}

static int
sapi_observability_control_handler (clib_socket_t *cs, app_sapi_msg_t *msg, u32 app_wrk_index)
{
  app_sapi_observability_control_v2_reply_msg_t *reply;
  sapi_observability_attachment_t *attachment;
  app_sapi_msg_t response = { 0 };

  if (msg->type == APP_SAPI_MSG_TYPE_OBS_DONE_V2_REPLY)
    {
      reply = &msg->observability_control_v2_reply;
      attachment = sapi_observability_attachment_find (reply->association, &reply->descriptor);
      if (!attachment || attachment->app_wrk_index != app_wrk_index || reply->retval ||
	  clib_atomic_load_acq_n (&attachment->segment->header.lifecycle) !=
	    SESSION_OBSERVABILITY_HEADER_DEAD)
	return -1;
      clib_atomic_store_rel_n (&attachment->segment->header.lifecycle,
			       SESSION_OBSERVABILITY_HEADER_RETIRED);
      sapi_observability_attachment_destroy (attachment);
      return 0;
    }

  response.type = msg->type + 1;
  reply = &response.observability_control_v2_reply;
  reply->association = msg->observability_control_v2.association;
  reply->descriptor = msg->observability_control_v2.descriptor;
  reply->retval = SESSION_E_INVALID;
  attachment = sapi_observability_attachment_find (reply->association,
						   &msg->observability_control_v2.descriptor);
  if (!attachment || attachment->app_wrk_index != app_wrk_index)
    goto done;
  if (msg->type == APP_SAPI_MSG_TYPE_OBS_ATTACH_ACK_V2)
    reply->retval = sapi_observability_attachment_control_for_bapi (
      APP_INVALID_INDEX, reply->association, &msg->observability_control_v2.descriptor,
      SESSION_OBSERVABILITY_HEADER_MAP_VALID);
  else if (msg->type == APP_SAPI_MSG_TYPE_OBS_DETACH_V2)
    reply->retval = sapi_observability_attachment_control_for_bapi (
      APP_INVALID_INDEX, reply->association, &msg->observability_control_v2.descriptor,
      SESSION_OBSERVABILITY_HEADER_DETACHING);
done:
  clib_socket_sendmsg (cs, &response, sizeof (response), 0, 0);
  if (!reply->retval && msg->type == APP_SAPI_MSG_TYPE_OBS_DETACH_V2)
    {
      attachment->control_socket = cs;
      attachment->detach_pending = 1;
      sapi_observability_attachment_reap (attachment);
    }
  return reply->retval;
}

typedef struct
{
  u32 app_ns_index;
  u32 socket_index;
  u32 app_wrk_index;
  session_observability_descriptor_t descriptor;
  session_observability_reply_t reply;
} sapi_observability_completion_t;

static void
sapi_observability_completion_send (void *arg)
{
  sapi_observability_completion_t *completion = arg;
  sapi_observability_attachment_t *attachment;
  app_ns_api_handle_t *handle;
  app_namespace_t *app_ns;
  app_sapi_msg_t response = { 0 };
  clib_socket_t *cs;

  app_ns = app_namespace_get (completion->app_ns_index);
  if (!app_ns)
    return;
  cs = appns_sapi_get_socket (app_ns, completion->socket_index);
  if (!cs)
    return;
  handle = (app_ns_api_handle_t *) &cs->private_data;
  attachment =
    sapi_observability_attachment_find (completion->app_wrk_index, &completion->descriptor);
  if (!attachment || handle->aah_app_wrk_index != completion->app_wrk_index ||
      clib_atomic_load_acq_n (&attachment->segment->header.lifecycle) !=
	SESSION_OBSERVABILITY_HEADER_MAP_VALID ||
      completion->reply.receipt_length > SESSION_OBSERVABILITY_RECEIPT_MAX)
    return;

  response.type = APP_SAPI_MSG_TYPE_OBS_REQUEST_V2_REPLY;
  response.observability_request_v2_reply = (app_sapi_observability_request_v2_reply_msg_t){
    .retval = 0,
    .status = completion->reply.status,
    .detail = completion->reply.detail,
    .receipt_length = completion->reply.receipt_length,
    .reply_flags = completion->reply.reply_flags,
    .request_id = completion->reply.request_id,
  };
  clib_memcpy_fast (response.observability_request_v2_reply.receipt, completion->reply.receipt,
		    completion->reply.receipt_length);
  (void) clib_socket_sendmsg (cs, &response, sizeof (response), 0, 0);
}

static void
sapi_observability_completion_notify (void *context, const session_observability_reply_t *reply)
{
  sapi_observability_completion_t *completion = context;

  if (!completion)
    return;
  completion->reply = *reply;
  vlib_rpc_call_main_thread (sapi_observability_completion_send, (u8 *) completion,
			     sizeof (*completion));
  clib_mem_free (completion);
}

static void
sapi_observability_completion_direct (app_namespace_t *app_ns, clib_socket_t *cs,
				      app_worker_t *app_wrk,
				      sapi_observability_attachment_t *attachment, u64 request_id,
				      session_observability_result_t result)
{
  sapi_observability_completion_t completion = {
    .app_ns_index = app_namespace_index (app_ns),
    .socket_index = appns_sapi_socket_index (app_ns, cs),
    .app_wrk_index = app_wrk->wrk_index,
    .descriptor = attachment->descriptor,
    .reply = {
      .request_id = request_id,
      .status = 2,
      .detail = result,
    },
  };

  vlib_rpc_call_main_thread (sapi_observability_completion_send, (u8 *) &completion,
			     sizeof (completion));
}

static int
sapi_observability_request_handler (app_namespace_t *app_ns, clib_socket_t *cs, app_sapi_msg_t *msg,
				    u32 app_wrk_index)
{
  app_sapi_observability_request_v2_msg_t *request = &msg->observability_request_v2;
  sapi_observability_attachment_t *attachment;
  session_observability_admission_t admission = { 0 };
  session_observability_dispatch_t dispatch = { 0 };
  sapi_observability_completion_t *completion = 0;
  svm_msg_q_observability_ticket_t queue_ticket;
  svm_msg_q_observability_reservation_result_t queue_rv;
  session_observability_event_t event;
  session_handle_tu_t handle;
  session_observability_directory_t *directory;
  session_observability_result_t result = SESSION_OBSERVABILITY_RESULT_SESSION_NOT_FOUND;
  svm_msg_q_msg_t queue_msg;
  app_worker_t *app_wrk;
  session_t *session;
  u64 ticket;
  u32 expected, slot;

  app_wrk = app_worker_get_if_valid (app_wrk_index);
  attachment = app_wrk ? sapi_observability_attachment_find (app_wrk_index, 0) : 0;
  if (!app_wrk || !attachment || app_wrk->observability_owner != &attachment->owner ||
      clib_atomic_load_acq_n (&attachment->segment->header.lifecycle) !=
	SESSION_OBSERVABILITY_HEADER_MAP_VALID)
    return -1;
  if (request->abi != SESSION_OBSERVABILITY_ABI_VERSION || request->request_flags ||
      !request->request_id ||
      request->sampling_point < SESSION_OBSERVABILITY_SAMPLING_POST_HANDSHAKE ||
      request->sampling_point > SESSION_OBSERVABILITY_SAMPLING_TERMINAL)
    {
      result = SESSION_OBSERVABILITY_RESULT_DISPATCH_REJECTED;
      goto direct;
    }
  slot = request->attachment_slot;
  if (slot >= SESSION_OBSERVABILITY_SLOT_COUNT)
    {
      result = SESSION_OBSERVABILITY_RESULT_DISPATCH_REJECTED;
      goto direct;
    }
  handle.handle = request->session_handle;
  session = session_get_from_handle_if_valid (handle);
  if (!session || session->app_wrk_index != app_wrk_index ||
      session->observability_token_version != 1 || !session->observability_association_token)
    goto direct;
  ticket = clib_atomic_fetch_add_rel (&attachment->segment->header.ticket_sequence_next, 1);
  if (!ticket)
    {
      result = SESSION_OBSERVABILITY_RESULT_QUEUE_BROKEN;
      goto direct;
    }
  event = (session_observability_event_t){
    .opcode = 1,
    .abi = SESSION_OBSERVABILITY_ABI_VERSION,
    .attachment_slot = slot,
    .allocation_nonce = ticket,
    .association_token = session->observability_association_token,
    .session_handle = request->session_handle,
    .directory_nonce = ticket,
    .attachment_instance = attachment->segment->header.attachment_instance,
    .binding_generation = attachment->segment->header.attach_generation,
    .request_id = request->request_id,
    .owner_thread = handle.thread_index,
    .vcl_application_association = app_wrk->observability_association,
    .ticket_sequence = ticket,
  };
  admission.owner = &attachment->owner;
  admission.directory = directory = &attachment->segment->directory[slot];
  admission.cell = &attachment->segment->cell[slot];
  admission.sidecar = &attachment->segment->sidecar[slot];
  admission.event = event;

  expected = SESSION_OBSERVABILITY_DIRECTORY_FREE;
  if (clib_atomic_cmp_and_swap_acq_relax_n (&directory->lifecycle, &expected,
					    SESSION_OBSERVABILITY_DIRECTORY_INITIALIZING, 0))
    {
      clib_memset (directory, 0, sizeof (*directory));
      directory->entry_nonce = ticket;
      directory->association_token = event.association_token;
      directory->session_handle = event.session_handle;
      directory->attachment_instance = event.attachment_instance;
      directory->binding_generation = event.binding_generation;
      directory->owner_thread = event.owner_thread;
      directory->vcl_application_association = event.vcl_application_association;
      clib_atomic_store_rel_n (&directory->lifecycle, SESSION_OBSERVABILITY_DIRECTORY_LIVE);
    }
  else if (expected != SESSION_OBSERVABILITY_DIRECTORY_LIVE ||
	   directory->association_token != event.association_token ||
	   directory->session_handle != event.session_handle ||
	   directory->attachment_instance != event.attachment_instance ||
	   directory->binding_generation != event.binding_generation ||
	   directory->owner_thread != event.owner_thread ||
	   directory->vcl_application_association != event.vcl_application_association)
    {
      result = SESSION_OBSERVABILITY_RESULT_ASSOCIATION_MISMATCH;
      goto direct;
    }
  admission.event.directory_nonce = directory->entry_nonce;
  if (session_observability_admission_gate_get (directory) ||
      session_observability_owner_get (admission.owner))
    {
      result = SESSION_OBSERVABILITY_RESULT_ASSOCIATION_MIGRATED;
      goto direct;
    }
  expected = SESSION_OBSERVABILITY_CELL_FREE;
  if (!clib_atomic_cmp_and_swap_acq_relax_n (&admission.cell->cell_state, &expected,
					     SESSION_OBSERVABILITY_CELL_INITIALIZING, 0) &&
      (expected != SESSION_OBSERVABILITY_CELL_COMPLETED ||
       clib_atomic_load_acq_n (&admission.cell->references) ||
       clib_atomic_load_acq_n (&admission.sidecar->references) ||
       clib_atomic_load_acq_n (&admission.sidecar->ticket_state) !=
	 SESSION_OBSERVABILITY_TICKET_FREE))
    {
      clib_atomic_fetch_sub_rel (&directory->admission_gate, 1);
      session_observability_owner_release (admission.owner);
      result = SESSION_OBSERVABILITY_RESULT_QUEUE_BUSY;
      goto direct;
    }
  clib_memset (admission.cell, 0, sizeof (*admission.cell));
  clib_memset (admission.sidecar, 0, sizeof (*admission.sidecar));
  admission.cell->allocation_nonce = ticket;
  admission.cell->request_id = request->request_id;
  admission.cell->sampling_point = request->sampling_point;
  admission.cell->request_flags = request->request_flags;
  admission.cell->directory_nonce = admission.event.directory_nonce;
  admission.cell->attachment_instance = admission.event.attachment_instance;
  admission.cell->binding_generation = admission.event.binding_generation;
  admission.cell->association_token = event.association_token;
  admission.cell->session_handle = event.session_handle;
  admission.cell->owner_thread = event.owner_thread;
  admission.cell->request_vcl_application_association = event.vcl_application_association;
  admission.cell->ticket_sequence = ticket;
  admission.sidecar->queue_identity = attachment->segment->header.queue_identity;
  admission.sidecar->queue_generation = attachment->segment->header.queue_generation;
  admission.sidecar->ticket_sequence = ticket;
  admission.sidecar->allocation_nonce = ticket;
  admission.sidecar->directory_nonce = admission.event.directory_nonce;
  admission.sidecar->attachment_instance = admission.event.attachment_instance;
  admission.sidecar->binding_generation = admission.event.binding_generation;
  admission.sidecar->attachment_slot = slot;
  clib_atomic_store_rel_n (&directory->admissions, 1);
  clib_atomic_store_rel_n (&directory->reservations, 1);
  clib_atomic_store_rel_n (&directory->references, 1);
  clib_atomic_store_rel_n (&admission.cell->references, 1);
  clib_atomic_store_rel_n (&admission.cell->cell_references, 1);
  clib_atomic_store_rel_n (&admission.cell->admission_pin, 1);
  clib_atomic_store_rel_n (&admission.cell->reservation_pin, 1);
  clib_atomic_store_rel_n (&admission.sidecar->references, 1);
  clib_atomic_store_rel_n (&admission.sidecar->ticket_state,
			   SESSION_OBSERVABILITY_TICKET_LOCAL_RESERVED);
  clib_atomic_store_rel_n (&admission.cell->cell_state, SESSION_OBSERVABILITY_CELL_RESERVED);
  queue_ticket = (svm_msg_q_observability_ticket_t){
    .state = &admission.sidecar->ticket_state,
    .cancellation = &admission.cell->cancellation,
    .ring_index = &admission.sidecar->ring_index,
    .ring_element_index = &admission.sidecar->ring_element_index,
    .descriptor_element_index = &admission.sidecar->descriptor_element_index,
  };
  completion = clib_mem_alloc (sizeof (*completion));
  if (!completion)
    {
      result = SESSION_OBSERVABILITY_RESULT_QUEUE_BROKEN;
      goto release;
    }
  *completion = (sapi_observability_completion_t){
    .app_ns_index = app_namespace_index (app_ns),
    .socket_index = appns_sapi_socket_index (app_ns, cs),
    .app_wrk_index = app_wrk_index,
    .descriptor = attachment->descriptor,
  };
  if (session_observability_dispatch_prepare_with_completion (
	admission.owner, &admission.event, &dispatch, sapi_observability_completion_notify,
	completion))
    {
      clib_mem_free (completion);
      completion = 0;
      result = SESSION_OBSERVABILITY_RESULT_QUEUE_BROKEN;
      goto release;
    }
  queue_rv = svm_msg_q_observability_try_reserve_commit (admission.owner->queue, 0, &queue_ticket,
							 &admission.event, sizeof (admission.event),
							 &queue_msg);
  if (queue_rv != SVM_MSG_Q_OBSERVABILITY_COMMITTED_NOTIFIED &&
      queue_rv != SVM_MSG_Q_OBSERVABILITY_COMMITTED_NOTIFY_DEFERRED)
    {
      session_observability_dispatch_cancel (&dispatch);
      clib_mem_free (completion);
      completion = 0;
      result = session_observability_queue_result (queue_rv);
      goto release;
    }
  clib_atomic_store_rel_n (&admission.cell->cell_state, SESSION_OBSERVABILITY_CELL_QUEUED);
  if (session_observability_dispatch_commit (&dispatch))
    {
      (void) svm_msg_q_observability_cancel (&queue_ticket);
      session_observability_dispatch_retry (&dispatch);
    }
  return 0;

release:
  session_observability_cell_complete (admission.cell, result);
  session_observability_producer_release (&admission);
direct:
  sapi_observability_completion_direct (app_ns, cs, app_wrk, attachment, request->request_id,
					result);
  return 0;
}

int
session_observability_test_attachment_create (u32 app_wrk_index)
{
  app_worker_t *app_wrk = app_worker_get_if_valid (app_wrk_index);
  sapi_observability_attachment_t *attachment;

  if (!app_wrk)
    return -1;
  attachment = sapi_observability_attachment_create (app_wrk);
  if (!attachment)
    return -1;
  return sapi_observability_attachment_control_for_bapi (
    APP_INVALID_INDEX, app_wrk->observability_association, &attachment->descriptor,
    SESSION_OBSERVABILITY_HEADER_MAP_VALID);
}

int
session_observability_test_socket_control (clib_socket_t *cs, app_sapi_msg_t *msg,
					   u32 app_wrk_index)
{
  return sapi_observability_control_handler (cs, msg, app_wrk_index);
}

void
session_observability_test_bapi_request (vl_api_app_observability_request_v2_t *mp)
{
  vl_api_app_observability_request_v2_t_handler (mp);
}

void
session_observability_test_peer_dead (u32 app_wrk_index)
{
  sapi_observability_attachment_destroy (sapi_observability_attachment_find (app_wrk_index, 0));
}

static void
session_api_attach_handler (app_namespace_t *app_ns, clib_socket_t *cs, app_sapi_attach_msg_t *mp,
			    u8 is_v2)
{
  int rv = 0, *fds = 0, n_fds = 0, i, n_workers;
  vnet_app_attach_args_t _a, *a = &_a;
  app_sapi_attach_reply_msg_t *rmp;
  u8 fd_flags = 0, ctrl_thread;
  app_ns_api_handle_t *handle;
  fifo_segment_t *rx_mqs_seg;
  app_sapi_legacy_msg_t legacy_msg = { 0 };
  app_sapi_msg_t v2_msg = { 0 };
  app_worker_t *app_wrk;
  application_t *app;
  svm_msg_q_t *rx_mq;
  sapi_observability_attachment_t *attachment = 0;

  /* Make sure name is null terminated */
  mp->name[63] = 0;

  clib_memset (a, 0, sizeof (*a));
  a->api_client_index = appns_sapi_socket_handle (app_ns, cs);
  a->name = format (0, "%s", (char *) mp->name);
  a->options = mp->options;
  a->session_cb_vft = &session_mq_sapi_cb_vft;
  a->use_sock_api = 1;
  a->options[APP_OPTIONS_NAMESPACE] = app_namespace_index (app_ns);

  if ((rv = vnet_application_attach (a)))
    {
      clib_warning ("attach returned: %d", rv);
      goto done;
    }

  n_workers = vlib_num_workers ();
  vec_validate (fds, 4 /* segs + attachment + tx evtfd */ + n_workers);

  /* Send event queues segment */
  app = application_get (a->app_index);
  rx_mqs_seg = application_get_rx_mqs_segment (app);

  fd_flags |= SESSION_FD_F_VPP_MQ_SEGMENT;
  fds[n_fds] = rx_mqs_seg->ssvm.fd;
  n_fds += 1;

  /* Send fifo segment fd if needed */
  if (ssvm_type (a->segment) == SSVM_SEGMENT_MEMFD)
    {
      fd_flags |= SESSION_FD_F_MEMFD_SEGMENT;
      fds[n_fds] = a->segment->fd;
      n_fds += 1;
    }
  app_wrk = application_get_worker (app, 0);
  if (is_v2)
    {
      attachment = sapi_observability_attachment_create (app_wrk);
      if (!attachment)
	{
	  rv = SESSION_E_ALLOC;
	  n_fds = 0;
	  fd_flags = 0;
	  goto done;
	}
      fd_flags |= SESSION_FD_F_OBSERVABILITY_ATTACHMENT;
      fds[n_fds++] = attachment->fd;
    }
  if (a->options[APP_OPTIONS_FLAGS] & APP_OPTIONS_FLAGS_EVT_MQ_USE_EVENTFD)
    {
      fd_flags |= SESSION_FD_F_MQ_EVENTFD;
      fds[n_fds] = svm_msg_q_get_eventfd (a->app_evt_q);
      n_fds += 1;
    }

  if (application_use_private_rx_mqs ())
    {
      fd_flags |= SESSION_FD_F_VPP_MQ_EVENTFD;
      for (i = 0; i < n_workers + 1; i++)
	{
	  rx_mq = application_rx_mq_get (app, i);
	  fds[n_fds] = svm_msg_q_get_eventfd (rx_mq);
	  n_fds += 1;
	}
    }

done:
  if (is_v2)
    {
      v2_msg.type = APP_SAPI_MSG_TYPE_ATTACH_V2_REPLY;
      rmp = &v2_msg.attach_v2_reply.base;
      v2_msg.attach_v2_reply.abi = SESSION_OBSERVABILITY_ABI_VERSION;
      if (!rv)
	{
	  v2_msg.attach_v2_reply.association = app_wrk->wrk_index;
	  v2_msg.attach_v2_reply.descriptor = attachment->descriptor;
	}
    }
  else
    {
      legacy_msg.type = APP_SAPI_MSG_TYPE_ATTACH_REPLY;
      rmp = &legacy_msg.attach_reply;
    }
  rmp->retval = rv;
  if (!rv)
    {
      ctrl_thread = n_workers ? 1 : 0;
      rmp->app_index = a->app_index;
      rmp->app_mq = fifo_segment_msg_q_offset ((fifo_segment_t *) a->segment, 0);
      rmp->vpp_ctrl_mq = fifo_segment_msg_q_offset (rx_mqs_seg, ctrl_thread);
      rmp->vpp_ctrl_mq_thread = ctrl_thread;
      rmp->n_fds = n_fds;
      rmp->fd_flags = fd_flags;
      /* No segment name and size since we only support memfds
       * in this configuration */
      rmp->segment_handle = a->segment_handle;
      rmp->api_client_handle = a->api_client_index;

      /* Update app index for socket */
      handle = (app_ns_api_handle_t *) &cs->private_data;
      handle->aah_app_wrk_index = app_wrk->wrk_index;
    }

  clib_socket_sendmsg (cs, is_v2 ? (void *) &v2_msg : (void *) &legacy_msg,
		       is_v2 ? sizeof (v2_msg) : sizeof (legacy_msg), fds, n_fds);
  vec_free (a->name);
  vec_free (fds);
}

static void
sapi_socket_close (app_namespace_t *app_ns, clib_socket_t *cs)
{
  app_ns_api_handle_t *handle;
  clib_file_t *cf;
  clib_error_t *err;

  handle = (app_ns_api_handle_t *) &cs->private_data;
  cf = clib_file_get (&file_main, handle->aah_file_index);
  if (cf)
    clib_file_del (&file_main, cf);

  sapi_observability_attachment_destroy (
    sapi_observability_attachment_find (handle->aah_app_wrk_index, 0));

  /* SAPI owns descriptors registered with dont_close. Retire the descriptor
   * before returning this socket slot to the namespace pool. */
  if (cs->fd >= 0)
    {
      err = clib_socket_close (cs);
      clib_error_free (err);
      cs->fd = -1;
    }
  appns_sapi_free_socket (app_ns, cs);
}

void
sapi_socket_close_w_handle (u32 api_handle)
{
  app_namespace_t *app_ns;
  clib_socket_t *cs;

  app_ns = app_namespace_get_if_valid (api_handle >> 16);
  if (!app_ns)
    return;
  cs = appns_sapi_get_socket (app_ns, api_handle & 0xffff);
  if (!cs)
    return;
  sapi_socket_close (app_ns, cs);
}

static void
sapi_add_del_worker_handler (app_namespace_t *app_ns, clib_socket_t *cs,
			     app_sapi_worker_add_del_msg_t *mp, u8 is_v2)
{
  int rv = 0, fds[SESSION_N_FD_TYPE], n_fds = 0;
  app_sapi_worker_add_del_reply_msg_t *rmp;
  app_ns_api_handle_t *handle;
  app_sapi_legacy_msg_t msg = { 0 };
  app_sapi_msg_t msg_v2 = { 0 };
  app_worker_t *app_wrk;
  sapi_observability_attachment_t *attachment = 0;
  u32 sapi_handle = -1;
  application_t *app;
  u8 fd_flags = 0;

  app = application_get_if_valid (mp->app_index);
  if (!app)
    {
      rv = SESSION_E_INVALID;
      goto done;
    }

  sapi_handle = appns_sapi_socket_handle (app_ns, cs);

  vnet_app_worker_add_del_args_t args = { .app_index = app->app_index,
					  .wrk_map_index = mp->wrk_index,
					  .api_client_index = sapi_handle,
					  .is_add = mp->is_add };
  rv = vnet_app_worker_add_del (&args);
  if (rv)
    {
      clib_warning ("app worker add/del returned: %U", format_session_error, rv);
      goto done;
    }

  if (!mp->is_add)
    goto done;

  /* Send fifo segment fd if needed */
  if (ssvm_type (args.segment) == SSVM_SEGMENT_MEMFD)
    {
      fd_flags |= SESSION_FD_F_MEMFD_SEGMENT;
      fds[n_fds] = args.segment->fd;
      n_fds += 1;
    }
  app_wrk = application_get_worker (app, args.wrk_map_index);
  if (is_v2)
    {
      attachment = sapi_observability_attachment_create (app_wrk);
      if (!attachment)
	{
	  rv = SESSION_E_ALLOC;
	  n_fds = 0;
	  fd_flags = 0;
	  goto done;
	}
      fd_flags |= SESSION_FD_F_OBSERVABILITY_ATTACHMENT;
      fds[n_fds++] = attachment->fd;
    }
  if (application_segment_manager_properties (app)->use_mq_eventfd)
    {
      fd_flags |= SESSION_FD_F_MQ_EVENTFD;
      fds[n_fds] = svm_msg_q_get_eventfd (args.evt_q);
      n_fds += 1;
    }

done:

  /* With app sock api socket expected to be closed, no reply */
  if (!mp->is_add && appns_sapi_enabled ())
    return;

  if (is_v2)
    {
      msg_v2.type = APP_SAPI_MSG_TYPE_ADD_DEL_WORKER_V2_REPLY;
      msg_v2.worker_add_del_v2_reply.abi = SESSION_OBSERVABILITY_ABI_VERSION;
      rmp = &msg_v2.worker_add_del_v2_reply.base;
    }
  else
    {
      msg.type = APP_SAPI_MSG_TYPE_ADD_DEL_WORKER_REPLY;
      rmp = &msg.worker_add_del_reply;
    }
  rmp->retval = rv;
  rmp->is_add = mp->is_add;
  rmp->wrk_index = mp->wrk_index;
  rmp->api_client_handle = sapi_handle;
  if (!rv && mp->is_add)
    {
      rmp->wrk_index = args.wrk_map_index;
      rmp->segment_handle = args.segment_handle;
      /* No segment name and size. This supports only memfds */
      rmp->app_event_queue_address = fifo_segment_msg_q_offset ((fifo_segment_t *) args.segment, 0);
      rmp->n_fds = n_fds;
      rmp->fd_flags = fd_flags;

      /* Update app index for socket */
      handle = (app_ns_api_handle_t *) &cs->private_data;
      handle->aah_app_wrk_index = app_wrk->wrk_index;
      if (is_v2)
	{
	  msg_v2.worker_add_del_v2_reply.association = app_wrk->wrk_index;
	  msg_v2.worker_add_del_v2_reply.descriptor = attachment->descriptor;
	}
    }

  clib_socket_sendmsg (cs, is_v2 ? (void *) &msg_v2 : (void *) &msg,
		       is_v2 ? sizeof (msg_v2) : sizeof (msg), fds, n_fds);
}

/* This is a workaround for the case when session layer starts reading
 * the socket before the client actualy sends the data
 */
static clib_error_t *
sapi_socket_receive_wait (clib_socket_t *cs, u8 *msg, u32 msg_len)
{
  clib_error_t *err;
  int n_tries = 5;

  while (1)
    {
      err = clib_socket_recvmsg (cs, msg, msg_len, 0, 0);
      if (!err)
	break;

      if (!n_tries)
	return err;

      n_tries--;
      usleep (1);
    }

  return err;
}

static void
sapi_add_del_cert_key_handler (app_namespace_t *app_ns, clib_socket_t *cs,
			       app_sapi_cert_key_add_del_msg_t *mp)
{
  vnet_app_add_cert_key_pair_args_t _a, *a = &_a;
  app_sapi_cert_key_add_del_reply_msg_t *rmp;
  app_sapi_legacy_msg_t msg = { 0 };
  int rv = 0;

  if (mp->is_add)
    {
      const u32 max_certkey_len = 2e4, max_cert_len = 1e4, max_key_len = 1e4;
      clib_error_t *err;
      u8 *certkey = 0;
      u32 key_len;

      if (mp->certkey_len > max_certkey_len)
	{
	  rv = SESSION_E_INVALID;
	  goto send_reply;
	}

      vec_validate (certkey, mp->certkey_len - 1);

      err = sapi_socket_receive_wait (cs, certkey, mp->certkey_len);
      if (err)
	{
	  clib_error_report (err);
	  rv = SESSION_E_INVALID;
	  goto send_reply;
	}

      if (mp->cert_len > max_cert_len)
	{
	  rv = SESSION_E_INVALID;
	  goto send_reply;
	}

      if (mp->certkey_len < mp->cert_len)
	{
	  rv = SESSION_E_INVALID;
	  goto send_reply;
	}

      key_len = mp->certkey_len - mp->cert_len;
      if (key_len > max_key_len)
	{
	  rv = SESSION_E_INVALID;
	  goto send_reply;
	}

      clib_memset (a, 0, sizeof (*a));
      a->cert = certkey;
      a->key = certkey + mp->cert_len;
      a->cert_len = mp->cert_len;
      a->key_len = key_len;
      rv = vnet_app_add_cert_key_pair (a);

      vec_free (certkey);
    }
  else
    {
      rv = vnet_app_del_cert_key_pair (mp->index);
    }

send_reply:

  msg.type = APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY_REPLY;
  rmp = &msg.cert_key_add_del_reply;
  rmp->retval = rv;
  rmp->context = mp->context;
  if (!rv && mp->is_add)
    rmp->index = a->index;

  clib_socket_sendmsg (cs, &msg, sizeof (msg), 0, 0);
}

static void
sapi_socket_detach (app_namespace_t *app_ns, clib_socket_t *cs)
{
  app_ns_api_handle_t *handle;
  app_worker_t *app_wrk;
  u32 api_client_handle;

  api_client_handle = appns_sapi_socket_handle (app_ns, cs);

  /* Cleanup everything because app worker closed socket or crashed */
  handle = (app_ns_api_handle_t *) &cs->private_data;
  app_wrk = app_worker_get_if_valid (handle->aah_app_wrk_index);
  if (!app_wrk)
    {
      /* A malformed frame can arrive before ATTACH binds this connection to
       * an application worker.  It still owns a registered file and must be
       * released, otherwise rejecting a frame leaves a live endpoint behind. */
      sapi_socket_close (app_ns, cs);
      return;
    }

  sapi_observability_attachment_destroy (
    sapi_observability_attachment_find (app_wrk->wrk_index, 0));

  vnet_app_worker_add_del_args_t args = { .app_index = app_wrk->app_index,
					  .wrk_map_index = app_wrk->wrk_map_index,
					  .api_client_index = api_client_handle,
					  .is_add = 0 };
  /* Send rpc to main thread for worker barrier */
  vlib_rpc_call_main_thread (vnet_app_worker_add_del, (u8 *) &args, sizeof (args));
}

static clib_error_t *
sapi_sock_read_ready (clib_file_t *cf)
{
  app_ns_api_handle_t *handle = (app_ns_api_handle_t *) &cf->private_data;
  vlib_main_t *vm = vlib_get_main ();
  app_sapi_msg_t msg = { 0 };
  app_namespace_t *app_ns;
  clib_error_t *err = 0;
  clib_socket_t *cs;
  ssize_t bytes;
  int flags;
  int fds[SESSION_N_FD_TYPE];
  u32 n_fds, i;
  u8 is_v2;

  if (PREDICT_FALSE (!cf->active))
    return 0;

  is_v2 = !!(handle->aah_app_ns_index & (1U << 31));
  app_ns = app_namespace_get (handle->aah_app_ns_index & ~(1U << 31));
  cs = appns_sapi_get_socket (app_ns, handle->aah_sock_index);
  if (!cs)
    goto error;

  err = clib_socket_recvmsg_with_result (cs, &msg, sizeof (msg), fds, ARRAY_LEN (fds), &bytes,
					 &flags, &n_fds);
  if (err)
    {
      clib_error_free (err);
      sapi_socket_detach (app_ns, cs);
      goto error;
    }

  if (n_fds || (flags & (MSG_TRUNC | MSG_CTRUNC)) ||
      (is_v2 && (bytes != sizeof (msg) || app_sapi_msg_v2_validate (&msg))) ||
      (!is_v2 && bytes != sizeof (app_sapi_legacy_msg_t)))
    {
      for (i = 0; i < ARRAY_LEN (fds); i++)
	if (fds[i] >= 0)
	  close (fds[i]);
      sapi_socket_detach (app_ns, cs);
      goto error;
    }

  handle = (app_ns_api_handle_t *) &cs->private_data;

  vlib_worker_thread_barrier_sync (vm);

  if (is_v2)
    {
      /* Before ATTACH this endpoint has no worker ownership.  Only the
       * versioned attach request can establish that ownership; every other
       * v2 discriminator must retire this connection without entering the
       * worker or observability-control dispatch paths. */
      if (handle->aah_app_wrk_index == APP_INVALID_INDEX)
	{
	  if (msg.type == APP_SAPI_MSG_TYPE_ATTACH_V2 &&
	      msg.attach_v2.abi == SESSION_OBSERVABILITY_ABI_VERSION)
	    session_api_attach_handler (app_ns, cs, &msg.attach_v2.base, 1);
	  else
	    sapi_socket_close (app_ns, cs);
	  vlib_worker_thread_barrier_release (vm);
	  return 0;
	}

      switch (msg.type)
	{
	case APP_SAPI_MSG_TYPE_ATTACH_V2:
	  if (msg.attach_v2.abi == SESSION_OBSERVABILITY_ABI_VERSION)
	    session_api_attach_handler (app_ns, cs, &msg.attach_v2.base, 1);
	  else
	    sapi_socket_detach (app_ns, cs);
	  break;
	case APP_SAPI_MSG_TYPE_ADD_DEL_WORKER_V2:
	  if (msg.worker_add_del_v2.abi == SESSION_OBSERVABILITY_ABI_VERSION)
	    sapi_add_del_worker_handler (app_ns, cs, &msg.worker_add_del_v2.base, 1);
	  else
	    sapi_socket_detach (app_ns, cs);
	  break;
	case APP_SAPI_MSG_TYPE_OBS_ATTACH_ACK_V2:
	case APP_SAPI_MSG_TYPE_OBS_DETACH_V2:
	case APP_SAPI_MSG_TYPE_OBS_DONE_V2_REPLY:
	  if (sapi_observability_control_handler (cs, &msg, handle->aah_app_wrk_index))
	    sapi_socket_detach (app_ns, cs);
	  break;
	case APP_SAPI_MSG_TYPE_OBS_REQUEST_V2:
	  if (sapi_observability_request_handler (app_ns, cs, &msg, handle->aah_app_wrk_index))
	    sapi_socket_detach (app_ns, cs);
	  break;
	default:
	  clib_warning ("app wrk %u unknown v2 message type: %u", handle->aah_app_wrk_index,
			msg.type);
	  sapi_socket_detach (app_ns, cs);
	  break;
	}
      vlib_worker_thread_barrier_release (vm);
      return 0;
    }

  switch (msg.type)
    {
    case APP_SAPI_MSG_TYPE_ATTACH:
      session_api_attach_handler (app_ns, cs, &msg.attach, 0);
      break;
    case APP_SAPI_MSG_TYPE_ADD_DEL_WORKER:
      sapi_add_del_worker_handler (app_ns, cs, &msg.worker_add_del, 0);
      break;
    case APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY:
      sapi_add_del_cert_key_handler (app_ns, cs, &msg.cert_key_add_del);
      break;
    default:
      clib_warning ("app wrk %u unknown message type: %u", handle->aah_app_wrk_index, msg.type);
      break;
    }

  vlib_worker_thread_barrier_release (vm);

error:
  return 0;
}

static clib_error_t *
sapi_sock_write_ready (clib_file_t *cf)
{
  app_ns_api_handle_t *handle = (app_ns_api_handle_t *) &cf->private_data;

  if (PREDICT_FALSE (!cf->active))
    return 0;

  clib_warning ("called for app ns %u", handle->aah_app_ns_index);
  return 0;
}

static clib_error_t *
sapi_sock_error (clib_file_t *cf)
{
  app_ns_api_handle_t *handle = (app_ns_api_handle_t *) &cf->private_data;
  app_namespace_t *app_ns;
  clib_socket_t *cs;

  if (PREDICT_FALSE (!cf->active))
    return 0;

  app_ns = app_namespace_get (handle->aah_app_ns_index & ~(1U << 31));
  cs = appns_sapi_get_socket (app_ns, handle->aah_sock_index);
  if (!cs)
    return 0;

  sapi_socket_detach (app_ns, cs);
  return 0;
}

static clib_error_t *
sapi_sock_accept_ready (clib_file_t *scf)
{
  app_ns_api_handle_t handle = *(app_ns_api_handle_t *) &scf->private_data;
  app_namespace_t *app_ns;
  clib_file_t cf = { 0 };
  clib_error_t *err = 0;
  clib_socket_t *ccs, *scs;

  /* Listener files point to namespace */
  app_ns = app_namespace_get (handle.aah_app_ns_index & ~(1U << 31));

  /*
   * Initialize client socket
   */
  ccs = appns_sapi_alloc_socket (app_ns);

  /* Grab server socket after client is initialized  */
  scs = appns_sapi_get_socket (app_ns, handle.aah_sock_index);
  if (!scs)
    goto error;

  err = clib_socket_accept (scs, ccs);
  if (err)
    {
      clib_error_report (err);
      goto error;
    }

  cf.read_function = sapi_sock_read_ready;
  cf.write_function = sapi_sock_write_ready;
  cf.error_function = sapi_sock_error;
  cf.file_descriptor = ccs->fd;
  cf.dont_close = 1;
  /* File points to app namespace and socket */
  handle.aah_sock_index = appns_sapi_socket_index (app_ns, ccs);
  cf.private_data = handle.as_u64;
  cf.description = format (0, "app sock conn fd: %d", ccs->fd);

  /* Poll until we get an attach message. Socket points to file and
   * application that owns the socket */
  handle.aah_app_wrk_index = APP_INVALID_INDEX;
  handle.aah_file_index = clib_file_add (&file_main, &cf);
  ccs->private_data = handle.as_u64;

  return err;

error:
  appns_sapi_free_socket (app_ns, ccs);
  return err;
}

void
appns_sapi_del_ns_socket (app_namespace_t *app_ns)
{
  app_ns_api_handle_t *handle;
  clib_socket_t *cs;

  pool_foreach (cs, app_ns->app_sockets)
    {
      handle = (app_ns_api_handle_t *) &cs->private_data;
      clib_file_del_by_index (&file_main, handle->aah_file_index);

      clib_socket_close (cs);
      clib_socket_free (cs);
    }
  pool_free (app_ns->app_sockets);
}

int
appns_sapi_add_ns_socket (app_namespace_t *app_ns)
{
  char *subdir = "/app_ns_sockets/";
  app_ns_api_handle_t *handle;
  clib_file_t cf = { 0 };
  struct stat file_stat;
  clib_error_t *err;
  clib_socket_t *cs;
  u8 *v2_sock_name = 0;
  u32 is_v2;
  char dir[4096];

  snprintf (dir, sizeof (dir), "%s%s", vlib_unix_get_runtime_dir (), subdir);

  if (!app_ns->sock_name)
    app_ns->sock_name = format (0, "%s%v%c", dir, app_ns->ns_id, 0);

  if (clib_socket_prefix_get_type ((char *) app_ns->sock_name) == CLIB_SOCKET_TYPE_UNIX)
    {
      err = vlib_unix_recursive_mkdir ((char *) dir);
      if (err)
	{
	  clib_error_report (err);
	  return SESSION_E_SYSCALL;
	}
    }
  /* The v2 listener is a distinct endpoint.  A connection is classified at
   * accept time, before its first byte is read, so no socket accepts both
   * fixed frame sizes. */
  v2_sock_name = format (0, "%s.v2%c", app_ns->sock_name, 0);
  for (is_v2 = 0; is_v2 < 2; is_v2++)
    {
      cs = appns_sapi_alloc_socket (app_ns);
      cs->config = (char *) vec_dup (is_v2 ? v2_sock_name : app_ns->sock_name);
      cs->flags = CLIB_SOCKET_F_IS_SERVER | CLIB_SOCKET_F_ALLOW_GROUP_WRITE |
		  CLIB_SOCKET_F_SEQPACKET | CLIB_SOCKET_F_PASSCRED;
      if ((err = clib_socket_init (cs)))
	{
	  clib_error_report (err);
	  vec_free (v2_sock_name);
	  return -1;
	}
      if (clib_socket_prefix_get_type (cs->config) == CLIB_SOCKET_TYPE_UNIX &&
	  stat (cs->config, &file_stat) == -1)
	{
	  vec_free (v2_sock_name);
	  return -1;
	}

      cf.read_function = sapi_sock_accept_ready;
      cf.file_descriptor = cs->fd;
      cf.dont_close = 1;
      handle = (app_ns_api_handle_t *) &cf.private_data;
      handle->aah_app_ns_index = app_namespace_index (app_ns) | (is_v2 ? (1U << 31) : 0);
      handle->aah_sock_index = appns_sapi_socket_index (app_ns, cs);
      cf.description = format (0, "app sock %slistener: %s", is_v2 ? "v2 " : "", cs->config);

      handle = (app_ns_api_handle_t *) &cs->private_data;
      handle->aah_file_index = clib_file_add (&file_main, &cf);
      handle->aah_app_wrk_index = APP_INVALID_INDEX;
    }
  vec_free (v2_sock_name);

  return 0;
}

#include <vnet/session/session.api.c>
static clib_error_t *
session_api_hookup (vlib_main_t *vm)
{
  api_main_t *am = vlibapi_get_main ();

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_SESSION_SDL_ADD_DEL, 1);
  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_SESSION_SDL_ADD_DEL_V2, 1);
  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_SESSION_SDL_ADD_DEL_REPLY, 1);
  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_SESSION_SDL_DUMP, 1);
  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_SESSION_SDL_DETAILS, 1);
  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_SESSION_SDL_ADD_DEL_V2_REPLY, 1);
  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_SESSION_SDL_V2_DUMP, 1);
  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_SESSION_SDL_V2_DETAILS, 1);
  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_SESSION_SDL_V3_DUMP, 1);
  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_SESSION_SDL_V3_DETAILS, 1);
  return 0;
}

VLIB_API_INIT_FUNCTION (session_api_hookup);
