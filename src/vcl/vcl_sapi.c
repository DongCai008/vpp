/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vcl/vcl_private.h>
#include <sys/mman.h>
#include <sys/stat.h>

static int
vcl_api_uses_app_socket_v2 (void)
{
  return vcm->cfg.vpp_app_socket_api_v2 != 0;
}

int vcl_sapi_detach (vcl_worker_t *wrk);

static void
vcl_api_close_fds (int *fds, u32 n_fds)
{
  u32 i;

  for (i = 0; i < n_fds; i++)
    if (fds[i] >= 0)
      close (fds[i]);
}

static void
vcl_api_close_app_socket (vcl_worker_t *wrk)
{
  clib_socket_t *cs = &wrk->app_api_sock;

  if (cs->close_func && cs->fd >= 0)
    (void) clib_socket_close (cs);
  cs->fd = -1;
}

static void
vcl_api_unmap_observability_attachment (vcl_worker_t *wrk)
{
  if (wrk->observability_segment)
    munmap (wrk->observability_segment, SESSION_OBSERVABILITY_SEGMENT_BYTES);
  if (wrk->observability_fd >= 0)
    close (wrk->observability_fd);
  wrk->observability_segment = 0;
  wrk->observability_fd = -1;
  clib_memset (&wrk->observability_descriptor, 0, sizeof (wrk->observability_descriptor));
  wrk->observability_association = 0;
}

static int
vcl_api_recv_v2_frame (clib_socket_t *cs, app_sapi_msg_t *msg, int *fds, u32 n_fds,
		       u32 *received_fds)
{
  clib_error_t *err;
  ssize_t bytes;
  int flags;
  u32 i;

  for (i = 0; i < n_fds; i++)
    fds[i] = -1;
  err = clib_socket_recvmsg_with_result (cs, msg, sizeof (*msg), fds, n_fds, &bytes, &flags,
					 received_fds);
  if (err)
    {
      clib_error_report (err);
      vcl_api_close_fds (fds, n_fds);
      return -1;
    }
  if (bytes == sizeof (*msg) && !(flags & (MSG_TRUNC | MSG_CTRUNC)) &&
      !app_sapi_msg_v2_validate (msg))
    return 0;

  vcl_api_close_fds (fds, n_fds);
  return -1;
}

static int
vcl_api_observability_header_is_valid (const session_observability_segment_t *segment,
				       const session_observability_descriptor_t *descriptor)
{
  const session_observability_header_t *header = &segment->header;
  uword i;

  if (header->magic != 0x3256545441504354ULL || header->abi != SESSION_OBSERVABILITY_ABI_VERSION ||
      header->header_bytes != sizeof (*header) || header->little_endian_marker != 0x01020304 ||
      header->layout_hash != SESSION_OBSERVABILITY_LAYOUT_HASH ||
      header->total_bytes != sizeof (*segment) ||
      header->directory_offset != offsetof (session_observability_segment_t, directory) ||
      header->directory_count != SESSION_OBSERVABILITY_SLOT_COUNT ||
      header->directory_stride != sizeof (segment->directory[0]) ||
      header->cell_offset != offsetof (session_observability_segment_t, cell) ||
      header->cell_count != SESSION_OBSERVABILITY_SLOT_COUNT ||
      header->cell_stride != sizeof (segment->cell[0]) ||
      header->sidecar_offset != offsetof (session_observability_segment_t, sidecar) ||
      header->sidecar_count != SESSION_OBSERVABILITY_SLOT_COUNT ||
      header->sidecar_stride != sizeof (segment->sidecar[0]) || header->event_bytes != 80 ||
      header->descriptor_bytes != sizeof (*descriptor) ||
      header->segment_handle != descriptor->segment_handle ||
      header->attachment_instance != descriptor->attachment_instance ||
      header->attach_generation != descriptor->attach_generation ||
      header->queue_identity != descriptor->queue_identity ||
      header->queue_generation != descriptor->queue_generation ||
      clib_atomic_load_acq_n (&header->lifecycle) != SESSION_OBSERVABILITY_HEADER_CREATED)
    return -1;
  for (i = 0; i < ARRAY_LEN (header->reserved_zero0); i++)
    if (header->reserved_zero0[i])
      return -1;
  for (i = 0; i < ARRAY_LEN (header->reserved_zero1); i++)
    if (header->reserved_zero1[i])
      return -1;
  return 0;
}

static int
vcl_api_map_observability_attachment (u8 fd_flags,
				      const session_observability_descriptor_t *descriptor,
				      u32 association, int *fds, u32 n_fds)
{
  session_observability_segment_t *segment;
  vcl_worker_t *wrk = vcl_worker_get_current ();
  struct stat st;
  u32 fd_index = 0;
  int fd;

  if (!(fd_flags & SESSION_FD_F_OBSERVABILITY_ATTACHMENT))
    return -1;
  if (fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
    fd_index++;
  if (fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
    fd_index++;
  if (fd_index >= n_fds || fds[fd_index] < 0)
    return -1;
  fd = fds[fd_index];
  if (fstat (fd, &st) || st.st_size != SESSION_OBSERVABILITY_SEGMENT_BYTES)
    return -1;
  segment =
    mmap (0, SESSION_OBSERVABILITY_SEGMENT_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (segment == MAP_FAILED || vcl_api_observability_header_is_valid (segment, descriptor))
    {
      if (segment != MAP_FAILED)
	munmap (segment, SESSION_OBSERVABILITY_SEGMENT_BYTES);
      return -1;
    }
  vcl_api_unmap_observability_attachment (wrk);
  wrk->observability_fd = fd;
  wrk->observability_segment = segment;
  wrk->observability_descriptor = *descriptor;
  wrk->observability_association = association;
  fds[fd_index] = -1;
  return 0;
}

static int
vcl_api_send_observability_control (clib_socket_t *cs, app_sapi_msg_type_e type,
				    const session_observability_descriptor_t *descriptor,
				    u32 association)
{
  app_sapi_msg_t request = { 0 }, response;
  clib_error_t *err;
  int fds[1];
  u32 n_fds;

  request.type = type;
  request.observability_control_v2.association = association;
  request.observability_control_v2.descriptor = *descriptor;
  err = clib_socket_sendmsg (cs, &request, sizeof (request), 0, 0);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }
  if (vcl_api_recv_v2_frame (cs, &response, fds, ARRAY_LEN (fds), &n_fds) || n_fds ||
      response.type != type + 1 || response.observability_control_v2_reply.retval ||
      response.observability_control_v2_reply.association != association ||
      memcmp (&response.observability_control_v2_reply.descriptor, descriptor,
	      sizeof (*descriptor)))
    {
      vcl_api_close_fds (fds, ARRAY_LEN (fds));
      return -1;
    }
  return 0;
}

static int
vcl_api_ack_observability_done (clib_socket_t *cs,
				const session_observability_descriptor_t *descriptor,
				u32 association)
{
  app_sapi_msg_t request = { 0 }, response = { 0 };
  clib_error_t *err;
  vcl_worker_t *wrk = vcl_worker_get_current ();
  int fds[1];
  u32 n_fds;

  if (vcl_api_recv_v2_frame (cs, &request, fds, ARRAY_LEN (fds), &n_fds) || n_fds ||
      request.type != APP_SAPI_MSG_TYPE_OBS_DONE_V2 ||
      request.observability_control_v2.association != association ||
      memcmp (&request.observability_control_v2.descriptor, descriptor, sizeof (*descriptor)) ||
      !wrk->observability_segment || wrk->observability_fd < 0 ||
      wrk->observability_association != association ||
      memcmp (&wrk->observability_descriptor, descriptor, sizeof (*descriptor)) ||
      clib_atomic_load_acq_n (&wrk->observability_segment->header.lifecycle) !=
	SESSION_OBSERVABILITY_HEADER_DEAD)
    {
      vcl_api_close_fds (fds, ARRAY_LEN (fds));
      return -1;
    }
  response.type = APP_SAPI_MSG_TYPE_OBS_DONE_V2_REPLY;
  response.observability_control_v2_reply.association = association;
  response.observability_control_v2_reply.descriptor = *descriptor;
  err = clib_socket_sendmsg (cs, &response, sizeof (response), 0, 0);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }
  return 0;
}

static int
vcl_api_send_observability_attach_ack (clib_socket_t *cs)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();

  return vcl_api_send_observability_control (cs, APP_SAPI_MSG_TYPE_OBS_ATTACH_ACK_V2,
					     &wrk->observability_descriptor,
					     wrk->observability_association);
}

static int
vcl_api_connect_app_socket (vcl_worker_t *wrk)
{
  clib_socket_t *cs = &wrk->app_api_sock;
  clib_error_t *err;
  int rv = 0;

  cs->config = (char *) (vcl_api_uses_app_socket_v2 () ? vcm->cfg.vpp_app_socket_api_v2 :
							 vcm->cfg.vpp_app_socket_api);
  cs->flags = CLIB_SOCKET_F_IS_CLIENT | CLIB_SOCKET_F_SEQPACKET | CLIB_SOCKET_F_BLOCKING;

  if ((err = clib_socket_init (cs)))
    {
      /* don't report the error to avoid flood of error messages during
       * reconnect */
      clib_error_free (err);
      rv = -1;
      goto done;
    }

done:

  return rv;
}

static int
vcl_api_attach_reply_handler (app_sapi_attach_reply_msg_t *mp, int *fds)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  int i, rv, n_fds_used = 0;
  u64 segment_handle;
  u8 *segment_name;

  if (mp->retval)
    {
      VERR ("attach failed: %U", format_session_error, mp->retval);
      goto failed;
    }

  wrk->api_client_handle = mp->api_client_handle;
  /* reattaching via `vcl_api_retry_attach` wants wrk->vpp_wrk_index to be 0 */
  wrk->vpp_wrk_index = 0;
  segment_handle = mp->segment_handle;
  if (segment_handle == VCL_INVALID_SEGMENT_HANDLE)
    {
      VERR ("invalid segment handle");
      goto failed;
    }

  if (!mp->n_fds)
    goto failed;

  if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
    if (vcl_segment_attach (vcl_vpp_worker_segment_handle (0), "vpp-mq-seg", SSVM_SEGMENT_MEMFD,
			    fds[n_fds_used++]))
      goto failed;

  if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
    {
      segment_name = format (0, "memfd-%ld%c", segment_handle, 0);
      rv = vcl_segment_attach (segment_handle, (char *) segment_name, SSVM_SEGMENT_MEMFD,
			       fds[n_fds_used++]);
      vec_free (segment_name);
      if (rv != 0)
	goto failed;
    }

  /* The v2 attachment follows the ordinary segment descriptors. */
  if (mp->fd_flags & SESSION_FD_F_OBSERVABILITY_ATTACHMENT)
    n_fds_used++;

  vcl_segment_attach_mq (segment_handle, mp->app_mq, 0, &wrk->app_event_queue);

  if (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD)
    {
      svm_msg_q_set_eventfd (wrk->app_event_queue, fds[n_fds_used++]);
      vcl_mq_epoll_add_evfd (wrk, wrk->app_event_queue);
    }

  vcl_segment_discover_mqs (vcl_vpp_worker_segment_handle (0), fds + n_fds_used,
			    mp->n_fds - n_fds_used);
  vcl_segment_attach_mq (vcl_vpp_worker_segment_handle (0), mp->vpp_ctrl_mq, mp->vpp_ctrl_mq_thread,
			 &wrk->ctrl_mq);
  vcm->ctrl_mq = wrk->ctrl_mq;
  vcm->app_index = mp->app_index;

  return 0;

failed:

  for (i = clib_max (n_fds_used - 1, 0); i < mp->n_fds; i++)
    close (fds[i]);

  return -1;
}

static int
vcl_api_send_attach (clib_socket_t *cs)
{
  app_sapi_legacy_msg_t msg = { 0 };
  app_sapi_msg_t msg_v2 = { 0 };
  app_sapi_attach_msg_t *mp;
  u8 app_is_proxy, tls_engine = CRYPTO_ENGINE_OPENSSL;
  clib_error_t *err;

  if (vcl_api_uses_app_socket_v2 ())
    {
      msg_v2.type = APP_SAPI_MSG_TYPE_ATTACH_V2;
      msg_v2.attach_v2.abi = SESSION_OBSERVABILITY_ABI_VERSION;
      mp = &msg_v2.attach_v2.base;
    }
  else
    {
      msg.type = APP_SAPI_MSG_TYPE_ATTACH;
      mp = &msg.attach;
    }

  app_is_proxy = (vcm->cfg.app_proxy_transport_tcp || vcm->cfg.app_proxy_transport_udp);
  tls_engine = vcm->cfg.tls_engine ? vcm->cfg.tls_engine : tls_engine;

  clib_memcpy (&mp->name, vcm->app_name, vec_len (vcm->app_name));
  mp->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_ACCEPT_REDIRECT | APP_OPTIONS_FLAGS_ADD_SEGMENT |
    (vcm->cfg.app_scope_local ? APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE : 0) |
    (vcm->cfg.app_scope_global ? APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE : 0) |
    (app_is_proxy ? APP_OPTIONS_FLAGS_IS_PROXY : 0) |
    (vcm->cfg.use_mq_eventfd ? APP_OPTIONS_FLAGS_EVT_MQ_USE_EVENTFD : 0) |
    (vcm->cfg.huge_page ? APP_OPTIONS_FLAGS_USE_HUGE_PAGE : 0) |
    (vcm->cfg.app_original_dst ? APP_OPTIONS_FLAGS_GET_ORIGINAL_DST : 0);
  mp->options[APP_OPTIONS_PROXY_TRANSPORT] =
    (u64) ((vcm->cfg.app_proxy_transport_tcp ? 1 << TRANSPORT_PROTO_TCP : 0) |
	   (vcm->cfg.app_proxy_transport_udp ? 1 << TRANSPORT_PROTO_UDP : 0));
  mp->options[APP_OPTIONS_SEGMENT_SIZE] = vcm->cfg.segment_size;
  mp->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = vcm->cfg.add_segment_size;
  mp->options[APP_OPTIONS_RX_FIFO_SIZE] = vcm->cfg.rx_fifo_size;
  mp->options[APP_OPTIONS_TX_FIFO_SIZE] = vcm->cfg.tx_fifo_size;
  mp->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = vcm->cfg.preallocated_fifo_pairs;
  mp->options[APP_OPTIONS_EVT_QUEUE_SIZE] = vcm->cfg.event_queue_size;
  mp->options[APP_OPTIONS_TLS_ENGINE] = tls_engine;

  err = clib_socket_sendmsg (cs, vcl_api_uses_app_socket_v2 () ? (void *) &msg_v2 : (void *) &msg,
			     vcl_api_uses_app_socket_v2 () ? sizeof (msg_v2) : sizeof (msg), 0, 0);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }

  return 0;
}

int
vcl_sapi_attach (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  app_sapi_legacy_msg_t _rmp, *rmp = &_rmp;
  app_sapi_msg_t rmp_v2;
  clib_error_t *err;
  clib_socket_t *cs;
  int fds[32];
  u32 n_fds;

  /* A retry replaces every part of the old attachment before reconnecting. */
  if (wrk->observability_segment || wrk->observability_fd >= 0)
    if (vcl_sapi_detach (wrk))
      return -1;

  /*
   * Init client socket and send attach
   */
  if (vcl_api_connect_app_socket (wrk))
    return -1;

  cs = &wrk->app_api_sock;
  if (vcl_api_send_attach (cs))
    return -1;

  /*
   * Wait for attach reply
   */
  if (vcl_api_uses_app_socket_v2 ())
    {
      if (vcl_api_recv_v2_frame (cs, &rmp_v2, fds, ARRAY_LEN (fds), &n_fds) ||
	  rmp_v2.type != APP_SAPI_MSG_TYPE_ATTACH_V2_REPLY ||
	  rmp_v2.attach_v2_reply.abi != SESSION_OBSERVABILITY_ABI_VERSION ||
	  !session_observability_descriptor_is_valid (&rmp_v2.attach_v2_reply.descriptor) ||
	  n_fds != rmp_v2.attach_v2_reply.base.n_fds)
	{
	  vcl_api_close_fds (fds, ARRAY_LEN (fds));
	  vcl_api_close_app_socket (wrk);
	  return -1;
	}
      if (vcl_api_map_observability_attachment (rmp_v2.attach_v2_reply.base.fd_flags,
						&rmp_v2.attach_v2_reply.descriptor,
						rmp_v2.attach_v2_reply.association, fds, n_fds) ||
	  vcl_api_send_observability_attach_ack (cs))
	{
	  vcl_api_close_fds (fds, ARRAY_LEN (fds));
	  vcl_api_unmap_observability_attachment (wrk);
	  vcl_api_close_app_socket (wrk);
	  return -1;
	}
      if (vcl_api_attach_reply_handler (&rmp_v2.attach_v2_reply.base, fds))
	{
	  vcl_api_unmap_observability_attachment (wrk);
	  vcl_api_close_app_socket (wrk);
	  return -1;
	}
      return 0;
    }

  err = clib_socket_recvmsg (cs, rmp, sizeof (*rmp), fds, ARRAY_LEN (fds));
  if (err)
    {
      clib_error_report (err);
      return -1;
    }

  if (rmp->type != APP_SAPI_MSG_TYPE_ATTACH_REPLY)
    return -1;

  return vcl_api_attach_reply_handler (&rmp->attach_reply, fds);
}

static int
vcl_api_add_del_worker_reply_handler (app_sapi_worker_add_del_reply_msg_t *mp, int *fds)
{
  int n_fds = 0, i, rv;
  u64 segment_handle;
  vcl_worker_t *wrk;

  if (mp->retval)
    {
      VDBG (0, "add/del worker failed: %U", format_session_error, mp->retval);
      goto failed;
    }

  if (!mp->is_add)
    goto failed;

  wrk = vcl_worker_get_current ();
  wrk->api_client_handle = mp->api_client_handle;
  wrk->vpp_wrk_index = mp->wrk_index;
  wrk->ctrl_mq = vcm->ctrl_mq;

  segment_handle = mp->segment_handle;
  if (segment_handle == VCL_INVALID_SEGMENT_HANDLE)
    {
      clib_warning ("invalid segment handle");
      goto failed;
    }

  if (!mp->n_fds)
    goto failed;

  if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
    if (vcl_segment_attach (vcl_vpp_worker_segment_handle (wrk->wrk_index), "vpp-worker-seg",
			    SSVM_SEGMENT_MEMFD, fds[n_fds++]))
      goto failed;

  if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
    {
      u8 *segment_name = format (0, "memfd-%ld%c", segment_handle, 0);
      rv = vcl_segment_attach (segment_handle, (char *) segment_name, SSVM_SEGMENT_MEMFD,
			       fds[n_fds++]);
      vec_free (segment_name);
      if (rv != 0)
	goto failed;
    }

  if (mp->fd_flags & SESSION_FD_F_OBSERVABILITY_ATTACHMENT)
    n_fds++;

  vcl_segment_attach_mq (segment_handle, mp->app_event_queue_address, 0, &wrk->app_event_queue);

  if (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD)
    {
      svm_msg_q_set_eventfd (wrk->app_event_queue, fds[n_fds]);
      vcl_mq_epoll_add_evfd (wrk, wrk->app_event_queue);
      n_fds++;
    }

  VDBG (0, "worker %u vpp-worker %u added", wrk->wrk_index, wrk->vpp_wrk_index);

  return 0;

failed:
  for (i = clib_max (n_fds - 1, 0); i < mp->n_fds; i++)
    close (fds[i]);

  return -1;
}

int
vcl_sapi_app_worker_add (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  app_sapi_worker_add_del_msg_t *mp;
  app_sapi_legacy_msg_t _rmp, *rmp = &_rmp;
  app_sapi_legacy_msg_t msg = { 0 };
  app_sapi_msg_t msg_v2 = { 0 }, rmp_v2 = { 0 };
  int fds[SESSION_N_FD_TYPE];
  clib_error_t *err;
  clib_socket_t *cs;

  /* Connect to socket api */
  if (vcl_api_connect_app_socket (wrk))
    return -1;

  /*
   * Send add worker
   */
  cs = &wrk->app_api_sock;

  if (vcl_api_uses_app_socket_v2 ())
    {
      msg_v2.type = APP_SAPI_MSG_TYPE_ADD_DEL_WORKER_V2;
      msg_v2.worker_add_del_v2.abi = SESSION_OBSERVABILITY_ABI_VERSION;
      mp = &msg_v2.worker_add_del_v2.base;
    }
  else
    {
      msg.type = APP_SAPI_MSG_TYPE_ADD_DEL_WORKER;
      mp = &msg.worker_add_del;
    }
  mp->app_index = vcm->app_index;
  mp->is_add = 1;

  err = clib_socket_sendmsg (cs, vcl_api_uses_app_socket_v2 () ? (void *) &msg_v2 : (void *) &msg,
			     vcl_api_uses_app_socket_v2 () ? sizeof (msg_v2) : sizeof (msg), 0, 0);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }

  /*
   * Wait for reply and process it
   */
  if (vcl_api_uses_app_socket_v2 ())
    {
      u32 n_fds;

      if (vcl_api_recv_v2_frame (cs, &rmp_v2, fds, ARRAY_LEN (fds), &n_fds) ||
	  rmp_v2.type != APP_SAPI_MSG_TYPE_ADD_DEL_WORKER_V2_REPLY ||
	  rmp_v2.worker_add_del_v2_reply.abi != SESSION_OBSERVABILITY_ABI_VERSION ||
	  !session_observability_descriptor_is_valid (&rmp_v2.worker_add_del_v2_reply.descriptor) ||
	  n_fds != rmp_v2.worker_add_del_v2_reply.base.n_fds ||
	  vcl_api_map_observability_attachment (rmp_v2.worker_add_del_v2_reply.base.fd_flags,
						&rmp_v2.worker_add_del_v2_reply.descriptor,
						rmp_v2.worker_add_del_v2_reply.association, fds,
						n_fds) ||
	  vcl_api_send_observability_attach_ack (cs))
	{
	  vcl_api_close_fds (fds, ARRAY_LEN (fds));
	  vcl_api_unmap_observability_attachment (wrk);
	  clib_socket_close (cs);
	  return -1;
	}
      return vcl_api_add_del_worker_reply_handler (&rmp_v2.worker_add_del_v2_reply.base, fds);
    }

  err = clib_socket_recvmsg (cs, rmp, sizeof (*rmp), fds, ARRAY_LEN (fds));
  if (err)
    {
      clib_error_report (err);
      return -1;
    }

  if (rmp->type != APP_SAPI_MSG_TYPE_ADD_DEL_WORKER_REPLY)
    {
      clib_warning ("unexpected reply type %u", rmp->type);
      return -1;
    }

  return vcl_api_add_del_worker_reply_handler (&rmp->worker_add_del_reply, fds);
}

void
vcl_sapi_app_worker_del (vcl_worker_t *wrk)
{
  app_sapi_worker_add_del_msg_t *mp;
  app_sapi_legacy_msg_t msg = { 0 };
  clib_error_t *err;
  clib_socket_t *cs;

  cs = &wrk->app_api_sock;

  if (vcl_api_uses_app_socket_v2 ())
    {
      app_sapi_msg_t msg_v2 = { 0 };

      msg_v2.type = APP_SAPI_MSG_TYPE_ADD_DEL_WORKER_V2;
      msg_v2.worker_add_del_v2.abi = SESSION_OBSERVABILITY_ABI_VERSION;
      mp = &msg_v2.worker_add_del_v2.base;
      mp->app_index = vcm->app_index;
      mp->wrk_index = wrk->vpp_wrk_index;
      mp->is_add = 0;
      err = clib_socket_sendmsg (cs, &msg_v2, sizeof (msg_v2), 0, 0);
      if (err)
	clib_error_report (err);
      vcl_api_unmap_observability_attachment (wrk);
      clib_socket_close (cs);
      return;
    }

  msg.type = APP_SAPI_MSG_TYPE_ADD_DEL_WORKER;
  mp = &msg.worker_add_del;
  mp->app_index = vcm->app_index;
  mp->wrk_index = wrk->vpp_wrk_index;
  mp->is_add = 0;

  err = clib_socket_sendmsg (cs, &msg, sizeof (msg), 0, 0);
  if (err)
    clib_error_report (err);
  clib_socket_close (cs);
}

void
vcl_sapi_peer_dead (vcl_worker_t *wrk)
{
  if (!wrk)
    return;
  vcl_api_unmap_observability_attachment (wrk);
}

int
vcl_sapi_detach (vcl_worker_t *wrk)
{
  clib_socket_t *cs = &wrk->app_api_sock;
  int rv = 0;

  if (vcl_api_uses_app_socket_v2 () && wrk->observability_segment)
    {
      session_observability_descriptor_t descriptor = wrk->observability_descriptor;
      u32 association = wrk->observability_association;

      if (!vcl_api_send_observability_control (cs, APP_SAPI_MSG_TYPE_OBS_DETACH_V2, &descriptor,
					       association) &&
	  !vcl_api_ack_observability_done (cs, &descriptor, association))
	{
	  vcl_api_unmap_observability_attachment (wrk);
	}
      else
	{
	  /* A failed normal detach is peer-death cleanup, never a completed
	   * lifecycle.  Keep the mapping through DONE and the ACK above; only
	   * failure releases it without a VPP retirement acknowledgement. */
	  vcl_sapi_peer_dead (wrk);
	  rv = -1;
	}
    }
  clib_socket_close (cs);
  return rv;
}

int
vcl_sapi_recv_fds (vcl_worker_t *wrk, int *fds, int n_fds)
{
  app_sapi_legacy_msg_t _msg, *msg = &_msg;
  clib_socket_t *cs;
  clib_error_t *err;

  cs = &wrk->app_api_sock;

  err = clib_socket_recvmsg (cs, msg, sizeof (*msg), fds, n_fds);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }
  if (msg->type != APP_SAPI_MSG_TYPE_SEND_FDS)
    return -1;

  return 0;
}

int
vcl_sapi_add_cert_key_pair (vppcom_cert_key_pair_t *ckpair)
{
  u32 cert_len = ckpair->cert_len, key_len = ckpair->key_len, certkey_len;
  vcl_worker_t *wrk = vcl_worker_get_current ();
  app_sapi_legacy_msg_t _msg = { 0 }, *msg = &_msg;
  app_sapi_cert_key_add_del_msg_t *mp;
  app_sapi_legacy_msg_t _rmp, *rmp = &_rmp;
  clib_error_t *err;
  clib_socket_t *cs;
  u8 *certkey = 0;
  int rv = -1;

  msg->type = APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY;
  mp = &msg->cert_key_add_del;
  mp->context = wrk->wrk_index;
  mp->cert_len = cert_len;
  mp->certkey_len = cert_len + key_len;
  mp->is_add = 1;

  certkey_len = cert_len + key_len;
  vec_validate (certkey, certkey_len - 1);
  clib_memcpy_fast (certkey, ckpair->cert, cert_len);
  clib_memcpy_fast (certkey + cert_len, ckpair->key, key_len);

  cs = &wrk->app_api_sock;
  err = clib_socket_sendmsg (cs, msg, sizeof (*msg), 0, 0);
  if (err)
    {
      clib_error_report (err);
      goto done;
    }

  err = clib_socket_sendmsg (cs, certkey, certkey_len, 0, 0);
  if (err)
    {
      clib_error_report (err);
      goto done;
    }

  /*
   * Wait for reply and process it
   */
  err = clib_socket_recvmsg (cs, rmp, sizeof (*rmp), 0, 0);
  if (err)
    {
      clib_error_report (err);
      goto done;
    }

  if (rmp->type != APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY_REPLY)
    {
      clib_warning ("unexpected reply type %u", rmp->type);
      goto done;
    }

  if (!rmp->cert_key_add_del_reply.retval)
    rv = rmp->cert_key_add_del_reply.index;

done:

  return rv;
}

int
vcl_sapi_del_cert_key_pair (u32 ckpair_index)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  app_sapi_legacy_msg_t _msg = { 0 }, *msg = &_msg;
  app_sapi_cert_key_add_del_msg_t *mp;
  app_sapi_legacy_msg_t _rmp, *rmp = &_rmp;
  clib_error_t *err;
  clib_socket_t *cs;

  msg->type = APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY;
  mp = &msg->cert_key_add_del;
  mp->context = wrk->wrk_index;
  mp->index = ckpair_index;

  cs = &wrk->app_api_sock;
  err = clib_socket_sendmsg (cs, msg, sizeof (*msg), 0, 0);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }

  /*
   * Wait for reply and process it
   */
  err = clib_socket_recvmsg (cs, rmp, sizeof (*rmp), 0, 0);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }

  if (rmp->type != APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY_REPLY)
    {
      clib_warning ("unexpected reply type %u", rmp->type);
      return -1;
    }

  if (rmp->cert_key_add_del_reply.retval)
    return -1;

  return 0;
}
