/* SPDX-License-Identifier: Apache-2.0 */

#include <assert.h>
#include <errno.h>

#include "../vcl_private.h"

extern int vls_sendmsg_iov_flags (int flags, int is_final_iov);

static int
ldp_sendmsg_flushes (int flags)
{
  return !(flags & MSG_MORE) || (flags & MSG_EOR);
}

static void
test_sendmsg_iov_flushes (void)
{
  int first, last;

  first = vls_sendmsg_iov_flags (0, 0);
  last = vls_sendmsg_iov_flags (0, 1);
  assert (first & MSG_MORE);
  assert (!(first & MSG_EOR));
  assert (!ldp_sendmsg_flushes (first));
  assert (ldp_sendmsg_flushes (last));

  first = vls_sendmsg_iov_flags (MSG_EOR, 0);
  last = vls_sendmsg_iov_flags (MSG_EOR, 1);
  assert (first & MSG_MORE);
  assert (!(first & MSG_EOR));
  assert (!ldp_sendmsg_flushes (first));
  assert (last & MSG_EOR);
  assert (ldp_sendmsg_flushes (last));

  first = vls_sendmsg_iov_flags (MSG_MORE, 0);
  last = vls_sendmsg_iov_flags (MSG_MORE, 1);
  assert (first & MSG_MORE);
  assert (!ldp_sendmsg_flushes (first));
  assert (last & MSG_MORE);
  assert (!ldp_sendmsg_flushes (last));
}

static void
test_socket_error_reset (void)
{
  vcl_session_t session = {
    .session_state = VCL_STATE_DISCONNECT,
    .socket_error = ECONNRESET,
  };

  assert (vcl_session_socket_error_take (&session) == ECONNRESET);
  assert (session.session_state == VCL_STATE_DISCONNECT);
  assert (vcl_session_socket_error_take (&session) == 0);
}

static void
test_socket_error_failed_connect (void)
{
  vcl_session_t session = {
    .session_state = VCL_STATE_DETACHED,
    .vpp_error = SESSION_E_REFUSED,
  };

  session.socket_error = vcl_session_socket_error_from_vpp_error (session.vpp_error);
  assert (vcl_session_socket_error_take (&session) == ECONNREFUSED);
  assert (session.session_state == VCL_STATE_DETACHED);
  assert (session.vpp_error == SESSION_E_REFUSED);
  assert (vcl_session_socket_error_take (&session) == 0);
}

static void
test_postponed_reset_epoll_error (void)
{
  struct epoll_event event = {
    .data.u64 = 0x12345678,
  };
  struct epoll_event result = {};
  vcl_worker_t *wrk;
  vcl_session_t *session;
  uint32_t buflen = sizeof (int);
  int error;
  int epoll_handle;
  int session_handle;

  memset (&_vppcom_main, 0, sizeof (_vppcom_main));
  vcm = &_vppcom_main;
  pool_get_zero (vcm->workers, wrk);
  wrk->wrk_index = 0;
  wrk->ep_lt_current = VCL_INVALID_SESSION_INDEX;
  vcl_set_worker_index (wrk->wrk_index);

  epoll_handle = vppcom_epoll_create ();
  session = vcl_session_alloc (wrk);
  session->session_state = VCL_STATE_DISCONNECT;
  session->vep.lt_next = VCL_INVALID_SESSION_INDEX;
  session_handle = vcl_session_handle (session);

  assert (vppcom_epoll_ctl (epoll_handle, EPOLL_CTL_ADD, session_handle, &event) == VPPCOM_OK);
  assert (vppcom_epoll_wait (epoll_handle, &result, 1, -2) == 1);
  assert ((result.events & (EPOLLERR | EPOLLHUP)) == (EPOLLERR | EPOLLHUP));
  assert (result.data.u64 == event.data.u64);

  assert (vppcom_session_attr (session_handle, VPPCOM_ATTR_GET_ERROR, &error, &buflen) ==
	  VPPCOM_OK);
  assert (error == ECONNRESET);
  buflen = sizeof (int);
  assert (vppcom_session_attr (session_handle, VPPCOM_ATTR_GET_ERROR, &error, &buflen) ==
	  VPPCOM_OK);
  assert (error == 0);
}

static void
test_enqueue_tcp_info_reply (svm_msg_q_t *mq, session_handle_t handle)
{
  svm_msg_q_msg_t msg;
  session_event_t *evt;
  session_transport_attr_reply_msg_t *reply;

  assert (svm_msg_q_lock_and_alloc_msg_w_ring (
	    mq, SESSION_MQ_CTRL_EVT_RING, SVM_Q_WAIT, &msg) == 0);
  evt = svm_msg_q_msg_data (mq, &msg);
  memset (evt, 0, sizeof (*evt));
  evt->event_type = SESSION_CTRL_EVT_TRANSPORT_ATTR_REPLY;
  reply = (session_transport_attr_reply_msg_t *) evt->data;
  reply->handle = handle;
  reply->retval = 0;
  reply->is_get = 1;
  reply->attr.type = TRANSPORT_ENDPT_ATTR_TCP_INFO;
  reply->attr.tcp_info.version = TRANSPORT_TCP_INFO_VERSION;
  reply->attr.tcp_info.length = sizeof (reply->attr.tcp_info);
  reply->attr.tcp_info.tcpi_state = 1;
  reply->attr.tcp_info.tcpi_ca_state = 3;
  reply->attr.tcp_info.tcpi_retransmits = 5;
  reply->attr.tcp_info.tcpi_backoff = 2;
  reply->attr.tcp_info.tcpi_rto = 200000;
  reply->attr.tcp_info.tcpi_snd_mss = 1200;
  reply->attr.tcp_info.tcpi_rcv_mss = 1180;
  reply->attr.tcp_info.tcpi_unacked = 4;
  reply->attr.tcp_info.tcpi_sacked = 1;
  reply->attr.tcp_info.tcpi_lost = 2;
  reply->attr.tcp_info.tcpi_retrans = 3;
  reply->attr.tcp_info.tcpi_rtt = 100000;
  reply->attr.tcp_info.tcpi_rttvar = 25000;
  reply->attr.tcp_info.tcpi_snd_ssthresh = 20;
  reply->attr.tcp_info.tcpi_snd_cwnd = 10;
  reply->attr.tcp_info.tcpi_reordering = 3;
  reply->attr.tcp_info.tcpi_total_retrans = 7;
  svm_msg_q_add_and_unlock (mq, &msg);
}

typedef struct test_control_queue_
{
  svm_msg_q_t mq;
  svm_msg_q_shared_t *shared;
} test_control_queue_t;

static test_control_queue_t *
test_alloc_control_queue (void)
{
  svm_msg_q_ring_cfg_t ring_cfgs[SESSION_MQ_N_RINGS] = {
    { 2, sizeof (session_event_t), 0 },
    { 2, 256, 0 },
  };
  svm_msg_q_cfg_t cfg = {
    .consumer_pid = 0,
    .q_nitems = 2,
    .n_rings = SESSION_MQ_N_RINGS,
    .ring_cfgs = ring_cfgs,
  };
  svm_msg_q_shared_t *shared;
  test_control_queue_t *queue;

  shared = svm_msg_q_alloc (&cfg);
  assert (shared);
  queue = clib_mem_alloc (sizeof (*queue));
  assert (queue);
  memset (queue, 0, sizeof (*queue));
  queue->shared = shared;
  svm_msg_q_attach (&queue->mq, shared);
  return queue;
}

static void
test_free_control_queue (test_control_queue_t *queue)
{
  svm_msg_q_cleanup (&queue->mq);
  clib_mem_free (queue->shared);
  clib_mem_free (queue);
}

static void
test_tcp_info_abi_and_control_path (void)
{
  vcl_worker_t *wrk;
  vcl_session_t *session;
  test_control_queue_t *app_event_queue_fixture;
  test_control_queue_t *vpp_event_queue_fixture;
  svm_msg_q_t *app_event_queue;
  svm_msg_q_t *vpp_event_queue;
  vppcom_tcp_info_t info = {};
  svm_msg_q_msg_t msg;
  uint32_t buflen;
  int session_handle;

  assert (sizeof (vppcom_tcp_info_t) == 60);
  assert (VPPCOM_TCP_INFO_VERSION == 1);

  wrk = vcl_worker_get_current ();
  app_event_queue_fixture = test_alloc_control_queue ();
  vpp_event_queue_fixture = test_alloc_control_queue ();
  app_event_queue = &app_event_queue_fixture->mq;
  vpp_event_queue = &vpp_event_queue_fixture->mq;
  wrk->app_event_queue = app_event_queue;
  session = vcl_session_alloc (wrk);
  session->session_type = VPPCOM_PROTO_TCP;
  session->session_state = VCL_STATE_READY;
  session->vpp_handle = 0x123400000001ULL;
  session->vpp_evt_q = vpp_event_queue;
  session_handle = vcl_session_handle (session);

  buflen = sizeof (info) - 1;
  assert (vppcom_session_attr (session_handle, VPPCOM_ATTR_GET_TCP_INFO,
				       &info, &buflen) == VPPCOM_EINVAL);

  test_enqueue_tcp_info_reply (app_event_queue, session->vpp_handle);
  buflen = sizeof (info);
  assert (vppcom_session_attr (session_handle, VPPCOM_ATTR_GET_TCP_INFO,
				       &info, &buflen) == VPPCOM_OK);
  assert (buflen == sizeof (info));
  assert (info.version == VPPCOM_TCP_INFO_VERSION);
  assert (info.length == sizeof (info));
  assert (info.tcpi_state == 1);
  assert (info.tcpi_ca_state == 3);
  assert (info.tcpi_retransmits == 5);
  assert (info.tcpi_backoff == 2);
  assert (info.tcpi_rto == 200000);
  assert (info.tcpi_snd_mss == 1200);
  assert (info.tcpi_rcv_mss == 1180);
  assert (info.tcpi_unacked == 4);
  assert (info.tcpi_sacked == 1);
  assert (info.tcpi_lost == 2);
  assert (info.tcpi_retrans == 3);
  assert (info.tcpi_rtt == 100000);
  assert (info.tcpi_rttvar == 25000);
  assert (info.tcpi_snd_ssthresh == 20);
  assert (info.tcpi_snd_cwnd == 10);
  assert (info.tcpi_reordering == 3);
  assert (info.tcpi_total_retrans == 7);

  assert (svm_msg_q_sub (vpp_event_queue, &msg, SVM_Q_NOWAIT, 0) == 0);
  svm_msg_q_free_msg (vpp_event_queue, &msg);

  session->session_type = VPPCOM_PROTO_UDP;
  buflen = sizeof (info);
  assert (vppcom_session_attr (session_handle, VPPCOM_ATTR_GET_TCP_INFO,
				       &info, &buflen) == VPPCOM_ENOPROTOOPT);
  session->session_type = VPPCOM_PROTO_TCP;

  buflen = sizeof (info);
  assert (vppcom_session_attr (
			vcl_session_handle_from_wrk_session_index (
			  (1 << 24) - 2, wrk->wrk_index),
			  VPPCOM_ATTR_GET_TCP_INFO, &info,
			  &buflen) == VPPCOM_EBADFD);

  session->vpp_evt_q = 0;
  vcl_session_free (wrk, session);
  wrk->app_event_queue = 0;
  test_free_control_queue (vpp_event_queue_fixture);
  test_free_control_queue (app_event_queue_fixture);
}

static void
test_tcp_info_never_connected (void)
{
  vcl_worker_t *wrk;
  vcl_session_t *session;
  vppcom_tcp_info_t info;
  uint32_t buflen;
  int session_handle;

  wrk = vcl_worker_get_current ();
  session = vcl_session_alloc (wrk);
  session->session_type = VPPCOM_PROTO_TCP;
  /* Deliberately leave session_state at its zero-initialized default
   * (VCL_STATE_CLOSED) and vpp_evt_q unset (NULL) -- this models a TCP
   * session that was created but never completed a handshake, so it has
   * no transport-level TCP_INFO to fetch. GET_TCP_INFO must still succeed
   * and report a meaningful tcpi_state (TCP_CLOSE) rather than an error or
   * an all-zero-but-ambiguous response. */
  assert (session->session_state == VCL_STATE_CLOSED);
  assert (session->vpp_evt_q == 0);
  session_handle = vcl_session_handle (session);

  memset (&info, 0xa5, sizeof (info));
  buflen = sizeof (info);
  assert (vppcom_session_attr (session_handle, VPPCOM_ATTR_GET_TCP_INFO,
				       &info, &buflen) == VPPCOM_OK);
  assert (buflen == sizeof (info));
  assert (info.version == VPPCOM_TCP_INFO_VERSION);
  assert (info.length == sizeof (info));
  assert (info.tcpi_state == 7); /* TCP_CLOSE */
  assert (info.tcpi_ca_state == 0);
  assert (info.tcpi_retransmits == 0);
  assert (info.tcpi_backoff == 0);
  assert (info.tcpi_rto == 0);
  assert (info.tcpi_snd_mss == 0);
  assert (info.tcpi_rcv_mss == 0);
  assert (info.tcpi_unacked == 0);
  assert (info.tcpi_sacked == 0);
  assert (info.tcpi_lost == 0);
  assert (info.tcpi_retrans == 0);
  assert (info.tcpi_rtt == 0);
  assert (info.tcpi_rttvar == 0);
  assert (info.tcpi_snd_ssthresh == 0);
  assert (info.tcpi_snd_cwnd == 0);
  assert (info.tcpi_reordering == 0);
  assert (info.tcpi_total_retrans == 0);

  vcl_session_free (wrk, session);
}

static void
test_tcp_info_disconnect_no_evt_q (void)
{
  vcl_worker_t *wrk;
  vcl_session_t *session;
  vppcom_tcp_info_t info;
  uint32_t buflen;
  int session_handle;

  /* Models a non-blocking connect that was RST'd before the CONNECTED
   * reply attached vpp_evt_q: session_state has already advanced to
   * VCL_STATE_DISCONNECT (so the RPC-eligibility gate on session_state
   * alone would be satisfied), but vpp_evt_q is still NULL, so
   * vcl_session_transport_attr() would short-circuit and return "success"
   * without touching its output. GET_TCP_INFO must not mistake that
   * untouched, request-seeded output for a real reply and must not
   * clobber tcpi_state with 0 -- it must keep the locally-computed
   * DISCONNECT -> TCP_CLOSING(11) state instead. */
  wrk = vcl_worker_get_current ();
  session = vcl_session_alloc (wrk);
  session->session_type = VPPCOM_PROTO_TCP;
  session->session_state = VCL_STATE_DISCONNECT;
  assert (session->vpp_evt_q == 0);
  session_handle = vcl_session_handle (session);

  memset (&info, 0xa5, sizeof (info));
  buflen = sizeof (info);
  assert (vppcom_session_attr (session_handle, VPPCOM_ATTR_GET_TCP_INFO,
				       &info, &buflen) == VPPCOM_OK);
  assert (buflen == sizeof (info));
  assert (info.version == VPPCOM_TCP_INFO_VERSION);
  assert (info.length == sizeof (info));
  assert (info.tcpi_state == 11); /* TCP_CLOSING, not the RPC's zero */
  assert (info.tcpi_ca_state == 0);
  assert (info.tcpi_retransmits == 0);
  assert (info.tcpi_backoff == 0);
  assert (info.tcpi_rto == 0);
  assert (info.tcpi_snd_mss == 0);
  assert (info.tcpi_rcv_mss == 0);
  assert (info.tcpi_unacked == 0);
  assert (info.tcpi_sacked == 0);
  assert (info.tcpi_lost == 0);
  assert (info.tcpi_retrans == 0);
  assert (info.tcpi_rtt == 0);
  assert (info.tcpi_rttvar == 0);
  assert (info.tcpi_snd_ssthresh == 0);
  assert (info.tcpi_snd_cwnd == 0);
  assert (info.tcpi_reordering == 0);
  assert (info.tcpi_total_retrans == 0);

  vcl_session_free (wrk, session);
}

int
main (void)
{
  assert (clib_mem_init (0, 64ULL << 20));
  test_sendmsg_iov_flushes ();
  test_socket_error_reset ();
  test_socket_error_failed_connect ();
  test_postponed_reset_epoll_error ();
  test_tcp_info_abi_and_control_path ();
  test_tcp_info_never_connected ();
  test_tcp_info_disconnect_no_evt_q ();
  return 0;
}
