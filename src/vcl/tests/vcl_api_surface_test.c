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

int
main (void)
{
  assert (clib_mem_init (0, 64ULL << 20));
  test_sendmsg_iov_flushes ();
  test_socket_error_reset ();
  test_socket_error_failed_connect ();
  test_postponed_reset_epoll_error ();
  return 0;
}
