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

int
main (void)
{
  test_sendmsg_iov_flushes ();
  test_socket_error_reset ();
  test_socket_error_failed_connect ();
  return 0;
}
