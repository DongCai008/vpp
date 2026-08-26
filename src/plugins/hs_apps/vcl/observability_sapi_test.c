/* SPDX-License-Identifier: Apache-2.0 */
/*
 * End-to-end test client for the version-2 application socket attachment.
 *
 * This intentionally uses the production VPPCom attach and detach paths.  It
 * is run as a separate process so VPP can dispatch the registered socket read
 * callback while VCL synchronously waits for each protocol reply.
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <vcl/vcl_private.h>

static int
observability_sapi_connect (const char *path)
{
  struct sockaddr_un addr = { .sun_family = AF_UNIX };
  int fd;

  if (strlen (path) >= sizeof (addr.sun_path))
    return -1;
  fd = socket (AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd < 0)
    return -1;
  memcpy (addr.sun_path, path, strlen (path) + 1);
  if (connect (fd, (struct sockaddr *) &addr, sizeof (addr)))
    {
      close (fd);
      return -1;
    }
  return fd;
}

static int
observability_sapi_expect_close (int socket_fd)
{
  struct pollfd pfd = { .fd = socket_fd, .events = POLLIN };
  char byte;

  if (poll (&pfd, 1, 1000) != 1 || !(pfd.revents & (POLLIN | POLLERR | POLLHUP)))
    return -1;
  return recv (socket_fd, &byte, sizeof (byte), 0) == 0 ? 0 : -1;
}

static int
observability_sapi_send_rejected_frame (const char *path, const void *frame, size_t frame_bytes,
					int fd)
{
  struct iovec iov = { .iov_base = (void *) frame, .iov_len = frame_bytes };
  struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
  char control[CMSG_SPACE (sizeof (fd))] = { 0 };
  struct cmsghdr *cmsg;
  int socket_fd;
  int rv = -1;

  socket_fd = observability_sapi_connect (path);
  if (socket_fd < 0)
    return -1;
  if (fd >= 0)
    {
      msg.msg_control = control;
      msg.msg_controllen = sizeof (control);
      cmsg = CMSG_FIRSTHDR (&msg);
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      cmsg->cmsg_len = CMSG_LEN (sizeof (fd));
      memcpy (CMSG_DATA (cmsg), &fd, sizeof (fd));
    }
  if (sendmsg (socket_fd, &msg, 0) == (ssize_t) frame_bytes &&
      !observability_sapi_expect_close (socket_fd))
    rv = 0;
  close (socket_fd);
  return rv;
}

static int
observability_sapi_v2_endpoint_path (char *v2_path, size_t v2_path_size, const char *legacy_path)
{
  return snprintf (v2_path, v2_path_size, "%s.v2", legacy_path) >= (int) v2_path_size ? -1 : 0;
}

static int
observability_sapi_reject_v2_padded_legacy (const char *legacy_path)
{
  app_sapi_msg_t frame = { .type = APP_SAPI_MSG_TYPE_ATTACH };
  char v2_path[sizeof (((struct sockaddr_un *) 0)->sun_path)];

  if (observability_sapi_v2_endpoint_path (v2_path, sizeof (v2_path), legacy_path) ||
      observability_sapi_send_rejected_frame (v2_path, &frame, sizeof (frame), -1))
    return -1;
  printf ("V2_PADDED_LEGACY_REJECT_CLOSED\n");
  return 0;
}

static int
observability_sapi_reject_v2_invalid_abi (const char *legacy_path)
{
  app_sapi_msg_t frame = { .type = APP_SAPI_MSG_TYPE_ATTACH_V2 };
  char v2_path[sizeof (((struct sockaddr_un *) 0)->sun_path)];

  frame.attach_v2.abi = SESSION_OBSERVABILITY_ABI_VERSION + 1;
  if (observability_sapi_v2_endpoint_path (v2_path, sizeof (v2_path), legacy_path) ||
      observability_sapi_send_rejected_frame (v2_path, &frame, sizeof (frame), -1))
    return -1;
  printf ("V2_INVALID_ABI_REJECT_CLOSED\n");
  return 0;
}

static int
observability_sapi_reject_endpoints (const char *legacy_path)
{
  app_sapi_legacy_msg_t legacy = { .type = APP_SAPI_MSG_TYPE_ATTACH };
  app_sapi_msg_t v2 = { .type = APP_SAPI_MSG_TYPE_OBS_ATTACH_ACK_V2 };
  u8 oversized[sizeof (v2) + 1] = { 0 };
  char v2_path[sizeof (((struct sockaddr_un *) 0)->sun_path)];
  int devnull = -1;
  int rv = -1;

  if (observability_sapi_v2_endpoint_path (v2_path, sizeof (v2_path), legacy_path))
    return -1;
  memcpy (oversized, &v2, sizeof (v2));
  devnull = open ("/dev/null", O_RDONLY);
  if (devnull < 0 || observability_sapi_send_rejected_frame (legacy_path, &v2, sizeof (v2), -1) ||
      observability_sapi_send_rejected_frame (v2_path, &legacy, sizeof (legacy), -1) ||
      observability_sapi_send_rejected_frame (v2_path, oversized, sizeof (oversized), -1) ||
      observability_sapi_send_rejected_frame (v2_path, &v2, sizeof (v2), devnull) ||
      observability_sapi_reject_v2_padded_legacy (legacy_path) ||
      observability_sapi_reject_v2_invalid_abi (legacy_path))
    goto done;
  printf ("ENDPOINT_REJECTION_OK legacy-v2-truncation-fd\n");
  rv = 0;

done:
  if (devnull >= 0)
    close (devnull);
  return rv;
}

static void
observability_sapi_config_init (vppcom_cfg_t *cfg, const char *socket_path)
{
  *cfg = (vppcom_cfg_t){
    .heapsize = 256ULL << 20,
    .max_workers = 16,
    .segment_size = 256ULL << 20,
    .add_segment_size = 128ULL << 20,
    .preallocated_fifo_pairs = 8,
    .rx_fifo_size = 1 << 20,
    .tx_fifo_size = 1 << 20,
    .event_queue_size = 2048,
    .app_scope_local = 1,
    .app_scope_global = 1,
    .app_timeout = 10 * 60.0,
    .session_timeout = 10 * 60.0,
    .event_log_path = "/dev/shm",
    .vpp_app_socket_api_v2 = (char *) socket_path,
    .app_name = "observability_sapi_test",
  };
}

static int
observability_sapi_attached (vcl_worker_t *wrk)
{
  return wrk && wrk->observability_fd >= 0 && wrk->observability_segment &&
	 session_observability_descriptor_is_valid (&wrk->observability_descriptor) &&
	 clib_atomic_load_acq_n (&wrk->observability_segment->header.lifecycle) ==
	   SESSION_OBSERVABILITY_HEADER_MAP_VALID;
}

static int
observability_sapi_detached (vcl_worker_t *wrk)
{
  return wrk && wrk->observability_fd < 0 && !wrk->observability_segment &&
	 !wrk->observability_association;
}

static int
observability_sapi_lifecycle (const char *socket_path)
{
  vppcom_cfg_t cfg;
  vcl_worker_t *wrk;
  session_observability_descriptor_t first;

  observability_sapi_config_init (&cfg, socket_path);
  if (vppcom_app_create_with_config (&cfg))
    return -1;
  wrk = vcl_worker_get_current ();
  if (!observability_sapi_attached (wrk))
    return -1;
  first = wrk->observability_descriptor;
  printf ("ATTACH_OK association=%u identity=%llu\n", wrk->observability_association,
	  (unsigned long long) first.attachment_instance);

  /* The production path validates DONE while still mapped, ACKs it, and only
   * then unmaps.  A non-zero return is peer-death cleanup, not success. */
  if (vcl_sapi_detach (wrk))
    return -1;
  if (!observability_sapi_detached (wrk))
    return -1;
  printf ("DETACH_DONE_ACK_OK mapped-until-ack identity=%llu\n",
	  (unsigned long long) first.attachment_instance);

  if (vcl_sapi_attach ())
    return -1;
  wrk = vcl_worker_get_current ();
  if (!observability_sapi_attached (wrk) ||
      wrk->observability_descriptor.attachment_instance == first.attachment_instance)
    return -1;
  printf ("RECONNECT_OK identity=%llu\n",
	  (unsigned long long) wrk->observability_descriptor.attachment_instance);

  if (vcl_sapi_detach (wrk))
    return -1;
  if (!observability_sapi_detached (wrk))
    return -1;
  printf ("LIFECYCLE_OK retired\n");
  fflush (stdout);
  _exit (0);
}

static int
observability_sapi_reject_v2_recycled (const char *legacy_path)
{
  static const app_sapi_msg_type_e unsupported[] = {
    APP_SAPI_MSG_TYPE_ATTACH_V2_REPLY,	 APP_SAPI_MSG_TYPE_ADD_DEL_WORKER_V2_REPLY,
    APP_SAPI_MSG_TYPE_OBS_ATTACH_ACK_V2, APP_SAPI_MSG_TYPE_OBS_ATTACH_ACK_V2_REPLY,
    APP_SAPI_MSG_TYPE_OBS_DETACH_V2,	 APP_SAPI_MSG_TYPE_OBS_DETACH_V2_REPLY,
    APP_SAPI_MSG_TYPE_OBS_DONE_V2,	 APP_SAPI_MSG_TYPE_OBS_DONE_V2_REPLY,
    APP_SAPI_MSG_TYPE_OBS_REQUEST_V2,	 APP_SAPI_MSG_TYPE_OBS_REQUEST_V2_REPLY,
  };
  app_sapi_msg_t frame = { 0 };
  char v2_path[sizeof (((struct sockaddr_un *) 0)->sun_path)];
  uword i;
  u32 attempt;

  if (observability_sapi_v2_endpoint_path (v2_path, sizeof (v2_path), legacy_path) ||
      observability_sapi_reject_endpoints (legacy_path))
    return -1;

  for (attempt = 0; attempt < 2; attempt++)
    {
      frame.type = APP_SAPI_MSG_TYPE_ADD_DEL_WORKER_V2;
      frame.worker_add_del_v2.abi = SESSION_OBSERVABILITY_ABI_VERSION + 1;
      if (observability_sapi_send_rejected_frame (v2_path, &frame, sizeof (frame), -1))
	return -1;

      for (i = 0; i < ARRAY_LEN (unsupported); i++)
	{
	  clib_memset (&frame, 0, sizeof (frame));
	  frame.type = unsupported[i];
	  if (observability_sapi_send_rejected_frame (v2_path, &frame, sizeof (frame), -1))
	    return -1;
	}
    }

  printf ("V2_RECYCLED_REJECTION_OK invalid-worker-and-all-discriminators\n");
  fflush (stdout);
  return observability_sapi_lifecycle (v2_path);
}

static int
observability_sapi_app_destroy (const char *socket_path)
{
  vppcom_cfg_t cfg;
  vcl_worker_t *wrk;

  observability_sapi_config_init (&cfg, socket_path);
  if (vppcom_app_create_with_config (&cfg))
    return -1;
  wrk = vcl_worker_get_current ();
  if (!observability_sapi_attached (wrk))
    return -1;
  printf ("APP_DESTROY_READY identity=%llu\n",
	  (unsigned long long) wrk->observability_descriptor.attachment_instance);
  fflush (stdout);
  vppcom_app_destroy ();
  printf ("APP_DESTROY_RETURNED\n");
  return 0;
}

static int
observability_sapi_reject_identity (const char *socket_path)
{
  app_sapi_msg_t request = { .type = APP_SAPI_MSG_TYPE_OBS_ATTACH_ACK_V2 };
  app_sapi_msg_t response = { 0 };
  vppcom_cfg_t cfg;
  vcl_worker_t *wrk;

  observability_sapi_config_init (&cfg, socket_path);
  if (vppcom_app_create_with_config (&cfg))
    return -1;
  wrk = vcl_worker_get_current ();
  if (!observability_sapi_attached (wrk))
    return -1;
  request.observability_control_v2.association = wrk->observability_association;
  request.observability_control_v2.descriptor = wrk->observability_descriptor;
  request.observability_control_v2.descriptor.binding_nonce++;
  if (send (wrk->app_api_sock.fd, &request, sizeof (request), 0) != sizeof (request) ||
      recv (wrk->app_api_sock.fd, &response, sizeof (response), 0) != sizeof (response) ||
      response.type != APP_SAPI_MSG_TYPE_OBS_ATTACH_ACK_V2_REPLY ||
      !response.observability_control_v2_reply.retval)
    return -1;
  vcl_sapi_peer_dead (wrk);
  if (!observability_sapi_detached (wrk))
    return -1;
  printf ("IDENTITY_REJECTION_OK\n");
  fflush (stdout);
  _exit (0);
}

static int
observability_sapi_reject_request (const char *socket_path)
{
  app_sapi_msg_t request = { .type = APP_SAPI_MSG_TYPE_OBS_REQUEST_V2 };
  app_sapi_msg_t response = { 0 };
  vppcom_session_observability_reply_t reply;
  vppcom_cfg_t cfg;
  vcl_worker_t *wrk;
  int session_handle;

  observability_sapi_config_init (&cfg, socket_path);
  if (vppcom_app_create_with_config (&cfg))
    return -1;
  wrk = vcl_worker_get_current ();
  if (!observability_sapi_attached (wrk))
    return -1;
  request.observability_request_v2 = (app_sapi_observability_request_v2_msg_t){
    .request_id = 1,
    .sampling_point = 0,
    .abi = SESSION_OBSERVABILITY_ABI_VERSION,
  };
  if (send (wrk->app_api_sock.fd, &request, sizeof (request), 0) != sizeof (request) ||
      recv (wrk->app_api_sock.fd, &response, sizeof (response), 0) != sizeof (response) ||
      response.type != APP_SAPI_MSG_TYPE_OBS_REQUEST_V2_REPLY ||
      response.observability_request_v2_reply.request_id != 1 ||
      response.observability_request_v2_reply.status != 2 ||
      response.observability_request_v2_reply.detail !=
	SESSION_OBSERVABILITY_RESULT_DISPATCH_REJECTED)
    return -1;

  /* Exercise the public VCL call as a closed request/completion exchange.
   * The unconnected VCL session has no VPP handle, so the only acceptable
   * result is the server's typed SESSION_NOT_FOUND completion. */
  session_handle = vppcom_session_create (VPPCOM_PROTO_TCP, 0);
  if (session_handle == INVALID_SESSION_ID ||
      vppcom_session_observability_request (session_handle, 2, VPPCOM_OBSERVABILITY_POST_HANDSHAKE,
					    0, &reply) ||
      reply.request_id != 2 || reply.status != 2 ||
      reply.detail != SESSION_OBSERVABILITY_RESULT_SESSION_NOT_FOUND)
    return -1;
  if (vcl_sapi_detach (wrk))
    return -1;
  printf ("REQUEST_REJECTION_OK fixed-sapi-completion-public-vcl\n");
  fflush (stdout);
  _exit (0);
}

static int
observability_sapi_success (const char *socket_path)
{
  static const u8 expected_receipt[] = "p17b1o-owner-vft";
  u8 loopback[] = { 127, 0, 0, 1 };
  vppcom_session_observability_reply_t reply = { 0 };
  vppcom_endpt_t endpoint = {
    .is_ip4 = 1,
    .ip = loopback,
    .port = htons (40000 + getpid () % 10000),
  };
  struct pollfd pfd;
  vppcom_cfg_t cfg;
  vcl_worker_t *wrk = 0;
  pid_t server = -1;
  int child_status, client = INVALID_SESSION_ID;
  int ready[2] = { -1, -1 }, done[2] = { -1, -1 };
  int rv = 0, stage = 1, success = 0;
  char child_result = 1;

  if (pipe (ready) || pipe (done))
    goto fail;
  server = fork ();
  if (server < 0)
    goto fail;
  if (!server)
    {
      int listener = INVALID_SESSION_ID, accepted = INVALID_SESSION_ID;
      char result = 1;

      close (ready[0]);
      close (done[1]);
      observability_sapi_config_init (&cfg, socket_path);
      cfg.app_name = "observability_sapi_success_server";
      if (!vppcom_app_create_with_config (&cfg) &&
	  (listener = vppcom_session_create (VPPCOM_PROTO_TCP, 0)) != INVALID_SESSION_ID &&
	  !vppcom_session_bind (listener, &endpoint) && !vppcom_session_listen (listener, 1))
	result = 0;
      if (write (ready[1], &result, sizeof (result)) != sizeof (result) || result)
	_exit (1);
      accepted = vppcom_session_accept (listener, 0, 0);
      if (accepted == INVALID_SESSION_ID ||
	  read (done[0], &result, sizeof (result)) != sizeof (result) ||
	  vppcom_session_close (accepted) || vppcom_session_close (listener) ||
	  vcl_sapi_detach (vcl_worker_get_current ()))
	_exit (1);
      _exit (0);
    }

  close (ready[1]);
  ready[1] = -1;
  close (done[0]);
  done[0] = -1;
  if (read (ready[0], &child_result, sizeof (child_result)) != sizeof (child_result) ||
      child_result)
    goto fail;
  stage = 2;
  observability_sapi_config_init (&cfg, socket_path);
  cfg.app_name = "observability_sapi_success_client";
  if (vppcom_app_create_with_config (&cfg))
    goto fail;
  wrk = vcl_worker_get_current ();
  if (!observability_sapi_attached (wrk))
    goto fail;
  stage = 3;
  client = vppcom_session_create (VPPCOM_PROTO_TCP, 0);
  if (client == INVALID_SESSION_ID || (rv = vppcom_session_connect (client, &endpoint)))
    goto fail;
  stage = 4;
  rv = vppcom_session_observability_request (client, 0x50313742314f0001ULL,
					     VPPCOM_OBSERVABILITY_POST_HANDSHAKE, 0, &reply);
  if (rv || reply.request_id != 0x50313742314f0001ULL || reply.status != 1 ||
      reply.detail != SESSION_OBSERVABILITY_RESULT_OK || reply.reply_flags != 1 ||
      reply.receipt_length != sizeof (expected_receipt) - 1 ||
      memcmp (reply.receipt, expected_receipt, sizeof (expected_receipt) - 1))
    goto fail;

  /* The completed public operation consumed the sole socket completion. */
  stage = 5;
  pfd = (struct pollfd){ .fd = wrk->app_api_sock.fd, .events = POLLIN };
  if (poll (&pfd, 1, 0))
    goto fail;
  stage = 6;
  if (vppcom_session_close (client) || vcl_sapi_detach (wrk))
    goto fail;
  client = INVALID_SESSION_ID;
  wrk = 0;
  if (write (done[1], &success, sizeof (success)) != sizeof (success) ||
      waitpid (server, &child_status, 0) != server || !WIFEXITED (child_status) ||
      WEXITSTATUS (child_status))
    goto fail;
  server = -1;
  printf ("REQUEST_SUCCESS_OK public-vcl-owner-vft-single-receipt\n");
  fflush (stdout);
  _exit (0);

fail:
  if (client != INVALID_SESSION_ID)
    (void) vppcom_session_close (client);
  if (wrk && observability_sapi_attached (wrk))
    (void) vcl_sapi_detach (wrk);
  if (server > 0)
    {
      (void) kill (server, SIGTERM);
      (void) waitpid (server, 0, 0);
    }
  if (ready[0] >= 0)
    close (ready[0]);
  if (ready[1] >= 0)
    close (ready[1]);
  if (done[0] >= 0)
    close (done[0]);
  if (done[1] >= 0)
    close (done[1]);
  fprintf (stderr,
	   "success test failed at stage %d (rv %d, status %u, detail %u, flags %u, length %u)\n",
	   stage, rv, reply.status, reply.detail, reply.reply_flags, reply.receipt_length);
  return -1;
}

static int
observability_sapi_peer_death (const char *socket_path)
{
  vppcom_cfg_t cfg;
  vcl_worker_t *wrk;

  observability_sapi_config_init (&cfg, socket_path);
  if (vppcom_app_create_with_config (&cfg))
    return -1;
  wrk = vcl_worker_get_current ();
  if (!observability_sapi_attached (wrk))
    return -1;
  printf ("PEER_DEATH_READY identity=%llu\n",
	  (unsigned long long) wrk->observability_descriptor.attachment_instance);
  fflush (stdout);
  _exit (0);
}

int
main (int argc, char **argv)
{
  int rv;

  if (argc == 3 && !strcmp (argv[1], "--endpoint-reject"))
    return observability_sapi_reject_endpoints (argv[2]) ? 1 : 0;
  if (argc == 3 && !strcmp (argv[1], "--v2-padded-legacy-reject"))
    return observability_sapi_reject_v2_padded_legacy (argv[2]) ? 1 : 0;
  if (argc == 3 && !strcmp (argv[1], "--v2-invalid-abi-reject"))
    return observability_sapi_reject_v2_invalid_abi (argv[2]) ? 1 : 0;
  if (argc == 3 && !strcmp (argv[1], "--v2-recycled-reject"))
    return observability_sapi_reject_v2_recycled (argv[2]) ? 1 : 0;
  if (argc != 3)
    {
      fprintf (
	stderr,
	"usage: %s "
	"[--lifecycle|--app-destroy|--identity-reject|--request-reject|--success|--peer-death] "
	"<v2-socket>\n"
	"       %s [--endpoint-reject|--v2-padded-legacy-reject|--v2-invalid-abi-reject|"
	"--v2-recycled-reject] "
	"<legacy-socket>\n",
	argv[0], argv[0]);
      return 2;
    }
  if (!strcmp (argv[1], "--lifecycle"))
    rv = observability_sapi_lifecycle (argv[2]);
  else if (!strcmp (argv[1], "--app-destroy"))
    rv = observability_sapi_app_destroy (argv[2]);
  else if (!strcmp (argv[1], "--identity-reject"))
    rv = observability_sapi_reject_identity (argv[2]);
  else if (!strcmp (argv[1], "--request-reject"))
    rv = observability_sapi_reject_request (argv[2]);
  else if (!strcmp (argv[1], "--success"))
    rv = observability_sapi_success (argv[2]);
  else if (!strcmp (argv[1], "--peer-death"))
    rv = observability_sapi_peer_death (argv[2]);
  else
    rv = -1;
  return rv ? 1 : 0;
}
