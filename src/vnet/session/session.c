/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

/**
 * @file
 * @brief Session and session manager
 */

#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>
#include <vlib/stats/stats.h>
#include <vlib/dma/dma.h>
#include <vnet/session/session_rules_table.h>

session_main_t session_main;

static volatile u64 session_observability_next_token = 1;

static u64
session_observability_allocate_token (void)
{
  u64 current, next;

  do
    {
      current = clib_atomic_load_acq_n (&session_observability_next_token);
      if (current == 0 || current == ~0ULL)
	return 0;
      next = current + 1;
    }
  while (
    !clib_atomic_cmp_and_swap_acq_relax_n (&session_observability_next_token, &current, next, 0));

  return current;
}

typedef enum
{
  SESSION_EVT_RPC,
  SESSION_EVT_IO,
  SESSION_EVT_SESSION,
} session_evt_family_t;

static inline int
session_send_evt_to_thread (void *data, void *args, clib_thread_index_t thread_index,
			    session_evt_type_t evt_type, session_evt_family_t family)
{
  session_worker_t *wrk = session_main_get_worker (thread_index);
  session_event_t *evt;
  svm_msg_q_msg_t msg;
  svm_msg_q_t *mq;

  mq = wrk->vpp_event_queue;
  if (PREDICT_FALSE (svm_msg_q_lock (mq)))
    return -1;
  if (PREDICT_FALSE (svm_msg_q_or_ring_is_full (mq, SESSION_MQ_IO_EVT_RING)))
    {
      svm_msg_q_unlock (mq);
      return -2;
    }
  switch (family)
    {
    case SESSION_EVT_RPC:
      ASSERT (evt_type == SESSION_CTRL_EVT_RPC);
      msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
      evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
      evt->rpc_args.fp = data;
      evt->rpc_args.arg = args;
      break;
    case SESSION_EVT_IO:
      ASSERT (evt_type == SESSION_IO_EVT_RX || evt_type == SESSION_IO_EVT_TX ||
	      evt_type == SESSION_IO_EVT_TX_FLUSH || evt_type == SESSION_IO_EVT_BUILTIN_RX);
      msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
      evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
      evt->session_index = *(u32 *) data;
      break;
    case SESSION_EVT_SESSION:
      ASSERT (evt_type == SESSION_CTRL_EVT_CLOSE || evt_type == SESSION_CTRL_EVT_HALF_CLOSE ||
	      evt_type == SESSION_CTRL_EVT_RESET);
      msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
      evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
      evt->session_handle = session_handle ((session_t *) data);
      break;
    default:
      ASSERT (0);
      clib_warning ("evt unhandled!");
      svm_msg_q_unlock (mq);
      return -1;
    }
  evt->event_type = evt_type;

  svm_msg_q_add_and_unlock (mq, &msg);

  if (PREDICT_FALSE (wrk->state == SESSION_WRK_INTERRUPT))
    vlib_node_set_interrupt_pending (wrk->vm, session_queue_node.index);

  return 0;
}

/* Deprecated, use session_program_* functions */
int
session_send_io_evt_to_thread (svm_fifo_t *f, session_evt_type_t evt_type)
{
  return session_send_evt_to_thread (&f->vpp_session_index, 0, f->master_thread_index, evt_type,
				     SESSION_EVT_IO);
}

/* Deprecated, use session_program_* functions */
int
session_send_io_evt_to_thread_custom (void *data, clib_thread_index_t thread_index,
				      session_evt_type_t evt_type)
{
  return session_send_evt_to_thread (data, 0, thread_index, evt_type, SESSION_EVT_IO);
}

int
session_program_tx_io_evt (session_handle_tu_t sh, session_evt_type_t evt_type)
{
  return session_send_evt_to_thread ((void *) &sh.session_index, 0, (u32) sh.thread_index, evt_type,
				     SESSION_EVT_IO);
}

int
session_program_rx_io_evt (session_handle_tu_t sh)
{
  if (sh.thread_index == vlib_get_thread_index ())
    {
      session_t *s = session_get_from_handle (sh);
      if (PREDICT_FALSE (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING))
	return 0;
      return session_enqueue_notify (s);
    }
  else
    {
      return session_send_evt_to_thread ((void *) &sh.session_index, 0, (u32) sh.thread_index,
					 SESSION_IO_EVT_BUILTIN_RX, SESSION_EVT_IO);
    }
}

int
session_program_transport_io_evt (session_handle_tu_t sh, session_evt_type_t evt_type)
{
  return session_send_evt_to_thread ((void *) &sh.session_index, 0, (u32) sh.thread_index, evt_type,
				     SESSION_EVT_IO);
}

int
session_send_ctrl_evt_to_thread (session_t *s, session_evt_type_t evt_type)
{
  /* only events supported are disconnect, shutdown and reset */
  return session_send_evt_to_thread (s, 0, s->thread_index, evt_type, SESSION_EVT_SESSION);
}

int
session_send_rpc_evt_to_thread_force (clib_thread_index_t thread_index, void *fp, void *rpc_args)
{
  return session_send_evt_to_thread (fp, rpc_args, thread_index, SESSION_CTRL_EVT_RPC,
				     SESSION_EVT_RPC);
}

int
session_send_rpc_evt_to_thread (clib_thread_index_t thread_index, void *fp, void *rpc_args)
{
  if (thread_index != vlib_get_thread_index ())
    return session_send_rpc_evt_to_thread_force (thread_index, fp, rpc_args);
  else
    {
      void (*fnp) (void *) = fp;
      fnp (rpc_args);
      return 0;
    }
}

void
session_add_self_custom_tx_evt (transport_connection_t *tc, u8 has_prio)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);

  ASSERT (s->thread_index == vlib_get_thread_index ());
  ASSERT (s->session_state != SESSION_STATE_TRANSPORT_DELETED);

  if (!(s->flags & SESSION_F_CUSTOM_TX))
    {
      s->flags |= SESSION_F_CUSTOM_TX;
      if (svm_fifo_set_event (s->tx_fifo) || transport_connection_is_descheduled (tc))
	{
	  session_evt_elt_t *elt;
	  session_worker_t *wrk;

	  wrk = session_main_get_worker (tc->thread_index);
	  if (has_prio)
	    elt = session_evt_alloc_new (wrk);
	  else
	    elt = session_evt_alloc_old (wrk);
	  elt->evt.session_index = tc->s_index;
	  elt->evt.event_type = SESSION_IO_EVT_TX;
	  tc->flags &= ~TRANSPORT_CONNECTION_F_DESCHED;

	  if (PREDICT_FALSE (wrk->state == SESSION_WRK_INTERRUPT))
	    vlib_node_set_interrupt_pending (wrk->vm, session_queue_node.index);
	}
    }
}

void
sesssion_reschedule_tx (transport_connection_t *tc)
{
  session_worker_t *wrk = session_main_get_worker (tc->thread_index);
  session_evt_elt_t *elt;

  ASSERT (tc->thread_index == vlib_get_thread_index ());

  elt = session_evt_alloc_new (wrk);
  elt->evt.session_index = tc->s_index;
  elt->evt.event_type = SESSION_IO_EVT_TX;

  if (PREDICT_FALSE (wrk->state == SESSION_WRK_INTERRUPT))
    vlib_node_set_interrupt_pending (wrk->vm, session_queue_node.index);
}

static void
session_program_transport_ctrl_evt (session_t *s, session_evt_type_t evt)
{
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  session_evt_elt_t *elt;
  session_worker_t *wrk;

  /* If we are in the handler thread, or being called with the worker barrier
   * held, just append a new event to pending disconnects vector. */
  if (vlib_thread_is_main_w_barrier () || thread_index == s->thread_index)
    {
      wrk = session_main_get_worker (s->thread_index);
      elt = session_evt_alloc_ctrl (wrk);
      clib_memset (&elt->evt, 0, sizeof (session_event_t));
      elt->evt.session_handle = session_handle (s);
      elt->evt.event_type = evt;

      if (PREDICT_FALSE (wrk->state == SESSION_WRK_INTERRUPT))
	vlib_node_set_interrupt_pending (wrk->vm, session_queue_node.index);
    }
  else
    session_send_ctrl_evt_to_thread (s, evt);
}

session_t *
session_alloc (clib_thread_index_t thread_index)
{
  session_worker_t *wrk = &session_main.wrk[thread_index];
  session_t *s;

  pool_get_aligned_safe (wrk->sessions, s, CLIB_CACHE_LINE_BYTES);
  clib_memset (s, 0, sizeof (*s));
  s->session_index = s - wrk->sessions;
  s->thread_index = thread_index;
  s->al_index = APP_INVALID_INDEX;
  s->listener_handle = SESSION_INVALID_HANDLE;
  s->observability_association_token = session_observability_allocate_token ();
  s->observability_token_version = s->observability_association_token ? 1 : 0;

  return s;
}

void
session_free (session_t *s)
{
  session_worker_t *wrk = &session_main.wrk[s->thread_index];

  SESSION_EVT (SESSION_EVT_FREE, s);
  session_observability_fence_session (s, SESSION_OBSERVABILITY_RESULT_ASSOCIATION_TOKEN_STALE);
  if (CLIB_DEBUG)
    clib_memset (s, 0xFA, sizeof (*s));
  pool_put (wrk->sessions, s);
}

typedef struct
{
  session_handle_t session_handle;
  session_observability_owner_t *owner;
  session_observability_event_t event;
  session_observability_completion_fn_t completion;
  void *completion_context;
} session_observability_rpc_t;

typedef struct
{
  u64 opaque;
  volatile u32 references;
  session_observability_owner_t *owner;
  session_observability_directory_t *directory;
  session_observability_cell_t *cell;
  session_observability_sidecar_t *sidecar;
  session_observability_event_t event;
  session_observability_completion_fn_t completion;
  void *completion_context;
  session_observability_reply_t reply;
  u8 arm_pending;
  u8 pins_held;
  u8 completed;
  u8 registered;
  u8 retired;
} session_observability_terminal_t;

typedef struct
{
  session_observability_terminal_t *terminal;
  session_observability_owner_t *owner;
  session_observability_directory_t *directory;
  session_observability_cell_t *cell;
  session_observability_sidecar_t *sidecar;
  session_observability_completion_fn_t completion;
  void *completion_context;
  session_observability_reply_t reply;
  u8 release_pins;
  u8 drop_registry_ref;
} session_observability_terminal_action_t;

static session_observability_terminal_t **session_observability_terminals;
static clib_spinlock_t session_observability_terminals_lock;
static volatile u64 session_observability_terminal_next;

static session_observability_terminal_t *
session_observability_terminal_find (u64 opaque, uword *index)
{
  session_observability_terminal_t *terminal;
  uword i;

  vec_foreach_index (i, session_observability_terminals)
    {
      terminal = session_observability_terminals[i];
      if (terminal->opaque == opaque)
	{
	  if (index)
	    *index = i;
	  return terminal;
	}
    }
  return 0;
}

static session_observability_terminal_t *
session_observability_terminal_find_owner (session_observability_owner_t *owner, u64 request_id,
					   uword *index)
{
  session_observability_terminal_t *terminal;
  uword i;

  vec_foreach_index (i, session_observability_terminals)
    {
      terminal = session_observability_terminals[i];
      if (terminal->owner == owner && terminal->event.request_id == request_id)
	{
	  if (index)
	    *index = i;
	  return terminal;
	}
    }
  return 0;
}

static void
session_observability_terminal_get (session_observability_terminal_t *terminal)
{
  clib_atomic_fetch_add_rel (&terminal->references, 1);
}

static void
session_observability_terminal_put (session_observability_terminal_t *terminal)
{
  if (clib_atomic_fetch_sub_rel (&terminal->references, 1) == 1)
    clib_mem_free (terminal);
}

static u8
session_observability_terminal_remove (session_observability_terminal_t *terminal, uword index)
{
  if (!terminal->registered)
    return 0;
  vec_del1 (session_observability_terminals, index);
  terminal->registered = 0;
  return 1;
}

static void
session_observability_dispatch_complete (session_observability_rpc_t *rpc,
					 session_observability_cell_t *cell)
{
  session_observability_reply_t reply = {
    .request_id = rpc->event.request_id,
    .status = 2,
    .detail = SESSION_OBSERVABILITY_RESULT_QUEUE_BROKEN,
  };

  if (!rpc->completion)
    return;
  if (cell && clib_atomic_load_acq_n (&cell->cell_state) == SESSION_OBSERVABILITY_CELL_COMPLETED)
    {
      reply.request_id = cell->reply_request_id;
      reply.status = cell->reply_status;
      reply.detail = cell->reply_detail;
      reply.receipt_length = cell->receipt_length;
      reply.reply_flags = cell->reply_flags;
      clib_memcpy_fast (reply.receipt, cell->receipt, reply.receipt_length);
    }
  rpc->completion (rpc->completion_context, &reply);
}

static void
session_observability_release_ticket (session_observability_sidecar_t *sidecar)
{
  /* The consumer has released the ring element before a sidecar can be
   * published FREE.  A producer may only reuse an all-zero sidecar. */
  clib_memset (sidecar, 0, sizeof (*sidecar));
  clib_atomic_store_rel_n (&sidecar->ticket_state, SESSION_OBSERVABILITY_TICKET_FREE);
}

static void
session_observability_release_pins (session_observability_owner_t *owner,
				    session_observability_directory_t *directory,
				    session_observability_cell_t *cell,
				    session_observability_sidecar_t *sidecar)
{
  clib_atomic_fetch_sub_rel (&directory->admission_gate, 1);
  clib_atomic_fetch_sub_rel (&directory->admissions, 1);
  clib_atomic_fetch_sub_rel (&directory->reservations, 1);
  clib_atomic_fetch_sub_rel (&directory->references, 1);
  clib_atomic_fetch_sub_rel (&cell->references, 1);
  clib_atomic_fetch_sub_rel (&cell->cell_references, 1);
  clib_atomic_store_rel_n (&cell->admission_pin, 0);
  clib_atomic_store_rel_n (&cell->reservation_pin, 0);
  clib_atomic_fetch_sub_rel (&sidecar->references, 1);
  session_observability_release_ticket (sidecar);
  if (!clib_atomic_load_acq_n (&directory->references))
    {
      clib_memset (directory, 0, sizeof (*directory));
      clib_atomic_store_rel_n (&directory->lifecycle, SESSION_OBSERVABILITY_DIRECTORY_FREE);
    }
  session_observability_owner_release (owner);
}

static session_observability_reply_t
session_observability_terminal_result (session_observability_terminal_t *terminal,
				       session_observability_result_t result)
{
  return (session_observability_reply_t){
    .request_id = terminal->event.request_id,
    .status = result == SESSION_OBSERVABILITY_RESULT_OK ? 1 : 2,
    .detail = result,
  };
}

static void
session_observability_terminal_action_prepare (session_observability_terminal_t *terminal,
					       session_observability_terminal_action_t *action)
{
  if (terminal->arm_pending)
    return;
  action->reply = terminal->reply;
  if (terminal->pins_held)
    {
      action->owner = terminal->owner;
      action->directory = terminal->directory;
      action->cell = terminal->cell;
      action->sidecar = terminal->sidecar;
      action->release_pins = 1;
      terminal->pins_held = 0;
    }
  if (terminal->completion)
    {
      action->completion = terminal->completion;
      action->completion_context = terminal->completion_context;
      terminal->completion = 0;
      terminal->completion_context = 0;
    }
}

static void
session_observability_terminal_action_run (session_observability_terminal_action_t *action)
{
  if (action->release_pins)
    {
      session_observability_cell_complete_reply (action->cell, &action->reply);
      session_observability_release_pins (action->owner, action->directory, action->cell,
					  action->sidecar);
    }
  if (action->completion)
    action->completion (action->completion_context, &action->reply);
}

static int
session_observability_terminal_complete_locked (session_observability_terminal_t *terminal,
						const session_observability_reply_t *reply,
						session_observability_terminal_action_t *action)
{
  if (terminal->completed)
    return -1;
  terminal->reply = *reply;
  terminal->reply.request_id = terminal->event.request_id;
  terminal->completed = 1;
  session_observability_terminal_action_prepare (terminal, action);
  return 0;
}

static int
session_observability_terminal_result_locked (session_observability_terminal_t *terminal,
					      session_observability_result_t result,
					      session_observability_terminal_action_t *action)
{
  if (terminal->completed)
    return -1;
  terminal->reply = session_observability_terminal_result (terminal, result);
  terminal->completed = 1;
  session_observability_terminal_action_prepare (terminal, action);
  return 0;
}

int
session_observability_terminal_request_id_in_use (session_observability_owner_t *owner,
						  u64 request_id)
{
  int in_use;

  clib_spinlock_lock (&session_observability_terminals_lock);
  in_use = session_observability_terminal_find_owner (owner, request_id, 0) != 0;
  clib_spinlock_unlock (&session_observability_terminals_lock);
  return in_use;
}

int
session_observability_terminal_complete (const session_observability_terminal_sink_t *sink,
					 const session_observability_reply_t *reply)
{
  session_observability_terminal_t *terminal;
  session_observability_terminal_action_t action = { 0 };
  uword index;
  u8 drop_registry_ref = 0;

  if (!sink || !sink->opaque || !reply || reply->receipt_length > SESSION_OBSERVABILITY_RECEIPT_MAX)
    return -1;
  clib_spinlock_lock (&session_observability_terminals_lock);
  terminal = session_observability_terminal_find (sink->opaque, &index);
  if (!terminal)
    {
      clib_spinlock_unlock (&session_observability_terminals_lock);
      return -1;
    }
  session_observability_terminal_get (terminal);
  if (session_observability_terminal_complete_locked (terminal, reply, &action))
    {
      clib_spinlock_unlock (&session_observability_terminals_lock);
      session_observability_terminal_put (terminal);
      return -1;
    }
  if (action.completion)
    drop_registry_ref = session_observability_terminal_remove (terminal, index);
  clib_spinlock_unlock (&session_observability_terminals_lock);

  session_observability_terminal_action_run (&action);
  if (drop_registry_ref)
    session_observability_terminal_put (terminal);
  session_observability_terminal_put (terminal);
  return 0;
}

int
session_observability_terminal_await (session_observability_owner_t *owner, u64 request_id,
				      session_observability_completion_fn_t completion,
				      void *completion_context)
{
  session_observability_terminal_t *terminal;
  session_observability_terminal_action_t action = { 0 };
  uword i;
  u8 drop_registry_ref = 0;

  if (!owner || !request_id || !completion)
    return -1;
  clib_spinlock_lock (&session_observability_terminals_lock);
  vec_foreach_index (i, session_observability_terminals)
    {
      terminal = session_observability_terminals[i];
      if (terminal->owner != owner || terminal->event.request_id != request_id)
	continue;
      session_observability_terminal_get (terminal);
      if (terminal->completion)
	{
	  clib_spinlock_unlock (&session_observability_terminals_lock);
	  session_observability_terminal_put (terminal);
	  return -1;
	}
      if (!terminal->completed || terminal->arm_pending)
	{
	  terminal->completion = completion;
	  terminal->completion_context = completion_context;
	  clib_spinlock_unlock (&session_observability_terminals_lock);
	  session_observability_terminal_put (terminal);
	  return 0;
	}
      terminal->completion = completion;
      terminal->completion_context = completion_context;
      session_observability_terminal_action_prepare (terminal, &action);
      drop_registry_ref = session_observability_terminal_remove (terminal, i);
      clib_spinlock_unlock (&session_observability_terminals_lock);
      session_observability_terminal_action_run (&action);
      if (drop_registry_ref)
	session_observability_terminal_put (terminal);
      session_observability_terminal_put (terminal);
      return 0;
    }
  clib_spinlock_unlock (&session_observability_terminals_lock);
  return -1;
}

int
session_observability_terminal_cancel (session_observability_owner_t *owner, u64 request_id,
				       session_observability_result_t result)
{
  session_observability_terminal_t *terminal;
  session_observability_terminal_action_t action = { 0 };
  uword i;
  u8 drop_registry_ref = 0;

  if (!owner || !request_id)
    return -1;
  clib_spinlock_lock (&session_observability_terminals_lock);
  vec_foreach_index (i, session_observability_terminals)
    {
      terminal = session_observability_terminals[i];
      if (terminal->owner == owner && terminal->event.request_id == request_id)
	{
	  session_observability_terminal_get (terminal);
	  if (terminal->completed)
	    {
	      clib_spinlock_unlock (&session_observability_terminals_lock);
	      session_observability_terminal_put (terminal);
	      return 0;
	    }
	  session_observability_terminal_result_locked (terminal, result, &action);
	  if (action.completion)
	    drop_registry_ref = session_observability_terminal_remove (terminal, i);
	  clib_spinlock_unlock (&session_observability_terminals_lock);
	  session_observability_terminal_action_run (&action);
	  if (drop_registry_ref)
	    session_observability_terminal_put (terminal);
	  session_observability_terminal_put (terminal);
	  return 0;
	}
    }
  clib_spinlock_unlock (&session_observability_terminals_lock);
  return -1;
}

static void
session_observability_terminal_fence (session_observability_owner_t *owner, session_handle_t handle,
				      session_observability_result_t result)
{
  session_observability_terminal_action_t *actions = 0;
  session_observability_terminal_action_t action;
  session_observability_terminal_t *terminal;
  uword i;

  clib_spinlock_lock (&session_observability_terminals_lock);
  for (i = vec_len (session_observability_terminals); i > 0; i--)
    {
      terminal = session_observability_terminals[i - 1];
      if ((owner && terminal->owner != owner) ||
	  (handle != SESSION_INVALID_HANDLE && terminal->event.session_handle != handle))
	continue;
      /* A session fence cannot rewrite a receipt already frozen for the
       * original attachment.  Owner teardown has no surviving VCL await
       * endpoint, so it retires both pending and committed records. */
      if (!owner && terminal->completed)
	continue;
      session_observability_terminal_get (terminal);
      action = (session_observability_terminal_action_t){ .terminal = terminal };
      if (!terminal->completed)
	{
	  terminal->retired = 1;
	  session_observability_terminal_result_locked (terminal, result, &action);
	}
      if (owner)
	{
	  terminal->retired = 1;
	  terminal->arm_pending = 0;
	  session_observability_terminal_action_prepare (terminal, &action);
	  action.drop_registry_ref = session_observability_terminal_remove (terminal, i - 1);
	}
      else if (action.completion)
	action.drop_registry_ref = session_observability_terminal_remove (terminal, i - 1);
      vec_add1 (actions, action);
    }
  clib_spinlock_unlock (&session_observability_terminals_lock);
  vec_foreach_index (i, actions)
    {
      action = actions[i];
      session_observability_terminal_action_run (&action);
      if (action.drop_registry_ref)
	session_observability_terminal_put (action.terminal);
      session_observability_terminal_put (action.terminal);
    }
  vec_free (actions);
}

static int
session_observability_tuple_is_valid (const session_observability_directory_t *directory,
				      const session_observability_cell_t *cell,
				      const session_observability_sidecar_t *sidecar,
				      const session_observability_event_t *event)
{
  return clib_atomic_load_acq_n (&directory->lifecycle) == SESSION_OBSERVABILITY_DIRECTORY_LIVE &&
	 !(clib_atomic_load_acq_n (&directory->admission_gate) &
	   SESSION_OBSERVABILITY_ADMISSION_CLOSED) &&
	 directory->entry_nonce == event->directory_nonce &&
	 directory->association_token == event->association_token &&
	 directory->session_handle == event->session_handle &&
	 directory->attachment_instance == event->attachment_instance &&
	 directory->binding_generation == event->binding_generation &&
	 directory->owner_thread == event->owner_thread &&
	 directory->vcl_application_association == event->vcl_application_association &&
	 cell->allocation_nonce == event->allocation_nonce &&
	 cell->directory_nonce == event->directory_nonce &&
	 cell->attachment_instance == event->attachment_instance &&
	 cell->binding_generation == event->binding_generation &&
	 cell->association_token == event->association_token &&
	 cell->session_handle == event->session_handle &&
	 cell->owner_thread == event->owner_thread &&
	 cell->request_vcl_application_association == event->vcl_application_association &&
	 cell->ticket_sequence == event->ticket_sequence &&
	 sidecar->ticket_sequence == event->ticket_sequence &&
	 sidecar->attachment_slot == event->attachment_slot &&
	 sidecar->allocation_nonce == event->allocation_nonce &&
	 sidecar->directory_nonce == event->directory_nonce &&
	 sidecar->attachment_instance == event->attachment_instance &&
	 sidecar->binding_generation == event->binding_generation;
}

void
session_observability_owner_release (session_observability_owner_t *owner)
{
  u32 references;

  if (!owner)
    return;
  references = clib_atomic_fetch_sub_rel (&owner->references, 1);
  if (references == 2 && clib_atomic_load_acq_n (&owner->fenced) && owner->drained)
    owner->drained (owner);
  if (references == 1 && owner->release)
    owner->release (owner);
}

void
session_observability_fence_owner (session_observability_owner_t *owner,
				   session_observability_result_t result)
{
  session_observability_segment_t *segment;
  u32 i;

  if (!owner || !(segment = owner->segment))
    return;
  session_observability_terminal_fence (owner, SESSION_INVALID_HANDLE, result);
  clib_atomic_store_rel_n (&owner->fenced, 1);
  clib_atomic_store_rel_n (&segment->header.lifecycle, SESSION_OBSERVABILITY_HEADER_DETACHING);
  for (i = 0; i < SESSION_OBSERVABILITY_SLOT_COUNT; i++)
    {
      session_observability_directory_t *directory = &segment->directory[i];
      session_observability_cell_t *cell = &segment->cell[i];
      session_observability_sidecar_t *sidecar = &segment->sidecar[i];
      svm_msg_q_observability_ticket_t ticket = {
	.state = &sidecar->ticket_state,
	.cancellation = &cell->cancellation,
	.ring_index = &sidecar->ring_index,
	.ring_element_index = &sidecar->ring_element_index,
	.descriptor_element_index = &sidecar->descriptor_element_index,
      };
      u32 cell_state;

      clib_atomic_fetch_or (&directory->admission_gate, SESSION_OBSERVABILITY_ADMISSION_CLOSED);
      clib_atomic_store_rel_n (&directory->lifecycle, SESSION_OBSERVABILITY_DIRECTORY_FENCING);
      cell_state = clib_atomic_load_acq_n (&cell->cell_state);
      if (cell_state == SESSION_OBSERVABILITY_CELL_QUEUED ||
	  cell_state == SESSION_OBSERVABILITY_CELL_DRAINING)
	{
	  /* Queued tickets have one terminal owner: their consumer.  It will
	   * drain the FIFO element, publish completion and release every pin. */
	  (void) svm_msg_q_observability_cancel (&ticket);
	  continue;
	}
      if (cell_state != SESSION_OBSERVABILITY_CELL_FREE)
	{
	  (void) svm_msg_q_observability_cancel (&ticket);
	  session_observability_cell_complete (cell, result);
	}
    }
}

void
session_observability_fence_session (session_t *s, session_observability_result_t result)
{
  if (!s)
    return;
  session_observability_terminal_fence (0, session_handle (s), result);
  s->observability_token_version = 0;
  s->observability_association_token = 0;
}

static void
session_observability_dispatch_rpc (void *arg)
{
  session_observability_rpc_t *rpc = arg;
  session_handle_tu_t handle = { .handle = rpc->session_handle };
  session_observability_event_t queued_event;
  session_observability_cell_t *cell = 0;
  session_observability_directory_t *directory = 0;
  session_observability_sidecar_t *sidecar = 0;
  session_observability_request_t request;
  session_observability_reply_t reply = { 0 };
  svm_msg_q_observability_ticket_t ticket;
  svm_msg_q_msg_t msg;
  session_t *s;
  app_worker_t *app_wrk;
  transport_proto_vft_t *vft;
  session_observability_terminal_t *terminal = 0;
  session_observability_terminal_sink_t sink;
  session_observability_terminal_action_t terminal_action = { 0 };
  u32 expected;
  int rv = -1;
  u8 drop_registry_ref = 0;

  if (!rpc->owner || !rpc->owner->segment || !rpc->owner->queue ||
      rpc->event.attachment_slot >= SESSION_OBSERVABILITY_SLOT_COUNT)
    goto done;
  cell = &rpc->owner->segment->cell[rpc->event.attachment_slot];
  directory = &rpc->owner->segment->directory[rpc->event.attachment_slot];
  sidecar = &rpc->owner->segment->sidecar[rpc->event.attachment_slot];
  if (svm_msg_q_sub (rpc->owner->queue, &msg, SVM_Q_NOWAIT, 0) ||
      svm_msg_q_msg_data (rpc->owner->queue, &msg) == 0)
    goto stale;
  clib_memcpy_fast (&queued_event, svm_msg_q_msg_data (rpc->owner->queue, &msg),
		    sizeof (queued_event));
  if (msg.ring_index != sidecar->ring_index || msg.elt_index != sidecar->ring_element_index ||
      memcmp (&queued_event, &rpc->event, sizeof (queued_event)))
    {
      svm_msg_q_free_msg (rpc->owner->queue, &msg);
      goto stale;
    }
  ticket = (svm_msg_q_observability_ticket_t){
    .state = &sidecar->ticket_state,
    .cancellation = &cell->cancellation,
    .ring_index = &sidecar->ring_index,
    .ring_element_index = &sidecar->ring_element_index,
    .descriptor_element_index = &sidecar->descriptor_element_index,
  };
  expected = SESSION_OBSERVABILITY_CELL_QUEUED;
  if (!clib_atomic_cmp_and_swap_acq_relax_n (&cell->cell_state, &expected,
					     SESSION_OBSERVABILITY_CELL_DRAINING, 0))
    {
      svm_msg_q_free_msg (rpc->owner->queue, &msg);
      goto stale;
    }
  if (svm_msg_q_observability_consume (&ticket) != 1)
    {
      svm_msg_q_free_msg (rpc->owner->queue, &msg);
      goto stale;
    }
  /* The live/cancel decision is now final.  No transport callback can occur
   * until the ticket has been removed from the FIFO. */
  svm_msg_q_free_msg (rpc->owner->queue, &msg);
  if (!session_observability_tuple_is_valid (directory, cell, sidecar, &rpc->event))
    goto stale;
  if (sidecar->queue_identity != rpc->owner->segment->header.queue_identity ||
      sidecar->queue_generation != rpc->owner->segment->header.queue_generation)
    goto stale;
  s = session_get_from_handle_if_valid (handle);
  if (!s || s->thread_index != vlib_get_thread_index ())
    goto stale;
  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (!app_wrk || app_wrk->observability_association != rpc->event.vcl_application_association)
    goto mismatch;
  if (s->observability_token_version != 1 ||
      s->observability_association_token != rpc->event.association_token ||
      rpc->event.session_handle != rpc->session_handle ||
      rpc->event.owner_thread != s->thread_index ||
      rpc->event.vcl_application_association != app_wrk->observability_association)
    goto stale;

  vft = &tp_vfts[session_get_transport_proto (s)];
  request = (session_observability_request_t){
    .schema_version = SESSION_OBSERVABILITY_ABI_VERSION,
    .sampling_point = cell->sampling_point,
    .request_flags = cell->request_flags,
    .request_id = cell->request_id,
    .session_handle = rpc->event.session_handle,
    .association_token = rpc->event.association_token,
    .directory_nonce = rpc->event.directory_nonce,
    .binding_generation = rpc->event.binding_generation,
    .owner_thread = rpc->event.owner_thread,
    .application_association = rpc->event.vcl_application_association,
  };
  if (cell->sampling_point == SESSION_OBSERVABILITY_SAMPLING_TERMINAL &&
      vft->observability_terminal_arm)
    {
      terminal = clib_mem_alloc (sizeof (*terminal));
      if (!terminal)
	goto done;
      clib_memset (terminal, 0, sizeof (*terminal));
      terminal->opaque = clib_atomic_fetch_add_rel (&session_observability_terminal_next, 1) + 1;
      if (!terminal->opaque)
	{
	  clib_mem_free (terminal);
	  terminal = 0;
	  goto done;
	}
      terminal->owner = rpc->owner;
      terminal->directory = directory;
      terminal->cell = cell;
      terminal->sidecar = sidecar;
      terminal->event = rpc->event;
      terminal->arm_pending = 1;
      terminal->pins_held = 1;
      /* Registry membership and this owner-VFT invocation each retain one
       * object reference.  The transport receives an opaque value only. */
      terminal->references = 2;
      terminal->registered = 1;
      sink = (session_observability_terminal_sink_t){
	.opaque = terminal->opaque,
	.complete = session_observability_terminal_complete,
      };
      clib_spinlock_lock (&session_observability_terminals_lock);
      if (session_observability_terminal_find_owner (rpc->owner, request.request_id, 0))
	{
	  clib_spinlock_unlock (&session_observability_terminals_lock);
	  session_observability_terminal_put (terminal);
	  session_observability_terminal_put (terminal);
	  terminal = 0;
	  session_observability_cell_complete (cell,
					       SESSION_OBSERVABILITY_RESULT_DISPATCH_REJECTED);
	  goto done;
	}
      vec_add1 (session_observability_terminals, terminal);
      clib_spinlock_unlock (&session_observability_terminals_lock);
      rv = vft->observability_terminal_arm (s->connection_index, s->thread_index, &request, &sink);
      clib_spinlock_lock (&session_observability_terminals_lock);
      terminal->arm_pending = 0;
      if (rv || terminal->retired)
	{
	  /* A failed arm never transfers a sink to the caller.  A producer may
	   * already have frozen its one receipt before returning failure, but it
	   * remains private: retire it after releasing the original pins. */
	  terminal->retired = 1;
	  (void) session_observability_terminal_result_locked (
	    terminal, SESSION_OBSERVABILITY_RESULT_DISPATCH_REJECTED, &terminal_action);
	  session_observability_terminal_action_prepare (terminal, &terminal_action);
	  reply = session_observability_terminal_result (
	    terminal, SESSION_OBSERVABILITY_RESULT_DISPATCH_REJECTED);
	  if (terminal->registered)
	    {
	      uword terminal_index;

	      terminal_index = ~0;
	      if (session_observability_terminal_find (terminal->opaque, &terminal_index) ==
		  terminal)
		drop_registry_ref =
		  session_observability_terminal_remove (terminal, terminal_index);
	    }
	}
      else
	{
	  reply = (session_observability_reply_t){
	    .request_id = request.request_id,
	    .status = 1,
	    .detail = SESSION_OBSERVABILITY_RESULT_OK,
	  };
	  if (terminal->completed)
	    session_observability_terminal_action_prepare (terminal, &terminal_action);
	}
      if (terminal_action.completion && terminal->registered)
	{
	  uword terminal_index;

	  terminal_index = ~0;
	  if (session_observability_terminal_find (terminal->opaque, &terminal_index) == terminal)
	    drop_registry_ref = session_observability_terminal_remove (terminal, terminal_index);
	}
      clib_spinlock_unlock (&session_observability_terminals_lock);
      session_observability_terminal_action_run (&terminal_action);
      if (rpc->completion)
	rpc->completion (rpc->completion_context, &reply);
      if (drop_registry_ref)
	session_observability_terminal_put (terminal);
      session_observability_terminal_put (terminal);
      terminal = 0;
      goto terminal_done;
    }
  if (cell->sampling_point == SESSION_OBSERVABILITY_SAMPLING_TERMINAL)
    {
      session_observability_cell_complete (cell, SESSION_OBSERVABILITY_RESULT_DISPATCH_REJECTED);
      goto done;
    }
  if (vft->observability_request)
    rv = vft->observability_request (s->connection_index, s->thread_index, &request, &reply);
  if (!rv)
    session_observability_cell_complete_reply (cell, &reply);
  else
    session_observability_cell_complete (cell, SESSION_OBSERVABILITY_RESULT_DISPATCH_REJECTED);
  goto done;

mismatch:
  session_observability_cell_complete (cell, SESSION_OBSERVABILITY_RESULT_ASSOCIATION_MISMATCH);
  goto done;
stale:
  session_observability_cell_complete (cell, SESSION_OBSERVABILITY_RESULT_ASSOCIATION_TOKEN_STALE);
done:
  session_observability_dispatch_complete (rpc, cell);
  if (rpc->event.attachment_slot < SESSION_OBSERVABILITY_SLOT_COUNT)
    session_observability_release_pins (rpc->owner,
					&rpc->owner->segment->directory[rpc->event.attachment_slot],
					&rpc->owner->segment->cell[rpc->event.attachment_slot],
					&rpc->owner->segment->sidecar[rpc->event.attachment_slot]);
  clib_mem_free (rpc);
  return;

terminal_done:
  clib_mem_free (rpc);
}

int
session_observability_dispatch_prepare (session_observability_owner_t *owner,
					const session_observability_event_t *event,
					session_observability_dispatch_t *dispatch)
{
  session_observability_rpc_t *rpc;

  if (!owner || !owner->segment || !owner->queue || !dispatch ||
      clib_atomic_load_acq_n (&owner->fenced) || !event || !event->association_token ||
      !event->vcl_application_association ||
      event->attachment_slot >= SESSION_OBSERVABILITY_SLOT_COUNT ||
      event->owner_thread !=
	((session_handle_tu_t){ .handle = event->session_handle }).thread_index)
    return -1;

  rpc = clib_mem_alloc (sizeof (*rpc));
  if (!rpc)
    return -1;
  rpc->session_handle = event->session_handle;
  rpc->owner = owner;
  rpc->event = *event;
  rpc->completion = 0;
  rpc->completion_context = 0;
  dispatch->rpc = rpc;
  return 0;
}

int
session_observability_dispatch_prepare_with_completion (
  session_observability_owner_t *owner, const session_observability_event_t *event,
  session_observability_dispatch_t *dispatch, session_observability_completion_fn_t completion,
  void *completion_context)
{
  session_observability_rpc_t *rpc;

  if (session_observability_dispatch_prepare (owner, event, dispatch))
    return -1;
  rpc = dispatch->rpc;
  rpc->completion = completion;
  rpc->completion_context = completion_context;
  return 0;
}

int
session_observability_dispatch_commit (session_observability_dispatch_t *dispatch)
{
  session_observability_rpc_t *rpc;
  int rv;

  if (!dispatch || !(rpc = dispatch->rpc))
    return -1;
  rv = session_send_rpc_evt_to_thread (rpc->event.owner_thread, session_observability_dispatch_rpc,
				       rpc);
  if (!rv)
    dispatch->rpc = 0;
  return rv;
}

void
session_observability_dispatch_retry (session_observability_dispatch_t *dispatch)
{
  session_observability_rpc_t *rpc;
  session_worker_t *wrk;

  if (!dispatch || !(rpc = dispatch->rpc))
    return;
  dispatch->rpc = 0;
  wrk = session_main_get_worker (rpc->event.owner_thread);
  clib_spinlock_lock (&wrk->observability_retry_lock);
  vec_add1 (wrk->observability_retry_rpcs, rpc);
  clib_spinlock_unlock (&wrk->observability_retry_lock);
  vlib_node_set_interrupt_pending (wrk->vm, session_queue_node.index);
}

void
session_observability_dispatch_retry_pending (clib_thread_index_t thread_index)
{
  session_worker_t *wrk = session_main_get_worker (thread_index);
  session_observability_rpc_t **rpcs;
  uword i;

  clib_spinlock_lock (&wrk->observability_retry_lock);
  rpcs = (session_observability_rpc_t **) wrk->observability_retry_rpcs;
  wrk->observability_retry_rpcs = 0;
  clib_spinlock_unlock (&wrk->observability_retry_lock);
  for (i = 0; i < vec_len (rpcs); i++)
    session_observability_dispatch_rpc (rpcs[i]);
  vec_free (rpcs);
}

void
session_observability_dispatch_cancel (session_observability_dispatch_t *dispatch)
{
  if (!dispatch || !dispatch->rpc)
    return;
  clib_mem_free (dispatch->rpc);
  dispatch->rpc = 0;
}

u8
session_is_valid (u32 si, u8 thread_index)
{
  session_t *s;
  transport_connection_t *tc;

  s = pool_elt_at_index (session_main.wrk[thread_index].sessions, si);

  if (s->thread_index != thread_index || s->session_index != si)
    return 0;

  if (s->session_state == SESSION_STATE_TRANSPORT_DELETED ||
      s->session_state <= SESSION_STATE_LISTENING)
    return 1;

  if ((s->session_state == SESSION_STATE_CONNECTING ||
       s->session_state == SESSION_STATE_TRANSPORT_CLOSED) &&
      (s->flags & SESSION_F_HALF_OPEN))
    return 1;

  tc = session_get_transport (s);
  if (s->connection_index != tc->c_index || s->thread_index != tc->thread_index ||
      tc->s_index != si)
    return 0;

  return 1;
}

void
session_cleanup (session_t *s)
{
  segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
  session_free (s);
}

static void
session_cleanup_notify (session_t *s, session_cleanup_ntf_t ntf)
{
  app_worker_t *app_wrk;

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (PREDICT_FALSE (!app_wrk))
    {
      if (ntf == SESSION_CLEANUP_TRANSPORT)
	return;

      session_cleanup (s);
      return;
    }
  app_worker_cleanup_notify (app_wrk, s, ntf);
}

static void
session_cleanup_notify_custom (session_t *s, session_cleanup_ntf_t ntf,
			       transport_cleanup_cb_fn cb_fn)
{
  app_worker_t *app_wrk;

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (PREDICT_FALSE (!app_wrk))
    {
      if (ntf == SESSION_CLEANUP_TRANSPORT)
	{
	  transport_cleanup_cb (cb_fn, session_get_transport (s));
	  return;
	}

      session_cleanup (s);
      return;
    }
  app_worker_cleanup_notify_custom (app_wrk, s, ntf, cb_fn);
}

void
session_program_cleanup (session_t *s)
{
  ASSERT (s->session_state == SESSION_STATE_TRANSPORT_DELETED);
  session_cleanup_notify (s, SESSION_CLEANUP_SESSION);
}

void
session_cleanup_half_open (session_handle_t ho_handle)
{
  session_t *ho = session_get_from_handle (ho_handle);

  /* App transports can migrate their half-opens */
  if (ho->flags & SESSION_F_IS_MIGRATING)
    {
      /* Session still migrating, move to closed state to signal that the
       * session should be removed. */
      if (ho->connection_index == ~0)
	{
	  session_set_state (ho, SESSION_STATE_CLOSED);
	  return;
	}
      /* Migrated transports are no longer half-opens */
      transport_cleanup (session_get_transport_proto (ho), ho->connection_index,
			 ho->al_index /* overloaded */);
    }
  else if (ho->session_state != SESSION_STATE_TRANSPORT_DELETED)
    {
      /* Cleanup half-open session lookup table if need be */
      if (ho->session_state != SESSION_STATE_TRANSPORT_CLOSED)
	{
	  transport_connection_t *tc;
	  tc = transport_get_half_open (session_get_transport_proto (ho), ho->connection_index,
					ho->al_index);
	  if (tc && !(tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP))
	    session_lookup_del_half_open (tc);
	}
      transport_cleanup_half_open (session_get_transport_proto (ho), ho->connection_index,
				   ho->al_index);
    }
  session_free (ho);
}

static void
session_half_open_cleanup_notify_custom (session_t *ho, transport_cleanup_cb_fn cb_fn)
{
  app_worker_t *app_wrk;

  ASSERT (vlib_get_thread_index () <= transport_cl_thread ());
  app_wrk = app_worker_get_if_valid (ho->app_wrk_index);

  if (!app_wrk)
    {
      if (cb_fn)
	transport_cleanup_cb (cb_fn, session_get_transport (ho));
      session_free (ho);
      return;
    }

  app_worker_cleanup_ho_notify (app_wrk, ho, cb_fn);
}

static void
session_half_open_cleanup_notify_rpc (void *args)
{
  session_t *ho = ho_session_get (pointer_to_uword (args));
  transport_cleanup_cb_fn cb_fn = 0;
  transport_connection_t *tc;

  if (ho->flags & SESSION_F_TPT_INIT_CLOSE)
    {
      tc = transport_get_half_open (session_get_transport_proto (ho), ho->connection_index,
				    ho->al_index);
      cb_fn = transport_get_cleanup_cb_fn (tc);
    }
  session_half_open_cleanup_notify_custom (ho, cb_fn);
}

void
session_half_open_delete_request (transport_connection_t *tc, transport_cleanup_cb_fn cb_fn)
{
  session_t *ho = ho_session_get (tc->s_index);

  /* Cleanup half-open lookup table if need be */
  if (ho->session_state != SESSION_STATE_TRANSPORT_CLOSED)
    {
      if (!(tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP))
	session_lookup_del_half_open (tc);
    }
  session_set_state (ho, SESSION_STATE_TRANSPORT_DELETED);

  /* Notification from ctrl thread accepted without rpc */
  if (tc->thread_index == transport_cl_thread ())
    {
      session_half_open_cleanup_notify_custom (ho, cb_fn);
    }
  else
    {
      void *args = uword_to_pointer ((uword) tc->s_index, void *);
      if (cb_fn)
	{
	  transport_set_cleanup_cb_fn (tc, cb_fn);
	  ho->flags |= SESSION_F_TPT_INIT_CLOSE;
	}
      session_send_rpc_evt_to_thread_force (transport_cl_thread (),
					    session_half_open_cleanup_notify_rpc, args);
    }
}

void
session_half_open_delete_notify (transport_connection_t *tc)
{
  session_half_open_delete_request (tc, 0);
}

void
session_half_open_migrate_notify (transport_connection_t *tc)
{
  session_t *ho;

  /* Support half-open migrations only for transports with no lookup */
  ASSERT (tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP);

  ho = ho_session_get (tc->s_index);
  ho->flags |= SESSION_F_IS_MIGRATING;
  ho->connection_index = ~0;
}

int
session_half_open_migrated_notify (transport_connection_t *tc)
{
  session_t *ho;

  ho = ho_session_get (tc->s_index);

  /* App probably detached so the half-open must be cleaned up */
  if (ho->session_state == SESSION_STATE_CLOSED)
    {
      session_half_open_delete_notify (tc);
      return -1;
    }
  ho->connection_index = tc->c_index;
  /* Overload al_index for half-open with new thread */
  ho->al_index = tc->thread_index;
  return 0;
}

session_t *
session_alloc_for_connection (transport_connection_t *tc)
{
  session_t *s;
  clib_thread_index_t thread_index = tc->thread_index;

  ASSERT (thread_index == vlib_get_thread_index () || transport_protocol_is_cl (tc->proto));

  s = session_alloc (thread_index);
  s->session_type = session_type_from_proto_and_ip (tc->proto, tc->is_ip4);

  /* Attach transport to session and vice versa */
  s->connection_index = tc->c_index;
  tc->s_index = s->session_index;
  session_set_state (s, SESSION_STATE_CLOSED);
  return s;
}

static session_t *
session_alloc_for_stream (session_handle_t parent_handle)
{
  session_t *s, *ps;
  clib_thread_index_t thread_index = session_thread_from_handle (parent_handle);

  ASSERT (thread_index == vlib_get_thread_index ());

  s = session_alloc (thread_index);
  ps = session_get_from_handle_if_valid (parent_handle);
  if (!ps)
    {
      session_free (s);
      return 0;
    }
  s->session_type = ps->session_type;
  s->connection_index = SESSION_INVALID_INDEX;
  /* don't use session_set_state() here because connection index is not valid and elog might assert
   */
  s->session_state = SESSION_STATE_CLOSED;

  return s;
}

session_t *
session_alloc_for_half_open (transport_connection_t *tc)
{
  session_t *s;

  s = ho_session_alloc ();
  s->session_type = session_type_from_proto_and_ip (tc->proto, tc->is_ip4);
  s->connection_index = tc->c_index;
  s->al_index = tc->thread_index;
  tc->s_index = s->session_index;
  return s;
}

void
session_fifo_tuning (session_t *s, svm_fifo_t *f, session_ft_action_t act, u32 len)
{
  if (s->flags & SESSION_F_CUSTOM_FIFO_TUNING)
    {
      app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
      app_worker_session_fifo_tuning (app_wrk, s, f, act, len);
      if (CLIB_ASSERT_ENABLE)
	{
	  segment_manager_t *sm;
	  sm = segment_manager_get (f->segment_manager);
	  ASSERT (f->shr->size >= 4096);
	  ASSERT (f->shr->size <= sm->max_fifo_size);
	}
    }
}

void
session_wrk_program_app_wrk_evts (session_worker_t *wrk, u32 app_wrk_index)
{
  u8 need_interrupt;

  ASSERT ((wrk - session_main.wrk) == vlib_get_thread_index ());
  need_interrupt = clib_bitmap_is_zero (wrk->app_wrks_pending_ntf);
  wrk->app_wrks_pending_ntf = clib_bitmap_set (wrk->app_wrks_pending_ntf, app_wrk_index, 1);

  if (need_interrupt)
    vlib_node_set_interrupt_pending (wrk->vm, session_input_node.index);
}

always_inline void
session_program_io_event (app_worker_t *app_wrk, session_t *s, session_evt_type_t et, u8 is_cl)
{
  if (is_cl)
    {
      /* Special events for connectionless sessions */
      et += SESSION_IO_EVT_BUILTIN_RX - SESSION_IO_EVT_RX;

      ASSERT (s->thread_index == 0 || et == SESSION_IO_EVT_TX_MAIN);
      session_event_t evt = {
	.event_type = et,
	.session_handle = session_handle (s),
      };

      app_worker_add_event_custom (app_wrk, vlib_get_thread_index (), &evt);
    }
  else
    {
      app_worker_add_event (app_wrk, s, et);
    }
}

static inline int
session_notify_subscribers (u32 app_index, session_t *s, svm_fifo_t *f, session_evt_type_t evt_type)
{
  app_worker_t *app_wrk;
  application_t *app;
  u8 is_cl;
  int i;

  app = application_get (app_index);
  if (!app)
    return -1;

  is_cl = s->thread_index != vlib_get_thread_index ();
  for (i = 0; i < f->signals->n_subscribers; i++)
    {
      app_wrk = application_get_worker (app, f->signals->subscribers[i]);
      if (!app_wrk)
	continue;
      session_program_io_event (app_wrk, s, evt_type, is_cl ? 1 : 0);
    }

  return 0;
}

always_inline int
session_enqueue_notify_inline (session_t *s, u8 is_cl)
{
  app_worker_t *app_wrk;

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (PREDICT_FALSE (!app_wrk))
    return -1;

  session_program_io_event (app_wrk, s, SESSION_IO_EVT_RX, is_cl);

  if (PREDICT_FALSE (svm_fifo_n_subscribers (s->rx_fifo)))
    return session_notify_subscribers (app_wrk->app_index, s, s->rx_fifo, SESSION_IO_EVT_RX);

  return 0;
}

int
session_enqueue_notify (session_t *s)
{
  return session_enqueue_notify_inline (s, 0 /* is_cl */);
}

int
session_enqueue_notify_cl (session_t *s)
{
  return session_enqueue_notify_inline (s, 1 /* is_cl */);
}

int
session_dequeue_notify (session_t *s)
{
  app_worker_t *app_wrk;
  u8 is_cl;

  /* Unset as soon as event is requested */
  svm_fifo_clear_deq_ntf (s->tx_fifo);

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (PREDICT_FALSE (!app_wrk))
    return -1;

  is_cl = s->session_state == SESSION_STATE_LISTENING || s->session_state == SESSION_STATE_OPENED;
  session_program_io_event (app_wrk, s, SESSION_IO_EVT_TX, is_cl ? 1 : 0);

  if (PREDICT_FALSE (svm_fifo_n_subscribers (s->tx_fifo)))
    return session_notify_subscribers (app_wrk->app_index, s, s->tx_fifo, SESSION_IO_EVT_TX);

  return 0;
}

/**
 * Flushes queue of sessions that are to be notified of new data
 * enqueued events.
 *
 * @param transport_proto transport protocol for which queue to be flushed
 * @param thread_index Thread index for which the flush is to be performed.
 * @return 0 on success or a positive number indicating the number of
 *         failures due to API queue being full.
 */
void
session_main_flush_enqueue_events (transport_proto_t transport_proto,
				   clib_thread_index_t thread_index)
{
  session_worker_t *wrk = session_main_get_worker (thread_index);
  session_handle_t *handles;
  session_t *s;
  u32 i, is_cl;

  handles = wrk->session_to_enqueue[transport_proto];

  for (i = 0; i < vec_len (handles); i++)
    {
      s = session_get_from_handle (handles[i]);
      session_fifo_tuning (s, s->rx_fifo, SESSION_FT_ACTION_ENQUEUED, 0 /* TODO/not needed */);
      is_cl = s->thread_index != thread_index || (s->flags & SESSION_F_IS_CLESS);
      if (!is_cl)
	session_enqueue_notify_inline (s, 0);
      else
	session_enqueue_notify_inline (s, 1);
    }

  vec_reset_length (handles);
  wrk->session_to_enqueue[transport_proto] = handles;
}

int
session_enqueue_dgram_connection_cl (session_t *s, session_dgram_hdr_t *hdr, vlib_buffer_t *b,
				     u8 proto, u8 queue_event)
{
  session_t *awls;

  awls = app_listener_select_wrk_cl_session (s, hdr);
  return session_enqueue_dgram_connection_inline (awls, hdr, b, proto, queue_event, 1 /* is_cl */);
}

int
session_tx_fifo_peek_bytes (transport_connection_t *tc, u8 *buffer, u32 offset, u32 max_bytes)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_peek (s->tx_fifo, offset, max_bytes, buffer);
}

u32
session_tx_fifo_dequeue_drop (transport_connection_t *tc, u32 max_bytes)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  u32 rv;

  rv = svm_fifo_dequeue_drop (s->tx_fifo, max_bytes);
  session_fifo_tuning (s, s->tx_fifo, SESSION_FT_ACTION_DEQUEUED, rv);

  if (svm_fifo_needs_deq_ntf (s->tx_fifo, max_bytes))
    session_dequeue_notify (s);

  return rv;
}

int
session_stream_connect_notify (transport_connection_t *tc, session_error_t err)
{
  u32 opaque = 0, new_ti, new_si;
  app_worker_t *app_wrk;
  session_t *s = 0, *ho;

  /*
   * Cleanup half-open table
   */
  session_lookup_del_half_open (tc);

  ho = ho_session_get (tc->s_index);
  session_set_state (ho, SESSION_STATE_TRANSPORT_CLOSED);
  opaque = ho->opaque;
  app_wrk = app_worker_get_if_valid (ho->app_wrk_index);
  if (!app_wrk)
    return -1;

  if (err)
    {
      /* Use transport error as indication that connection failed */
      tc->flags |= TRANSPORT_CONNECTION_F_ERROR;
      return app_worker_connect_notify (app_wrk, s, err, opaque);
    }

  s = session_alloc_for_connection (tc);
  session_set_state (s, SESSION_STATE_CONNECTING);
  s->app_wrk_index = app_wrk->wrk_index;
  s->opaque = opaque;
  new_si = s->session_index;
  new_ti = s->thread_index;

  if ((err = app_worker_init_connected (app_wrk, s)))
    {
      session_free (s);
      app_worker_connect_notify (app_wrk, 0, err, opaque);
      return -1;
    }

  s = session_get (new_si, new_ti);
  session_set_state (s, SESSION_STATE_READY);
  session_lookup_add_connection (tc, session_handle (s));

  if (app_worker_connect_notify (app_wrk, s, SESSION_E_NONE, opaque))
    {
      session_lookup_del_connection (tc);
      /* Avoid notifying app about rejected session cleanup */
      s = session_get (new_si, new_ti);
      segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
      session_free (s);
      return -1;
    }

  return 0;
}

static void
session_switch_pool_closed_rpc (void *arg)
{
  session_handle_t sh;
  session_t *s;

  sh = pointer_to_uword (arg);
  s = session_get_from_handle_if_valid (sh);
  if (!s)
    return;

  transport_cleanup (session_get_transport_proto (s), s->connection_index, s->thread_index);
  session_cleanup (s);
}

/**
 * Notify old thread of the session pool switch
 */
static void
session_switch_pool (session_switch_pool_args_t *args)
{
  session_t *s = session_get_from_handle (args->old_sh);
  ASSERT (s->thread_index == vlib_get_thread_index ());

  /* The old handle may be recycled before the owner RPC runs.  Invalidate its
   * private association token before publishing the migration callback. */
  session_observability_fence_session (s, SESSION_OBSERVABILITY_RESULT_ASSOCIATION_MIGRATED);

  if (!(s->flags & SESSION_F_PROXY))
    {
      /* Cleanup fifo segment slice state for fifos */
      segment_manager_detach_fifo (&s->rx_fifo);
      segment_manager_detach_fifo (&s->tx_fifo);
    }

  /* Check if session closed during migration */
  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    goto app_closed;

  app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
  app_worker_migrate_notify (app_wrk, s, args->new_sh);

  return;

app_closed:
  /* Session closed during migration. Clean everything up */
  session_send_rpc_evt_to_thread (session_thread_from_handle (args->new_sh),
				  session_switch_pool_closed_rpc,
				  uword_to_pointer (args->new_sh, void *));
  transport_cleanup (session_get_transport_proto (s), s->connection_index, s->thread_index);
  session_cleanup (s);
}

static void
session_switch_pool_rpc (void *args)
{
  u32 thread_index = pointer_to_uword (args);
  session_worker_t *wrk;
  session_switch_pool_args_t *swpa;

  wrk = session_main_get_worker (thread_index);

  clib_spinlock_lock (&wrk->session_migrate_lock);
  swpa = wrk->session_migrate_requests;
  wrk->session_migrate_requests = wrk->session_migrate_requests_handling;
  wrk->session_migrate_requests_handling = swpa;
  clib_spinlock_unlock (&wrk->session_migrate_lock);

  vec_foreach (swpa, wrk->session_migrate_requests_handling)
    session_switch_pool (swpa);

  vec_reset_length (wrk->session_migrate_requests_handling);
}

static inline void
session_program_thread_migration (session_switch_pool_args_t *args)
{
  session_worker_t *wrk;
  u8 rpc_needed = 0;

  wrk = session_main_get_worker (args->old_sh.thread_index);

  clib_spinlock_lock (&wrk->session_migrate_lock);
  vec_add1 (wrk->session_migrate_requests, *args);
  if (vec_len (wrk->session_migrate_requests) == 1)
    rpc_needed = 1;
  clib_spinlock_unlock (&wrk->session_migrate_lock);

  if (rpc_needed)
    {
      void *rpc_args = uword_to_pointer ((uword) args->old_sh.thread_index, void *);
      session_send_rpc_evt_to_thread (args->old_sh.thread_index, session_switch_pool_rpc, rpc_args);
    }
}

void
session_migrate_accept (session_t *s)
{
  s->flags &= ~SESSION_F_IS_MIGRATING;
  s->flags |= SESSION_F_RX_READY;

  if (s->tx_fifo && svm_fifo_max_dequeue (s->tx_fifo))
    session_program_tx_io_evt (session_handle (s), SESSION_IO_EVT_TX);

  if (s->flags & SESSION_F_RX_EVT)
    session_program_rx_io_evt (session_handle (s));
}

/**
 * Move dgram session to the right thread
 */
int
session_dgram_connect_notify (transport_connection_t *tc, session_handle_tu_t osh,
			      session_t **new_session)
{
  session_t *new_s;

  /*
   * Clone half-open session to the right thread.
   */
  new_s = session_clone_safe (tc->s_index, osh.thread_index);
  new_s->observability_association_token = session_observability_allocate_token ();
  new_s->observability_token_version = new_s->observability_association_token ? 1 : 0;
  new_s->connection_index = tc->c_index;
  session_set_state (new_s, SESSION_STATE_READY);
  new_s->flags |= SESSION_F_IS_MIGRATING;
  new_s->flags &= ~SESSION_F_RX_READY;

  if (!(tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP))
    session_lookup_add_connection (tc, session_handle (new_s));

  if (!(new_s->flags & SESSION_F_PROXY))
    {
      /* New set of fifos attached to the same shared memory */
      segment_manager_attach_fifo (&new_s->rx_fifo, new_s);
      segment_manager_attach_fifo (&new_s->tx_fifo, new_s);
    }

  /*
   * Ask thread owning the old session to clean it up and make us the tx
   * fifo owner
   */
  session_switch_pool_args_t rpc_args = { .new_sh = session_handle (new_s), .old_sh = osh };
  session_program_thread_migration (&rpc_args);

  tc->s_index = new_s->session_index;
  new_s->connection_index = tc->c_index;
  *new_session = new_s;
  return 0;
}

/**
 * Notification from transport that connection is being closed.
 *
 * A disconnect is sent to application but state is not removed. Once
 * disconnect is acknowledged by application, session disconnect is called.
 * Ultimately this leads to close being called on transport (passive close).
 */
void
session_transport_closing_notify (transport_connection_t *tc)
{
  app_worker_t *app_wrk;
  session_t *s;

  s = session_get (tc->s_index, tc->thread_index);
  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    return;

  /* Wait for reply from app before sending notification as the
   * accept might be rejected */
  if (s->session_state == SESSION_STATE_ACCEPTING)
    {
      session_set_state (s, SESSION_STATE_TRANSPORT_CLOSING);
      return;
    }

  session_set_state (s, SESSION_STATE_TRANSPORT_CLOSING);
  app_wrk = app_worker_get (s->app_wrk_index);
  app_worker_close_notify (app_wrk, s);
}

/**
 * Notification from transport that connection is being deleted
 *
 * This removes the session if it is still valid. It should be called only on
 * previously fully established sessions. For instance failed connects should
 * call stream_session_connect_notify and indicate that the connect has
 * failed.
 */
void
session_transport_delete_notify (transport_connection_t *tc)
{
  session_t *s;

  s = session_get (tc->s_index, tc->thread_index);

  switch (s->session_state)
    {
    case SESSION_STATE_CREATED:
      /* Session was created but accept notification was not yet sent to the
       * app. Cleanup everything. */
      session_lookup_del_session (s);
      segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
      session_free (s);
      break;
    case SESSION_STATE_ACCEPTING:
    case SESSION_STATE_TRANSPORT_CLOSING:
    case SESSION_STATE_CLOSING:
    case SESSION_STATE_TRANSPORT_CLOSED:
      /* If transport finishes or times out before we get a reply
       * from the app, mark transport as closed and wait for reply
       * before removing the session. Cleanup session table in advance
       * because transport will soon be closed and closed sessions
       * are assumed to have been removed from the lookup table */
      session_lookup_del_session (s);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify (s, SESSION_CLEANUP_TRANSPORT);
      break;
    case SESSION_STATE_APP_CLOSED:
      /* Cleanup lookup table as transport needs to still be valid.
       * Program transport close to ensure that all session events
       * have been cleaned up. Once transport close is called, the
       * session is just removed because both transport and app have
       * confirmed the close*/
      session_lookup_del_session (s);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify (s, SESSION_CLEANUP_TRANSPORT);
      session_program_transport_ctrl_evt (s, SESSION_CTRL_EVT_CLOSE);
      break;
    case SESSION_STATE_TRANSPORT_DELETED:
      break;
    case SESSION_STATE_CLOSED:
      session_lookup_del_session (s);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify (s, SESSION_CLEANUP_TRANSPORT);
      session_program_cleanup (s);
      break;
    default:
      clib_warning ("session %u state %u", s->session_index, s->session_state);
      session_lookup_del_session (s);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify (s, SESSION_CLEANUP_TRANSPORT);
      session_program_cleanup (s);
      break;
    }
}

/**
 * Request from transport to program connection deletion
 *
 * Similar to session_transport_delete_notify just that transport
 * is asking session layer to delete the transport connection after
 * it delievers notifications to app. Must be used if transport
 * stats are to be collected.
 */
void
session_transport_delete_request (transport_connection_t *tc, transport_cleanup_cb_fn cb_fn)
{
  session_t *s;

  s = session_get (tc->s_index, tc->thread_index);

  switch (s->session_state)
    {
    case SESSION_STATE_CREATED:
      /* Session was created but accept notification was not yet sent to the
       * app. Cleanup everything. */
      session_lookup_del_session (s);
      segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
      transport_cleanup_cb (cb_fn, tc);
      session_free (s);
      break;
    case SESSION_STATE_ACCEPTING:
    case SESSION_STATE_TRANSPORT_CLOSING:
    case SESSION_STATE_CLOSING:
    case SESSION_STATE_TRANSPORT_CLOSED:
      /* If transport finishes or times out before we get a reply
       * from the app, mark transport as closed and wait for reply
       * before removing the session. Cleanup session table in advance
       * because transport will soon be closed and closed sessions
       * are assumed to have been removed from the lookup table */
      session_lookup_del_session (s);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify_custom (s, SESSION_CLEANUP_TRANSPORT, cb_fn);
      break;
    case SESSION_STATE_APP_CLOSED:
      /* Cleanup lookup table as transport needs to still be valid.
       * Program transport close to ensure that all session events
       * have been cleaned up. Once transport close is called, the
       * session is just removed because both transport and app have
       * confirmed the close*/
      session_lookup_del_session (s);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify_custom (s, SESSION_CLEANUP_TRANSPORT, cb_fn);
      session_program_transport_ctrl_evt (s, SESSION_CTRL_EVT_CLOSE);
      break;
    case SESSION_STATE_TRANSPORT_DELETED:
      transport_cleanup_cb (cb_fn, tc);
      break;
    case SESSION_STATE_CLOSED:
      session_lookup_del_session (s);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify_custom (s, SESSION_CLEANUP_TRANSPORT, cb_fn);
      session_program_cleanup (s);
      break;
    default:
      clib_warning ("session %u state %u", s->session_index, s->session_state);
      session_lookup_del_session (s);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify_custom (s, SESSION_CLEANUP_TRANSPORT, cb_fn);
      session_program_cleanup (s);
      break;
    }
}

/**
 * Notification from transport that it is closed
 *
 * Should be called by transport, prior to calling delete notify, once it
 * knows that no more data will be exchanged. This could serve as an
 * early acknowledgment of an active close especially if transport delete
 * can be delayed a long time, e.g., tcp time-wait.
 */
void
session_transport_closed_notify (transport_connection_t *tc)
{
  app_worker_t *app_wrk;
  session_t *s;

  if (!(s = session_get_if_valid (tc->s_index, tc->thread_index)))
    return;

  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSED)
    return;

  /* Transport thinks that app requested close but it actually didn't.
   * Can happen for tcp:
   * 1)if fin and rst are received in close succession.
   * 2)if app shutdown the connection.  */
  if (s->session_state == SESSION_STATE_READY)
    {
      session_transport_closing_notify (tc);
      session_set_state (s, SESSION_STATE_TRANSPORT_CLOSED);
    }
  /* If app close has not been received or has not yet resulted in
   * a transport close, only mark the session transport as closed */
  else if (s->session_state <= SESSION_STATE_CLOSING)
    session_set_state (s, SESSION_STATE_TRANSPORT_CLOSED);
  /* If app also closed, switch to closed */
  else if (s->session_state == SESSION_STATE_APP_CLOSED)
    session_set_state (s, SESSION_STATE_CLOSED);

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (app_wrk)
    app_worker_transport_closed_notify (app_wrk, s);
}

/**
 * Notify application that connection has been reset.
 */
void
session_transport_reset_notify (transport_connection_t *tc)
{
  app_worker_t *app_wrk;
  session_t *s;

  s = session_get (tc->s_index, tc->thread_index);
  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    return;
  if (s->session_state == SESSION_STATE_ACCEPTING)
    {
      session_set_state (s, SESSION_STATE_TRANSPORT_CLOSING);
      return;
    }
  session_set_state (s, SESSION_STATE_TRANSPORT_CLOSING);
  app_wrk = app_worker_get (s->app_wrk_index);
  app_worker_reset_notify (app_wrk, s);
}

int
session_stream_accept_notify (transport_connection_t *tc)
{
  app_worker_t *app_wrk;
  session_t *s;

  s = session_get (tc->s_index, tc->thread_index);
  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (!app_wrk)
    return -1;
  if (s->session_state != SESSION_STATE_CREATED)
    return 0;
  session_set_state (s, SESSION_STATE_ACCEPTING);
  if (app_worker_accept_notify (app_wrk, s))
    {
      /* On transport delete, no notifications should be sent. Unless, the
       * accept is retried and successful. */
      session_set_state (s, SESSION_STATE_CREATED);
      return -1;
    }
  return 0;
}

/**
 * Accept a stream session. Optionally ping the server by callback.
 */
int
session_stream_accept (transport_connection_t *tc, u32 listener_index,
		       clib_thread_index_t thread_index, u8 notify)
{
  session_t *s;
  int rv;

  s = session_alloc_for_connection (tc);
  s->listener_handle = ((u64) thread_index << 32) | (u64) listener_index;
  session_set_state (s, SESSION_STATE_CREATED);

  if ((rv = app_worker_init_accepted (s)))
    {
      session_free (s);
      return rv;
    }

  session_lookup_add_connection (tc, session_handle (s));

  /* Shoulder-tap the server */
  if (notify)
    {
      app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
      if ((rv = app_worker_accept_notify (app_wrk, s)))
	{
	  session_lookup_del_session (s);
	  segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
	  session_free (s);
	  return rv;
	}
    }

  return 0;
}

int
session_dgram_accept (transport_connection_t *tc, u32 listener_index,
		      clib_thread_index_t thread_index)
{
  app_worker_t *app_wrk;
  session_t *s;
  int rv;

  s = session_alloc_for_connection (tc);
  s->listener_handle = ((u64) thread_index << 32) | (u64) listener_index;

  if ((rv = app_worker_init_accepted (s)))
    {
      session_free (s);
      return rv;
    }

  session_lookup_add_connection (tc, session_handle (s));
  session_set_state (s, SESSION_STATE_ACCEPTING);

  app_wrk = app_worker_get (s->app_wrk_index);
  if ((rv = app_worker_accept_notify (app_wrk, s)))
    {
      session_lookup_del_session (s);
      segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
      session_free (s);
      return rv;
    }

  return 0;
}

int
session_open_cl (session_endpoint_cfg_t *rmt, session_handle_t *rsh)
{
  transport_connection_t *tc;
  transport_endpoint_cfg_t *tep;
  app_worker_t *app_wrk;
  session_handle_t sh;
  session_t *s;
  int rv;

  tep = session_endpoint_to_transport_cfg (rmt);
  rv = transport_connect (rmt->transport_proto, tep, &tc);
  if (rv)
    {
      SESSION_DBG ("Transport failed to open connection.");
      return rv;
    }
  if (!tc)
    {
      SESSION_DBG ("Transport failed to open connection.");
      return SESSION_E_UNKNOWN;
    }

  /* For dgram type of service, allocate session and fifos now */
  app_wrk = app_worker_get (rmt->app_wrk_index);
  s = session_alloc_for_connection (tc);
  s->app_wrk_index = app_wrk->wrk_index;
  s->opaque = rmt->opaque;
  session_set_state (s, SESSION_STATE_OPENED);
  if (transport_connection_is_cless (tc))
    s->flags |= SESSION_F_IS_CLESS;
  if (app_worker_init_connected (app_wrk, s))
    {
      session_free (s);
      return -1;
    }

  sh = session_handle (s);
  *rsh = sh;

  if (!(tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP))
    session_lookup_add_connection (tc, sh);

  return app_worker_connect_notify (app_wrk, s, SESSION_E_NONE, rmt->opaque);
}

int
session_open_vc (session_endpoint_cfg_t *rmt, session_handle_t *rsh)
{
  transport_connection_t *tc;
  transport_endpoint_cfg_t *tep;
  app_worker_t *app_wrk;
  session_t *ho;
  int rv;

  tep = session_endpoint_to_transport_cfg (rmt);
  rv = transport_connect (rmt->transport_proto, tep, &tc);
  if (rv)
    {
      SESSION_DBG ("Transport failed to open connection.");
      return rv;
    }
  if (!tc)
    {
      SESSION_DBG ("Transport failed to open connection.");
      return SESSION_E_UNKNOWN;
    }

  app_wrk = app_worker_get (rmt->app_wrk_index);

  /* If transport offers a vc service, only allocate established
   * session once the connection has been established.
   * In the meantime allocate half-open session for tracking purposes
   * associate half-open connection to it and add session to app-worker
   * half-open table. These are needed to allocate the established
   * session on transport notification, and to cleanup the half-open
   * session if the app detaches before connection establishment.
   */
  ho = session_alloc_for_half_open (tc);
  ho->app_wrk_index = app_wrk->wrk_index;
  ho->ho_index = app_worker_add_half_open (app_wrk, session_handle (ho));
  ho->opaque = rmt->opaque;
  *rsh = session_handle (ho);

  if (!(tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP))
    session_lookup_add_half_open (tc,
				  transport_connection_make_handle (tc->c_index, tc->thread_index));

  return 0;
}

typedef int (*session_open_service_fn) (session_endpoint_cfg_t *, session_handle_t *);

static session_open_service_fn session_open_srv_fns[TRANSPORT_N_SERVICES] = {
  session_open_vc,
  session_open_cl,
};

/**
 * Ask transport to open connection to remote transport endpoint.
 *
 * Stores handle for matching request with reply since the call can be
 * asynchronous. For instance, for TCP the 3-way handshake must complete
 * before reply comes. Session is only created once connection is established.
 *
 * @param app_index Index of the application requesting the connect
 * @param st Session type requested.
 * @param tep Remote transport endpoint
 * @param opaque Opaque data (typically, api_context) the application expects
 * 		 on open completion.
 */
int
session_open (session_endpoint_cfg_t *rmt, session_handle_t *rsh)
{
  transport_service_type_t tst;
  tst = transport_protocol_service_type (rmt->transport_proto);
  return session_open_srv_fns[tst](rmt, rsh);
}

/**
 * Ask transport to open stream on existing connection.
 */
int
session_open_stream (session_endpoint_cfg_t *sep, session_handle_t *rsh)
{
  transport_connection_t *tc;
  transport_endpoint_cfg_t *tep;
  app_worker_t *app_wrk;
  session_t *s;
  u32 conn_index;
  int rv;

  app_wrk = app_worker_get (sep->app_wrk_index);
  tep = session_endpoint_to_transport_cfg (sep);

  /* allocate session and fifos now */
  s = session_alloc_for_stream (sep->parent_handle);
  if (PREDICT_FALSE (!s))
    return SESSION_E_INVALID;

  *rsh = session_handle (s);
  s->app_wrk_index = app_wrk->wrk_index;
  s->opaque = sep->opaque;
  s->flags |= SESSION_F_STREAM;
  if ((rv = app_worker_init_connected (app_wrk, s)))
    {
      session_free (s);
      if (app_worker_application_is_builtin (app_wrk))
	return rv;
      return app_worker_connect_notify (app_wrk, 0, rv, sep->opaque);
    }

  rv = transport_connect_stream (sep->transport_proto, tep, s, &conn_index);
  /* regrab session, pool might grow, transport like h3 might open quic stream */
  s = session_get_from_handle (*rsh);
  if (rv < 0)
    {
      SESSION_DBG ("Transport failed to open stream.");
      segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
      session_free (s);
      if (app_worker_application_is_builtin (app_wrk))
	return rv;
      return app_worker_connect_notify (app_wrk, 0, rv, sep->opaque);
    }

  tc = transport_get_connection (sep->transport_proto, conn_index,
				 session_thread_from_handle (sep->parent_handle));

  /* Attach transport to session and vice versa */
  s->connection_index = tc->c_index;
  tc->s_index = s->session_index;

  session_set_state (s, SESSION_STATE_READY);

  /* builtin apps are synchronous */
  if (app_worker_application_is_builtin (app_wrk))
    {
      s->flags |= SESSION_F_RX_READY;
      return SESSION_E_NONE;
    }

  return app_worker_connect_notify (app_wrk, s, SESSION_E_NONE, sep->opaque);
}

/**
 * Ask transport to listen on session endpoint.
 *
 * @param s Session for which listen will be called. Note that unlike
 * 	    established sessions, listen sessions are not associated to a
 * 	    thread.
 * @param sep Local endpoint to be listened on.
 */
int
session_listen (session_t *ls, session_endpoint_cfg_t *sep)
{
  transport_endpoint_cfg_t *tep;
  int tc_index;
  u32 s_index;

  /* Transport bind/listen */
  tep = session_endpoint_to_transport_cfg (sep);
  s_index = ls->session_index;
  tc_index = transport_start_listen (session_get_transport_proto (ls), s_index, tep);

  if (tc_index < 0)
    return tc_index;

  /* Attach transport to session. Lookup tables are populated by the app
   * worker because local tables (for ct sessions) are not backed by a fib */
  ls = listen_session_get (s_index);
  ls->connection_index = tc_index;
  ls->opaque = sep->opaque;
  if (transport_connection_is_cless (session_get_transport (ls)))
    ls->flags |= SESSION_F_IS_CLESS;

  return 0;
}

/**
 * Ask transport to stop listening on local transport endpoint.
 *
 * @param s Session to stop listening on. It must be in state LISTENING.
 */
int
session_stop_listen (session_t *s)
{
  transport_proto_t tp = session_get_transport_proto (s);
  transport_connection_t *tc;

  if (s->session_state != SESSION_STATE_LISTENING)
    return SESSION_E_NOLISTEN;

  tc = transport_get_listener (tp, s->connection_index);

  /* If no transport, assume everything was cleaned up already */
  if (!tc)
    return SESSION_E_NONE;

  if (!(tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP))
    session_lookup_del_connection (tc);

  transport_stop_listen (tp, s->connection_index);
  return 0;
}

/**
 * Initialize session half-closing procedure.
 *
 * Note that half-closing will not change the state of the session.
 */
void
session_half_close (session_t *s)
{
  if (!s)
    return;

  session_program_transport_ctrl_evt (s, SESSION_CTRL_EVT_HALF_CLOSE);
}

/**
 * Initialize session closing procedure.
 *
 * Request is always sent to session node to ensure that all outstanding
 * requests are served before transport is notified.
 */
void
session_close (session_t *s)
{
  if (!s || (s->flags & SESSION_F_APP_CLOSED))
    return;

  /* Transports can close and delete their state independent of app closes
   * and transport initiated state transitions can hide app closes. Instead
   * of extending the state machine to support separate tracking of app and
   * transport initiated closes, use a flag. */
  s->flags |= SESSION_F_APP_CLOSED;

  /* Disable fifo tuning when app closes */
  s->flags &= ~SESSION_F_CUSTOM_FIFO_TUNING;

  if (s->session_state >= SESSION_STATE_CLOSING)
    {
      /* Session will only be removed once both app and transport
       * acknowledge the close */
      if (s->session_state == SESSION_STATE_TRANSPORT_CLOSED ||
	  s->session_state == SESSION_STATE_TRANSPORT_DELETED)
	session_program_transport_ctrl_evt (s, SESSION_CTRL_EVT_CLOSE);
      return;
    }

  /* App closed so stop propagating dequeue notifications.
   * App might disconnect session before connected, in this case,
   * tx_fifo may not be setup yet, so clear only it's inited. */
  if (s->tx_fifo)
    svm_fifo_clear_deq_ntf (s->tx_fifo);
  session_set_state (s, SESSION_STATE_CLOSING);
  session_program_transport_ctrl_evt (s, SESSION_CTRL_EVT_CLOSE);
}

/**
 * Force a close without waiting for data to be flushed
 */
void
session_reset (session_t *s)
{
  if (s->flags & SESSION_F_APP_CLOSED)
    return;
  s->flags |= SESSION_F_APP_CLOSED;
  s->flags &= ~SESSION_F_CUSTOM_FIFO_TUNING;

  if (s->session_state >= SESSION_STATE_CLOSING)
    {
      /* Session will only be removed once both app and transport
       * acknowledge the close */
      if (s->session_state == SESSION_STATE_TRANSPORT_CLOSED ||
	  s->session_state == SESSION_STATE_TRANSPORT_DELETED)
	session_program_transport_ctrl_evt (s, SESSION_CTRL_EVT_RESET);
      return;
    }

  /* App closed so stop propagating dequeue notifications.
   * App might disconnect session before connected, in this case,
   * tx_fifo may not be setup yet, so clear only it's inited. */
  if (s->tx_fifo)
    svm_fifo_clear_deq_ntf (s->tx_fifo);
  session_set_state (s, SESSION_STATE_CLOSING);
  session_program_transport_ctrl_evt (s, SESSION_CTRL_EVT_RESET);
}

void
session_detach_app (session_t *s)
{
  if (s->session_state < SESSION_STATE_TRANSPORT_CLOSING)
    {
      session_close (s);
    }
  else if (s->session_state < SESSION_STATE_TRANSPORT_DELETED)
    {
      transport_connection_t *tc;

      /* Transport is closing but it's not yet deleted. Confirm close and
       * subsequently detach transport from session and enqueue a session
       * cleanup notification. Transport closed and cleanup notifications are
       * going to be dropped by session layer apis */
      transport_close (session_get_transport_proto (s), s->connection_index, s->thread_index);
      tc = session_get_transport (s);
      tc->s_index = SESSION_INVALID_INDEX;
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify (s, SESSION_CLEANUP_SESSION);
    }
  else
    {
      session_cleanup_notify (s, SESSION_CLEANUP_SESSION);
    }

  s->flags |= SESSION_F_APP_CLOSED;
  s->app_wrk_index = APP_INVALID_INDEX;
}

/**
 * Notify transport the session can be half-disconnected.
 *
 * Must be called from the session's thread.
 */
void
session_transport_half_close (session_t *s)
{
  /* A half-close may also be requested after the peer has already sent FIN.
   * In that case the session is transport-closing and the transport must be
   * allowed to send its FIN to complete the passive close. */
  if (s->session_state != SESSION_STATE_READY &&
      s->session_state != SESSION_STATE_TRANSPORT_CLOSING)
    return;

  transport_half_close (session_get_transport_proto (s), s->connection_index, s->thread_index);
}

/**
 * Notify transport the session can be disconnected. This should eventually
 * result in a delete notification that allows us to cleanup session state.
 * Called for both active/passive disconnects.
 *
 * Must be called from the session's thread.
 */
void
session_transport_close (session_t *s)
{
  if (s->session_state >= SESSION_STATE_APP_CLOSED)
    {
      if (s->session_state == SESSION_STATE_TRANSPORT_CLOSED)
	session_set_state (s, SESSION_STATE_CLOSED);
      /* If transport is already deleted, just free the session. Half-opens
       * expected to be already cleaning up at this point */
      else if (s->session_state >= SESSION_STATE_TRANSPORT_DELETED &&
	       !(s->flags & SESSION_F_HALF_OPEN))
	session_program_cleanup (s);
      return;
    }

  /* If the tx queue wasn't drained, the transport can continue to try
   * sending the outstanding data (in closed state it cannot). It MUST however
   * at one point, either after sending everything or after a timeout, call
   * delete notify. This will finally lead to the complete cleanup of the
   * session.
   */
  session_set_state (s, SESSION_STATE_APP_CLOSED);

  transport_close (session_get_transport_proto (s), s->connection_index, s->thread_index);
}

/**
 * Force transport close
 */
void
session_transport_reset (session_t *s)
{
  if (s->session_state >= SESSION_STATE_APP_CLOSED)
    {
      if (s->session_state == SESSION_STATE_TRANSPORT_CLOSED)
	session_set_state (s, SESSION_STATE_CLOSED);
      else if (s->session_state >= SESSION_STATE_TRANSPORT_DELETED &&
	       !(s->flags & SESSION_F_HALF_OPEN))
	session_program_cleanup (s);
      return;
    }

  session_set_state (s, SESSION_STATE_APP_CLOSED);
  transport_reset (session_get_transport_proto (s), s->connection_index, s->thread_index);
}

/**
 * Cleanup transport and session state.
 *
 * Notify transport of the cleanup and free the session. This should
 * be called only if transport reported some error and is already
 * closed.
 */
void
session_transport_cleanup (session_t *s)
{
  /* Delete from main lookup table before we axe the the transport */
  session_lookup_del_session (s);
  if (s->session_state != SESSION_STATE_TRANSPORT_DELETED)
    transport_cleanup (session_get_transport_proto (s), s->connection_index, s->thread_index);
  /* Since we called cleanup, no delete notification will come. So, make
   * sure the session is properly freed. */
  segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
  session_free (s);
}

/**
 * Allocate worker mqs in share-able segment
 *
 * That can only be a newly created memfd segment, that must be mapped
 * by all apps/stack users unless private rx mqs are enabled.
 */
void
session_vpp_wrk_mqs_alloc (session_main_t *smm)
{
  u32 mq_q_length = 2048, evt_size = sizeof (session_event_t);
  fifo_segment_t *mqs_seg = &smm->wrk_mqs_segment;
  svm_msg_q_cfg_t _cfg, *cfg = &_cfg;
  uword mqs_seg_size;
  int i;

  mq_q_length = clib_max (mq_q_length, smm->configured_wrk_mq_length);

  svm_msg_q_ring_cfg_t rc[SESSION_MQ_N_RINGS] = { { mq_q_length, evt_size, 0 },
						  { mq_q_length >> 1, 256, 0 } };
  cfg->consumer_pid = 0;
  cfg->n_rings = 2;
  cfg->q_nitems = mq_q_length;
  cfg->ring_cfgs = rc;

  /*
   * Compute mqs segment size based on rings config and leave space
   * for passing extended configuration messages, i.e., data allocated
   * outside of the rings. If provided with a config value, accept it
   * if larger than minimum size.
   */
  mqs_seg_size = svm_msg_q_size_to_alloc (cfg) * vec_len (smm->wrk);
  mqs_seg_size = mqs_seg_size + (1 << 20);
  mqs_seg_size = clib_max (mqs_seg_size, smm->wrk_mqs_segment_size);

  mqs_seg->ssvm.ssvm_size = mqs_seg_size;
  mqs_seg->ssvm.my_pid = getpid ();
  mqs_seg->ssvm.name = format (0, "%s%c", "session: wrk-mqs-segment", 0);

  if (ssvm_server_init (&mqs_seg->ssvm, SSVM_SEGMENT_MEMFD))
    {
      clib_warning ("failed to initialize queue segment");
      return;
    }

  fifo_segment_init (mqs_seg);

  /* Special fifo segment that's filled only with mqs */
  mqs_seg->h->n_mqs = vec_len (smm->wrk);

  for (i = 0; i < vec_len (smm->wrk); i++)
    smm->wrk[i].vpp_event_queue = fifo_segment_msg_q_alloc (mqs_seg, i, cfg);
}

fifo_segment_t *
session_main_get_wrk_mqs_segment (void)
{
  return &session_main.wrk_mqs_segment;
}

u64
session_segment_handle (session_t *s)
{
  svm_fifo_t *f;

  if (!s->rx_fifo)
    return SESSION_INVALID_HANDLE;

  f = s->rx_fifo;
  return segment_manager_make_segment_handle (f->segment_manager, f->segment_index);
}

void
session_get_original_dst (transport_endpoint_t *i2o_src, transport_endpoint_t *i2o_dst,
			  transport_proto_t transport_proto, u32 *original_dst,
			  u16 *original_dst_port)
{
  session_main_t *smm = vnet_get_session_main ();
  ip_protocol_t proto = (transport_proto == TRANSPORT_PROTO_TCP ? IPPROTO_TCP : IPPROTO_UDP);
  if (!smm->original_dst_lookup || !i2o_dst->is_ip4)
    return;
  smm->original_dst_lookup (&i2o_src->ip.ip4, i2o_src->port, &i2o_dst->ip.ip4, i2o_dst->port, proto,
			    original_dst, original_dst_port);
}

static session_fifo_rx_fn *session_tx_fns[TRANSPORT_TX_N_FNS] = { session_tx_fifo_peek_and_snd,
								  session_tx_fifo_dequeue_and_snd,
								  session_tx_fifo_dequeue_internal,
								  session_tx_fifo_dequeue_and_snd };

void
session_register_transport (transport_proto_t transport_proto, const transport_proto_vft_t *vft,
			    u8 is_ip4, u32 output_node)
{
  session_main_t *smm = &session_main;
  session_type_t session_type;
  u32 next_index = ~0;

  session_type = session_type_from_proto_and_ip (transport_proto, is_ip4);

  vec_validate (smm->session_type_to_next, session_type);
  vec_validate (smm->session_tx_fns, session_type);

  if (output_node != ~0)
    next_index = vlib_node_add_next (vlib_get_main (), session_queue_node.index, output_node);

  smm->session_type_to_next[session_type] = next_index;
  smm->session_tx_fns[session_type] = session_tx_fns[vft->transport_options.tx_type];
}

static void
session_update_time_fn_vec_update (session_update_time_fn **fns, session_update_time_fn fn,
				   u8 is_add)
{
  session_update_time_fn *fi;
  u32 fi_pos = ~0;
  u8 found = 0;

  vec_foreach (fi, *fns)
    {
      if (*fi == fn)
	{
	  fi_pos = fi - *fns;
	  found = 1;
	  break;
	}
    }

  if (is_add)
    {
      if (found)
	{
	  clib_warning ("update time fn %p already registered", fn);
	  return;
	}
      vec_add1 (*fns, fn);
    }
  else
    {
      if (found)
	vec_del1 (*fns, fi_pos);
    }
}

void
session_register_update_time_fn_w_thread (session_update_time_fn fn, u8 is_add,
					  clib_thread_index_t thread_index)
{
  session_worker_t *wrk;

  ASSERT (thread_index < vec_len (session_main.wrk));

  wrk = session_main_get_worker (thread_index);
  session_update_time_fn_vec_update (&wrk->update_time_fns, fn, is_add);
}

void
session_register_update_time_fn (session_update_time_fn fn, u8 is_add)
{
  session_main_t *smm = &session_main;
  clib_thread_index_t thread_index;

  for (thread_index = 0; thread_index < vec_len (smm->wrk); thread_index++)
    session_register_update_time_fn_w_thread (fn, is_add, thread_index);
}

transport_proto_t
session_add_transport_proto (void)
{
  session_main_t *smm = &session_main;
  session_worker_t *wrk;
  u32 thread;

  smm->last_transport_proto_type += 1;

  for (thread = 0; thread < vec_len (smm->wrk); thread++)
    {
      wrk = session_main_get_worker (thread);
      vec_validate (wrk->session_to_enqueue, smm->last_transport_proto_type);
    }

  return smm->last_transport_proto_type;
}

transport_connection_t *
session_get_transport (session_t *s)
{
  if (s->session_state != SESSION_STATE_LISTENING)
    return transport_get_connection (session_get_transport_proto (s), s->connection_index,
				     s->thread_index);
  else
    return transport_get_listener (session_get_transport_proto (s), s->connection_index);
}

void
session_get_endpoint (session_t *s, transport_endpoint_t *tep_rmt, transport_endpoint_t *tep_lcl)
{
  if (s->session_state != SESSION_STATE_LISTENING)
    return transport_get_endpoint (session_get_transport_proto (s), s->connection_index,
				   s->thread_index, tep_rmt, tep_lcl);
  else
    return transport_get_listener_endpoint (session_get_transport_proto (s), s->connection_index,
					    tep_rmt, tep_lcl);
}

int
session_transport_attribute (session_t *s, u8 is_get, transport_endpt_attr_t *attr)
{
  if (!is_get && s->session_state < SESSION_STATE_READY)
    return -1;

  return transport_connection_attribute (session_get_transport_proto (s), s->connection_index,
					 s->thread_index, is_get, attr);
}

transport_connection_t *
listen_session_get_transport (session_t *s)
{
  return transport_get_listener (session_get_transport_proto (s), s->connection_index);
}

void
session_queue_run_on_main_thread (vlib_main_t *vm)
{
  ASSERT (vlib_get_thread_index () == 0);
  vlib_node_set_interrupt_pending (vm, session_queue_node.index);
}

static void
session_stats_collector_fn (vlib_stats_collector_data_t *d)
{
  u32 i, n_workers, n_wrk_sessions, n_sessions = 0;
  session_main_t *smm = &session_main;
  session_worker_t *wrk;
  counter_t **counters;
  counter_t *cb;

  n_workers = vec_len (smm->wrk);
  vlib_stats_validate (d->entry_index, 0, n_workers - 1);
  counters = d->entry->data;
  cb = counters[0];

  for (i = 0; i < vec_len (smm->wrk); i++)
    {
      wrk = session_main_get_worker (i);
      n_wrk_sessions = pool_elts (wrk->sessions);
      cb[i] = n_wrk_sessions;
      n_sessions += n_wrk_sessions;
    }

  vlib_stats_set_gauge (d->private_data, n_sessions);
  vlib_stats_set_gauge (smm->stats_seg_idx.tp_port_alloc_max_tries,
			transport_port_alloc_max_tries ());
}

static void
session_stats_collector_init (void)
{
  session_main_t *smm = &session_main;
  vlib_stats_collector_reg_t reg = {};

  reg.entry_index = vlib_stats_add_counter_vector ("/sys/session/sessions_per_worker");
  reg.private_data = vlib_stats_add_gauge ("/sys/session/sessions_total");
  reg.collect_fn = session_stats_collector_fn;
  vlib_stats_register_collector_fn (&reg);
  vlib_stats_validate (reg.entry_index, 0, vlib_get_n_threads ());

  smm->stats_seg_idx.tp_port_alloc_max_tries =
    vlib_stats_add_gauge ("/sys/session/transport_port_alloc_max_tries");
  vlib_stats_set_gauge (smm->stats_seg_idx.tp_port_alloc_max_tries, 0);
}

static clib_error_t *
session_manager_main_enable (vlib_main_t *vm, session_rt_engine_type_t rt_engine_type)
{
  session_main_t *smm = &session_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads, preallocated_sessions_per_worker;
  session_worker_t *wrk;
  int i;

  if (session_rt_backend_enable_disable (rt_engine_type))
    return clib_error_return (0, "error on enable backend engine");

  /* We only initialize once and do not de-initialized on disable */
  if (smm->is_initialized)
    goto done;

  num_threads = 1 /* main thread */ + vtm->n_threads;

  if (num_threads < 1)
    return clib_error_return (0, "n_thread_stacks not set");

  /* Allocate cache line aligned worker contexts */
  vec_validate_aligned (smm->wrk, num_threads - 1, CLIB_CACHE_LINE_BYTES);
  clib_spinlock_init (&session_main.pool_realloc_lock);
  clib_spinlock_init (&session_observability_terminals_lock);

  for (i = 0; i < num_threads; i++)
    {
      wrk = &smm->wrk[i];
      wrk->ctrl_head = clib_llist_make_head (wrk->event_elts, evt_list);
      wrk->new_head = clib_llist_make_head (wrk->event_elts, evt_list);
      wrk->old_head = clib_llist_make_head (wrk->event_elts, evt_list);
      wrk->pending_connects = clib_llist_make_head (wrk->event_elts, evt_list);
      wrk->evts_pending_main = clib_llist_make_head (wrk->event_elts, evt_list);
      wrk->vm = vlib_get_main_by_index (i);
      wrk->last_vlib_time = vlib_time_now (vm);
      wrk->last_vlib_us_time = wrk->last_vlib_time * CLIB_US_TIME_FREQ;
      wrk->timerfd = -1;
      vec_validate (wrk->session_to_enqueue, smm->last_transport_proto_type);
      clib_spinlock_init (&wrk->session_migrate_lock);
      clib_spinlock_init (&wrk->observability_retry_lock);

      if (!smm->no_adaptive && smm->use_private_rx_mqs)
	session_wrk_enable_adaptive_mode (wrk);
    }

  /* Allocate vpp event queues segment and queue */
  session_vpp_wrk_mqs_alloc (smm);

  /* Initialize segment manager properties */
  segment_manager_main_init (smm->no_dump_segments);

  /* Preallocate sessions */
  if (smm->preallocated_sessions)
    {
      if (num_threads == 1)
	{
	  pool_init_fixed (smm->wrk[0].sessions, smm->preallocated_sessions);
	}
      else
	{
	  int j;
	  preallocated_sessions_per_worker =
	    (1.1 * (f64) smm->preallocated_sessions / (f64) (num_threads - 1));

	  for (j = 1; j < num_threads; j++)
	    {
	      pool_init_fixed (smm->wrk[j].sessions, preallocated_sessions_per_worker);
	    }
	}
    }

  session_lookup_init ();
  app_namespaces_init ();
  transport_init ();
  session_stats_collector_init ();
  smm->is_initialized = 1;

done:

  smm->is_enabled = 1;

  /* Enable transports */
  transport_enable_disable (vm, 1);
  session_debug_init ();

  return 0;
}

static void
session_manager_main_disable (vlib_main_t *vm, session_rt_engine_type_t rt_engine_type)
{
  transport_enable_disable (vm, 0 /* is_en */);
  session_rt_backend_enable_disable (rt_engine_type);
}

/* in this new callback, cookie hint the index */
void
session_dma_completion_cb (vlib_main_t *vm, struct vlib_dma_batch *batch)
{
  session_worker_t *wrk;
  wrk = session_main_get_worker (vm->thread_index);
  session_dma_transfer *dma_transfer;

  dma_transfer = &wrk->dma_trans[wrk->trans_head];
  vec_add (wrk->pending_tx_buffers, dma_transfer->pending_tx_buffers,
	   vec_len (dma_transfer->pending_tx_buffers));
  vec_add (wrk->pending_tx_nexts, dma_transfer->pending_tx_nexts,
	   vec_len (dma_transfer->pending_tx_nexts));
  vec_reset_length (dma_transfer->pending_tx_buffers);
  vec_reset_length (dma_transfer->pending_tx_nexts);
  wrk->trans_head++;
  if (wrk->trans_head == wrk->trans_size)
    wrk->trans_head = 0;
  return;
}

static void
session_prepare_dma_args (vlib_dma_config_t *args)
{
  args->max_batches = 16;
  args->max_transfers = DMA_TRANS_SIZE;
  args->max_transfer_size = 65536;
  args->features = 0;
  args->sw_fallback = 1;
  args->barrier_before_last = 1;
  args->callback_fn = session_dma_completion_cb;
}

static void
session_node_enable_dma (u8 is_en, int n_vlibs)
{
  vlib_dma_config_t args;
  session_prepare_dma_args (&args);
  session_worker_t *wrk;
  vlib_main_t *vm;

  int config_index = -1;

  if (is_en)
    {
      vm = vlib_get_main_by_index (0);
      config_index = vlib_dma_config_add (vm, &args);
    }
  else
    {
      vm = vlib_get_main_by_index (0);
      wrk = session_main_get_worker (0);
      if (wrk->config_index >= 0)
	vlib_dma_config_del (vm, wrk->config_index);
    }
  int i;
  for (i = 0; i < n_vlibs; i++)
    {
      vm = vlib_get_main_by_index (i);
      wrk = session_main_get_worker (vm->thread_index);
      wrk->config_index = config_index;
      if (is_en)
	{
	  if (config_index >= 0)
	    wrk->dma_enabled = true;
	  wrk->dma_trans = (session_dma_transfer *) clib_mem_alloc (sizeof (session_dma_transfer) *
								    DMA_TRANS_SIZE);
	  bzero (wrk->dma_trans, sizeof (session_dma_transfer) * DMA_TRANS_SIZE);
	}
      else
	{
	  if (wrk->dma_trans)
	    clib_mem_free (wrk->dma_trans);
	}
      wrk->trans_head = 0;
      wrk->trans_tail = 0;
      wrk->trans_size = DMA_TRANS_SIZE;
    }
}

static void
session_main_start_q_process (vlib_main_t *vm, vlib_node_state_t state)
{
  vlib_node_t *n;

  vlib_node_set_state (vm, session_queue_process_node.index, state);
  n = vlib_get_node (vm, session_queue_process_node.index);
  vlib_start_process (vm, n->runtime_index);
}

void
session_node_enable_disable (u8 is_en)
{
  u8 mstate = is_en ? VLIB_NODE_STATE_INTERRUPT : VLIB_NODE_STATE_DISABLED;
  u8 state = is_en ? VLIB_NODE_STATE_POLLING : VLIB_NODE_STATE_DISABLED;
  session_main_t *sm = &session_main;
  vlib_main_t *vm;
  int n_vlibs, i;

  n_vlibs = vlib_get_n_threads ();
  for (i = 0; i < n_vlibs; i++)
    {
      vm = vlib_get_main_by_index (i);
      /* main thread with workers and not polling */
      if (i == 0 && n_vlibs > 1)
	{
	  vlib_node_set_state (vm, session_queue_node.index, mstate);
	  if (is_en)
	    {
	      session_main_get_worker (0)->state = SESSION_WRK_INTERRUPT;
	      session_main_start_q_process (vm, state);
	    }
	  else
	    {
	      vlib_process_signal_event_mt (vm, session_queue_process_node.index,
					    SESSION_Q_PROCESS_STOP, 0);
	    }
	  if (!sm->poll_main)
	    continue;
	}
      vlib_node_set_state (vm, session_input_node.index, mstate);
      vlib_node_set_state (vm, session_queue_node.index, state);
    }

  if (sm->use_private_rx_mqs)
    application_enable_rx_mqs_nodes (is_en);

  if (sm->dma_enabled)
    session_node_enable_dma (is_en, n_vlibs);
}

clib_error_t *
vnet_session_enable_disable (vlib_main_t *vm, session_enable_disable_args_t *args)
{
  clib_error_t *error = 0;

  if (args->is_en)
    {
      if (session_main.is_enabled)
	return 0;

      error = session_manager_main_enable (vm, args->rt_engine_type);
      session_node_enable_disable (1);
    }
  else
    {
      session_main.is_enabled = 0;
      session_manager_main_disable (vm, args->rt_engine_type);
      session_node_enable_disable (0);
    }

  return error;
}

clib_error_t *
session_main_init (vlib_main_t *vm)
{
  session_main_t *smm = &session_main;

  smm->is_enabled = 0;
  smm->session_enable_asap = 0;
  smm->poll_main = 0;
  smm->use_private_rx_mqs = 0;
  smm->no_adaptive = 0;
  smm->last_transport_proto_type = TRANSPORT_PROTO_HTTP;
  smm->port_allocator_min_src_port = 1024;
  smm->port_allocator_max_src_port = 65535;

  /* default enable app socket api */
  (void) appns_sapi_enable_disable (1 /* is_enable */);

  return 0;
}

VLIB_INIT_FUNCTION (session_main_init);

static clib_error_t *
session_main_loop_init (vlib_main_t *vm)
{
  session_main_t *smm = &session_main;

  if (smm->session_enable_asap)
    {
      session_enable_disable_args_t args = { .is_en = 1, .rt_engine_type = smm->rt_engine_type };

      vlib_worker_thread_barrier_sync (vm);
      vnet_session_enable_disable (vm, &args);
      vlib_worker_thread_barrier_release (vm);
    }
  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (session_main_loop_init);
