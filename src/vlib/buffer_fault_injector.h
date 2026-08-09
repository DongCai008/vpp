/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/*
 * Copyright (c) 2026
 */

#ifndef included_vlib_buffer_fault_injector_h
#define included_vlib_buffer_fault_injector_h

#include <vppinfra/types.h>

struct vlib_main_t;

/** \brief Select one buffer-allocation request to fail in this VLIB thread.

    This test-only facility exists only in builds configured with
    @c VPP_BUFFER_FAULT_INJECTOR. @c fail_at is a one-based allocation-request
    ordinal; zero disarms the injector. The selected request returns no
    buffers and the injector disarms itself. The state is scoped to @c vm.
*/
int vlib_buffer_alloc_fault_injector_set (struct vlib_main_t *vm, u64 fail_at);

#endif /* included_vlib_buffer_fault_injector_h */
