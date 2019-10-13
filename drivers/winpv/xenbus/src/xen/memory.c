/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 * *   Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer in the documentation and/or other 
 *     materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 */

#define XEN_API __declspec(dllexport)

#include <ntddk.h>
#include <xen.h>

#include "hypercall.h"
#include "dbg_print.h"
#include "assert.h"

static FORCEINLINE LONG_PTR
MemoryOp(
    IN  ULONG   Command,
    IN  PVOID   Argument
    )
{
    return HYPERCALL(LONG_PTR, memory_op, 2, Command, Argument);
}

__checkReturn
XEN_API
NTSTATUS
MemoryAddToPhysmap(
    IN  PFN_NUMBER              Pfn,
    IN  ULONG                   Space,
    IN  ULONG_PTR               Offset
    )
{
    struct xen_add_to_physmap   op;
    LONG_PTR                    rc;
    NTSTATUS                    status;

    op.domid = DOMID_SELF;
    op.space = Space;
    op.idx = Offset;
    op.gpfn = (xen_pfn_t)Pfn;

    rc = MemoryOp(XENMEM_add_to_physmap, &op);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

__checkReturn
XEN_API
ULONG
MemoryDecreaseReservation(
    IN  ULONG                       Order,
    IN  ULONG                       Count,
    IN  PPFN_NUMBER                 PfnArray
    )
{
    struct xen_memory_reservation   op;
    LONG_PTR                        rc;

    set_xen_guest_handle(op.extent_start, PfnArray);
    op.extent_order = Order;
    op.mem_flags = 0;
    op.domid = DOMID_SELF;
    op.nr_extents = Count;

    rc = MemoryOp(XENMEM_decrease_reservation, &op);

    return (ULONG)rc;
}

__checkReturn
XEN_API
ULONG
MemoryPopulatePhysmap(
    IN  ULONG                       Order,
    IN  ULONG                       Count,
    IN  PPFN_NUMBER                 PfnArray
    )
{
    struct xen_memory_reservation   op;
    LONG_PTR                        rc;

    set_xen_guest_handle(op.extent_start, PfnArray);
    op.extent_order = Order;
    op.mem_flags = 0;
    op.domid = DOMID_SELF;
    op.nr_extents = Count;

    rc = MemoryOp(XENMEM_populate_physmap, &op);

    return (ULONG)rc;
}


