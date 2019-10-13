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

static LONG_PTR
HvmOp(
    IN  ULONG   Command,
    IN  PVOID   Argument
    )
{
    return HYPERCALL(LONG_PTR, hvm_op, 2, Command, Argument);
}

__checkReturn
XEN_API
NTSTATUS
HvmSetParam(
    IN  ULONG               Parameter,
    IN  ULONGLONG           Value
    )
{
    struct xen_hvm_param    op;
    LONG_PTR                rc;
    NTSTATUS                status;

    op.domid = DOMID_SELF;
    op.index = Parameter;
    op.value = Value;

    rc = HvmOp(HVMOP_set_param, &op);
    
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
NTSTATUS
HvmGetParam(
    IN  ULONG               Parameter,
    OUT PULONGLONG          Value
    )
{
    struct xen_hvm_param    op;
    LONG_PTR                rc;
    NTSTATUS                status;

    op.domid = DOMID_SELF;
    op.index = Parameter;
    op.value = 0xFEEDFACE;

    rc = HvmOp(HVMOP_get_param, &op);
    
    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    ASSERT(op.value != 0xFEEDFACE);
    *Value = op.value;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

__checkReturn
XEN_API
NTSTATUS
HvmPagetableDying(
    IN  PHYSICAL_ADDRESS            Address
    )
{
    struct xen_hvm_pagetable_dying  op;
    LONG_PTR                        rc;
    NTSTATUS                        status;

    op.domid = DOMID_SELF;
    op.gpa = Address.QuadPart;

    rc = HvmOp(HVMOP_pagetable_dying, &op);
    
    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    return status;
}

__checkReturn
XEN_API
NTSTATUS
HvmSetEvtchnUpcallVector(
    IN  unsigned int                    vcpu_id,
    IN  UCHAR                           Vector
    )
{
    struct xen_hvm_evtchn_upcall_vector op;
    LONG_PTR                            rc;
    NTSTATUS                            status;

    op.vcpu = vcpu_id;
    op.vector = Vector;

    rc = HvmOp(HVMOP_set_evtchn_upcall_vector, &op);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    return status;
}
