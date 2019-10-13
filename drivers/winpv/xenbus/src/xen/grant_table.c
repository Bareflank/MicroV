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

#pragma warning(push)
#pragma warning(disable:4127)   // conditional expression is constant

// Most of the GNTST_* values don't have meaningful NTSTATUS counterparts,
// this macro translates those that do.
#define GNTST_TO_STATUS(_gntst, _status)                    \
        do {                                                \
            switch (_gntst) {                               \
            case GNTST_okay:                                \
                _status = STATUS_SUCCESS;                   \
                break;                                      \
                                                            \
            case GNTST_bad_handle:                          \
                _status = STATUS_INVALID_HANDLE;            \
                break;                                      \
                                                            \
            case GNTST_permission_denied:                   \
                _status = STATUS_ACCESS_DENIED;             \
                break;                                      \
                                                            \
            case GNTST_eagain:                              \
                _status = STATUS_RETRY;                     \
                break;                                      \
                                                            \
            default:                                        \
                _status = STATUS_UNSUCCESSFUL;              \
                break;                                      \
            }                                               \
        } while (FALSE)

#pragma warning(pop)

static LONG_PTR
GrantTableOp(
    IN  ULONG   Command,
    IN  PVOID   Argument,
    IN  ULONG   Count
    )
{
    return HYPERCALL(LONG_PTR, grant_table_op, 3, Command, Argument, Count);
}

__checkReturn
XEN_API
NTSTATUS
GrantTableSetVersion(
    IN  uint32_t                Version
    )
{
    struct gnttab_set_version   op;
    LONG_PTR                    rc;
    NTSTATUS                    status;

    op.version = Version;

    rc = GrantTableOp(GNTTABOP_set_version, &op, 1);

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
GrantTableGetVersion(
    OUT uint32_t                *Version
    )
{
    struct gnttab_get_version   op;
    LONG_PTR                    rc;
    NTSTATUS                    status;

    op.dom = DOMID_SELF;

    rc = GrantTableOp(GNTTABOP_get_version, &op, 1);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    *Version = op.version;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

__checkReturn
XEN_API
NTSTATUS
GrantTableCopy(
    IN  struct gnttab_copy  op[],
    IN  ULONG               Count
    )
{
    LONG_PTR                rc;
    NTSTATUS                status;

    rc = GrantTableOp(GNTTABOP_copy, &op[0], Count);

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
GrantTableMapForeignPage(
    IN  USHORT                  Domain,
    IN  ULONG                   GrantRef,
    IN  PHYSICAL_ADDRESS        Address,
    IN  BOOLEAN                 ReadOnly,
    OUT ULONG                   *Handle
    )
{
    struct gnttab_map_grant_ref op;
    LONG_PTR                    rc;
    NTSTATUS                    status;

    RtlZeroMemory(&op, sizeof(op));
    op.dom = Domain;
    op.ref = GrantRef;
    op.flags = GNTMAP_host_map;
    if (ReadOnly)
        op.flags |= GNTMAP_readonly;
    op.host_addr = Address.QuadPart;

    rc = GrantTableOp(GNTTABOP_map_grant_ref, &op, 1);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    if (op.status != GNTST_okay) {
        Warning("%u:%u -> %u.%u failed (%d)\n",
                op.dom,
                op.ref,
                Address.HighPart,
                Address.LowPart,
                op.status);

        GNTST_TO_STATUS(op.status, status);
        goto fail2;
    }

    *Handle = op.handle;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

__checkReturn
XEN_API
NTSTATUS
GrantTableUnmapForeignPage(
    IN  ULONG                     Handle,
    IN  PHYSICAL_ADDRESS          Address
    )
{
    struct gnttab_unmap_grant_ref op;
    LONG_PTR                      rc;
    NTSTATUS                      status;

    RtlZeroMemory(&op, sizeof(op));
    op.handle = Handle;
    op.host_addr = Address.QuadPart;

    rc = GrantTableOp(GNTTABOP_unmap_grant_ref, &op, 1);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    if (op.status != GNTST_okay) {
        Warning("%u.%u failed (%d)\n",
                Address.HighPart,
                Address.LowPart,
                op.status);

        GNTST_TO_STATUS(op.status, status);
        goto fail2;
    }

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

__checkReturn
XEN_API
NTSTATUS
GrantTableQuerySize(
    OUT uint32_t                *Current OPTIONAL,
    OUT uint32_t                *Maximum OPTIONAL
    )
{
    struct gnttab_query_size    op;
    LONG_PTR                    rc;
    NTSTATUS                    status;

    op.dom = DOMID_SELF;

    rc = GrantTableOp(GNTTABOP_query_size, &op, 1);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    status = STATUS_UNSUCCESSFUL;
    if (op.status != GNTST_okay)
        goto fail2;

    if (Current != NULL)
        *Current = op.nr_frames;

    if (Maximum != NULL)
        *Maximum = op.max_nr_frames;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}
