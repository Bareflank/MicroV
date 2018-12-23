/*
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <driver.h>

#include <common.h>
#include <bfbfbuilderinterface.h>

#include <bfdebug.h>
#include <bftypes.h>
#include <bfconstants.h>
#include <bfplatform.h>

#define MAX_VMS 0x1000
struct vm_t g_vms[MAX_VMS] = {0};

/* -------------------------------------------------------------------------- */
/* VM Helpers                                                                 */
/* -------------------------------------------------------------------------- */

FAST_MUTEX g_vm_mutex;

static struct vm_t *
acquire_vm(void)
{
    int64_t i;
    struct vm_t *vm = 0;

    ExAcquireFastMutex(&g_vm_mutex);

    for (i = 0; i < MAX_VMS; i++) {
        vm = &g_vms[i];
        if (vm->used == 0) {
            break;
        }
    }

    if (i == MAX_VMS) {
        BFALERT("MAX_VMS reached. No more VMs can be created\n");
        goto done;
    }

    platform_memset(vm, 0, sizeof(struct vm_t));
    vm->used = 1;

done:

    ExReleaseFastMutex(&g_vm_mutex);
    return vm;
}

static struct vm_t *
get_vm(domainid_t domainid)
{
    int64_t i;
    struct vm_t *vm = 0;

    ExAcquireFastMutex(&g_vm_mutex);

    for (i = 0; i < MAX_VMS; i++) {
        vm = &g_vms[i];
        if (vm->used == 1 && vm->domainid == domainid) {
            break;
        }
    }

    if (i == MAX_VMS) {
        BFALERT("MAX_VMS reached. Could not locate VM\n");
        goto done;
    }

done:

    ExReleaseFastMutex(&g_vm_mutex);
    return vm;
}

/* -------------------------------------------------------------------------- */
/* Queue Functions                                                            */
/* -------------------------------------------------------------------------- */

static long
ioctl_create_from_elf(struct create_from_elf_args *args)
{
    int64_t ret;

    void *file = 0;
    void *cmdl = 0;

    if (args->file_size != 0) {
        file = platform_alloc_rw(args->file_size);
        if (file == NULL) {
            BFALERT("IOCTL_CREATE_FROM_ELF: failed to allocate memory for file\n");
            goto failed;
        }

        platform_memcpy(file, args->file, args->file_size);
        args->file = file;
    }

    if (args->cmdl_size != 0) {
        cmdl = platform_alloc_rw(args->cmdl_size);
        if (cmdl == NULL) {
            BFALERT("IOCTL_CREATE_FROM_ELF: failed to allocate memory for file\n");
            goto failed;
        }

        platform_memcpy(cmdl, args->cmdl, args->cmdl_size);
        args->cmdl = cmdl;
    }

    ret = common_create_from_elf(acquire_vm(), args);
    if (ret != BF_SUCCESS) {
        BFDEBUG("common_create_from_elf failed: %llx\n", ret);
        goto failed;
    }

    args->file = 0;
    args->cmdl = 0;

    platform_free_rw(file, args->file_size);
    platform_free_rw(cmdl, args->cmdl_size);

    BFDEBUG("IOCTL_CREATE_FROM_ELF: succeeded\n");
    return BF_IOCTL_SUCCESS;

failed:

    args->file = 0;
    args->cmdl = 0;

    platform_free_rw(file, args->file_size);
    platform_free_rw(cmdl, args->cmdl_size);

    BFALERT("IOCTL_CREATE_FROM_ELF: failed\n");
    return BF_IOCTL_FAILURE;
}

static long
ioctl_destroy(domainid_t *args)
{
    int64_t ret;
    domainid_t domainid;

    platform_memcpy(&domainid, args, sizeof(domainid_t));

    ret = common_destroy(get_vm(domainid));
    if (ret != BF_SUCCESS) {
        BFDEBUG("common_destroy failed: %llx\n", ret);
        return BF_IOCTL_FAILURE;
    }

    BFDEBUG("IOCTL_DESTROY: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

NTSTATUS
bfbuilderQueueInitialize(
    _In_ WDFDEVICE Device
)
{
    WDFQUEUE queue;
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;

    ExInitializeFastMutex(&g_vm_mutex);

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchParallel
    );

    queueConfig.EvtIoStop = bfbuilderEvtIoStop;
    queueConfig.EvtIoDeviceControl = bfbuilderEvtIoDeviceControl;

    status = WdfIoQueueCreate(Device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    BFDEBUG("bfbuilderQueueInitialize: success\n");
    return STATUS_SUCCESS;
}

VOID
bfbuilderEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    PVOID in = 0;
    PVOID out = 0;
    size_t in_size = 0;
    size_t out_size = 0;

    int64_t ret = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Queue);

    if (InputBufferLength != 0) {
        status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &in, &in_size);

        if (!NT_SUCCESS(status)) {
            goto IOCTL_FAILURE;
        }
    }

    if (OutputBufferLength != 0) {
        status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &out, &out_size);

        if (!NT_SUCCESS(status)) {
            goto IOCTL_FAILURE;
        }
    }

    switch (IoControlCode) {
        case IOCTL_CREATE_FROM_ELF_CMD:
            ret = ioctl_create_from_elf((struct create_from_elf_args *)in);
            platform_memcpy(out, in, out_size);
            break;

        case IOCTL_DESTROY_CMD:
            ret = ioctl_destroy((domainid_t *)in);
            break;

        default:
            goto IOCTL_FAILURE;
    }

    if (OutputBufferLength != 0) {
        WdfRequestSetInformation(Request, out_size);
    }

    if (ret != BF_IOCTL_SUCCESS) {
        goto IOCTL_FAILURE;
    }

    WdfRequestComplete(Request, STATUS_SUCCESS);
    return;

IOCTL_FAILURE:

    WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
    return;
}

VOID
bfbuilderEvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags
)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(ActionFlags);

    WdfRequestComplete(Request, STATUS_SUCCESS);
    return;
}
