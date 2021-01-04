/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <driver.h>
#include <device.h>
#include <microv/hypercall.h>
#include <microv/visrinterface.h>

extern WDFSPINLOCK VisrEventLock;

typedef struct _VISR_EVENT_CONTEXT {
    PKEVENT    Event;
} VISR_EVENT_CONTEXT, *PVISR_EVENT_CONTEXT;

PVISR_EVENT_CONTEXT EventContext = NULL;

VOID
visr_evt_io_stop(
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

VOID
visr_evt_io_device_control(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    PVOID in = 0;
    size_t in_size = 0;
    NTSTATUS status;
    struct visr_register_event *usr_event;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength != 0) {
        status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &in, &in_size);

        if (!NT_SUCCESS(status)) {
            ERROR("IOCTL_VISR_REGISTER_EVENT: failed to retrieve input buffer\n");
            goto fail;
        }
    }

    switch (IoControlCode) {
    case IOCTL_VISR_REGISTER_EVENT:

        if (!in) {
            ERROR("IOCTL_VISR_REGISTER_EVENT: in buffer is NULL\n");
            goto fail;
        }

        usr_event = (struct visr_register_event *)in;

        if (!usr_event->event) {
            ERROR("IOCTL_VISR_REGISTER_EVENT: in->event is NULL\n");
            goto fail;
        }

        WdfSpinLockAcquire(VisrEventLock);

        if (EventContext) {
            ERROR("IOCTL_VISR_REGISTER_EVENT: event already registered\n");
            WdfSpinLockRelease(VisrEventLock);
            goto fail;
        }

        EventContext = ExAllocatePoolWithTag(NonPagedPool,
                                             sizeof(VISR_EVENT_CONTEXT),
                                             VISR_POOL_TAG);
        if (!EventContext) {
            ERROR("IOCTL_VISR_REGISTER_EVENT: failed to allocate event context\n");
            WdfSpinLockRelease(VisrEventLock);
            goto fail;
        }

        RtlZeroMemory(EventContext, sizeof(VISR_EVENT_CONTEXT));

        WdfSpinLockRelease(VisrEventLock);

        status = ObReferenceObjectByHandle(usr_event->event,
                                           EVENT_MODIFY_STATE,
                                           *ExEventObjectType,
                                           UserMode,
                                           &EventContext->Event,
                                           NULL);
        if (!NT_SUCCESS(status)) {
            ERROR("IOCTL_VISR_REGISTER_EVENT: failed to reference in->event\n");
            goto fail;
        }

        KeMemoryBarrier();

        break;
    default:
        goto fail;
    }

    WdfRequestComplete(Request, STATUS_SUCCESS);
    return;

fail:
    WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
    return;
}

NTSTATUS
visr_queue_init(
    _In_ WDFDEVICE Device
)
{
    WDFQUEUE queue;
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchParallel
    );

    queueConfig.EvtIoStop = visr_evt_io_stop;
    queueConfig.EvtIoDeviceControl = visr_evt_io_device_control;

    status = WdfIoQueueCreate(Device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    DEBUG("visr_queue_init: success\n");
    return STATUS_SUCCESS;
}

NTSTATUS
visr_evt_device_d0_entry(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(PreviousState);

    DEBUG("visr_evt_device_d0_entry called\n");

    return STATUS_SUCCESS;
}

NTSTATUS
visr_evt_device_d0_exit(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE TargetState
)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(TargetState);

    DEBUG("visr_evt_device_d0_exit called\n");

    return STATUS_SUCCESS;
}

NTSTATUS
visr_post_interrupts_enabled(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(PreviousState);

    DEBUG("visr_post_interrupts_enabled called\n");

    return STATUS_SUCCESS;
}

NTSTATUS
visr_pre_interrupts_disabled(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(PreviousState);

    DEBUG("visr_pre_interrupts_disabled called\n");

    return STATUS_SUCCESS;
}

NTSTATUS
visr_query_stop(
    _In_ WDFDEVICE Device
)
{
    UNREFERENCED_PARAMETER(Device);

    DEBUG("visr_query_stop called\n");

    // Returning failure here prevents BARs from being
    // relocated in the event of resource rebalancing.

    return STATUS_UNSUCCESSFUL;
}

BOOLEAN
visr_wdf_isr(
    _In_ WDFINTERRUPT Interrupt,
    _In_ ULONG MessageID
)
{
    UNREFERENCED_PARAMETER(MessageID);

    WDF_INTERRUPT_INFO interrupt_info;
    WDF_INTERRUPT_INFO_INIT(&interrupt_info);
    WdfInterruptGetInfo(Interrupt, &interrupt_info);

    __event_op__send_vector(interrupt_info.Vector);
    (VOID) WdfInterruptQueueDpcForIsr(Interrupt);

    return TRUE;
}

VOID
visr_wdf_interrupt_dpc(
    _In_ WDFINTERRUPT Interrupt,
    _In_ WDFOBJECT AssociatedObject
)
{
    UNREFERENCED_PARAMETER(Interrupt);
    UNREFERENCED_PARAMETER(AssociatedObject);

    WdfSpinLockAcquire(VisrEventLock);

    if (EventContext) {
        (VOID) KeSetEvent(EventContext->Event, 0, FALSE);
    }

    WdfSpinLockRelease(VisrEventLock);
}

NTSTATUS
visr_wdf_interrupt_enable(
    _In_ WDFINTERRUPT Interrupt,
    _In_ WDFDEVICE AssociatedDevice
)
{
    UNREFERENCED_PARAMETER(Interrupt);
    UNREFERENCED_PARAMETER(AssociatedDevice);

    DEBUG("visr_wdf_interrupt_enable called\n");

    return STATUS_SUCCESS;
}

NTSTATUS
visr_wdf_interrupt_disable(
    _In_ WDFINTERRUPT Interrupt,
    _In_ WDFDEVICE AssociatedDevice
)
{
    UNREFERENCED_PARAMETER(Interrupt);
    UNREFERENCED_PARAMETER(AssociatedDevice);

    DEBUG("visr_wdf_interrupt_disable called\n");

    return STATUS_SUCCESS;
}

NTSTATUS
visr_evt_device_add(
    _In_    WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    NTSTATUS status;
    WDFDEVICE device;
    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_INTERRUPT_CONFIG interrupt_cfg;
    WDFINTERRUPT interrupt;

    UNREFERENCED_PARAMETER(Driver);

    // Setup PnP Power Callbacks
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    pnpPowerCallbacks.EvtDeviceD0Entry = visr_evt_device_d0_entry;
    pnpPowerCallbacks.EvtDeviceD0Exit = visr_evt_device_d0_exit;
    pnpPowerCallbacks.EvtDeviceD0EntryPostInterruptsEnabled = visr_post_interrupts_enabled;
    pnpPowerCallbacks.EvtDeviceD0ExitPreInterruptsDisabled = visr_pre_interrupts_disabled;
    pnpPowerCallbacks.EvtDeviceQueryStop = visr_query_stop;

    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

    // Initialize a WDF device
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_visr, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = visr_queue_init(device);
    if (!NT_SUCCESS(status)) {
        ERROR("Failed to initialize IO queue\n");
        return status;
    }

    // Initialize interrupts
    WDF_INTERRUPT_CONFIG_INIT(&interrupt_cfg, visr_wdf_isr, visr_wdf_interrupt_dpc);
    interrupt_cfg.EvtInterruptEnable = visr_wdf_interrupt_enable;
    interrupt_cfg.EvtInterruptDisable = visr_wdf_interrupt_disable;

    status = WdfInterruptCreate(device, &interrupt_cfg, WDF_NO_OBJECT_ATTRIBUTES, &interrupt);
    if (!NT_SUCCESS(status)) {
        ERROR("Failed to initialize interrupts\n");
        return status;
    }

    DEBUG("Visr device initialized\n");
    return status;
}
