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

#include <ndis.h>
#include <version.h>

#include "driver.h"
#include "miniport.h"
#include "adapter.h"
#include "dbg_print.h"
#include "assert.h"

static
_Function_class_(SET_OPTIONS)
NDIS_STATUS
MiniportSetOptions(
    IN  NDIS_HANDLE NdisDriverHandle,
    IN  NDIS_HANDLE DriverContext
    )
{
    UNREFERENCED_PARAMETER(NdisDriverHandle);
    UNREFERENCED_PARAMETER(DriverContext);

    Trace("<===>\n");

    return NDIS_STATUS_SUCCESS;
}

static
_Function_class_(MINIPORT_INITIALIZE)
NDIS_STATUS
MiniportInitializeEx(
    IN  NDIS_HANDLE                     NdisMiniportHandle,
    IN  NDIS_HANDLE                     MiniportDriverContext,
    IN  PNDIS_MINIPORT_INIT_PARAMETERS  MiniportInitParameters
    )
{
    PXENNET_ADAPTER                     Adapter;
    NDIS_STATUS                         NdisStatus;

    UNREFERENCED_PARAMETER(MiniportDriverContext);
    UNREFERENCED_PARAMETER(MiniportInitParameters);

    NdisStatus = AdapterInitialize(NdisMiniportHandle, &Adapter);
    if (NdisStatus != NDIS_STATUS_SUCCESS)
        goto fail1;

    return NDIS_STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", NdisStatus);

    return NdisStatus;
}

static
_Function_class_(MINIPORT_HALT)
VOID
MiniportHaltEx(
    IN  NDIS_HANDLE         MiniportAdapterContext,
    IN  NDIS_HALT_ACTION    HaltAction
    )
{
    PXENNET_ADAPTER         Adapter = (PXENNET_ADAPTER)MiniportAdapterContext;

    UNREFERENCED_PARAMETER(HaltAction);

    if (Adapter == NULL)
        return;

    AdapterTeardown(Adapter);
}

static
_Function_class_(MINIPORT_UNLOAD)
VOID
MiniportDriverUnload(
    IN  PDRIVER_OBJECT  DriverObject
    )
{
    DriverUnload(DriverObject);
}

static
_Function_class_(MINIPORT_PAUSE)
NDIS_STATUS
MiniportPause(
    IN  NDIS_HANDLE                     MiniportAdapterContext,
    IN  PNDIS_MINIPORT_PAUSE_PARAMETERS MiniportPauseParameters
    )
{
    PXENNET_ADAPTER                     Adapter = (PXENNET_ADAPTER)MiniportAdapterContext;

    UNREFERENCED_PARAMETER(MiniportPauseParameters);

    AdapterDisable(Adapter);

    return NDIS_STATUS_SUCCESS;
}

static
_Function_class_(MINIPORT_RESTART)
NDIS_STATUS
MiniportRestart(
    IN  NDIS_HANDLE                         MiniportAdapterContext,
    IN  PNDIS_MINIPORT_RESTART_PARAMETERS   MiniportRestartParameters
    )
{
    PXENNET_ADAPTER                         Adapter = (PXENNET_ADAPTER)MiniportAdapterContext;
    NDIS_STATUS                             NdisStatus;

    UNREFERENCED_PARAMETER(MiniportRestartParameters);

    NdisStatus = AdapterEnable(Adapter);

    return NdisStatus;
}

static
_Function_class_(MINIPORT_OID_REQUEST)
NDIS_STATUS
MiniportOidRequest(
    IN  NDIS_HANDLE         MiniportAdapterContext,
    IN  PNDIS_OID_REQUEST   OidRequest
    )
{
    PXENNET_ADAPTER         Adapter = (PXENNET_ADAPTER)MiniportAdapterContext;
    NDIS_STATUS             NdisStatus;

    switch (OidRequest->RequestType) {
        case NdisRequestSetInformation:
            NdisStatus = AdapterSetInformation(Adapter, OidRequest);
            break;

        case NdisRequestQueryInformation:
        case NdisRequestQueryStatistics:
            NdisStatus = AdapterQueryInformation(Adapter, OidRequest);
            break;

        default:
            NdisStatus = NDIS_STATUS_NOT_SUPPORTED;
            break;
    };

    return NdisStatus;
}

static
_Function_class_(MINIPORT_SEND_NET_BUFFER_LISTS)
VOID
MiniportSendNetBufferLists(
    IN  NDIS_HANDLE         MiniportAdapterContext,
    IN  PNET_BUFFER_LIST    NetBufferList,
    IN  NDIS_PORT_NUMBER    PortNumber,
    IN  ULONG               SendFlags
    )
{
    PXENNET_ADAPTER         Adapter = (PXENNET_ADAPTER)MiniportAdapterContext;
    PXENNET_TRANSMITTER     Transmitter = AdapterGetTransmitter(Adapter);

    TransmitterSendNetBufferLists(Transmitter,
                                  NetBufferList,
                                  PortNumber,
                                  SendFlags);
}

static
_Function_class_(MINIPORT_RETURN_NET_BUFFER_LISTS)
VOID
MiniportReturnNetBufferLists(
    IN  NDIS_HANDLE         MiniportAdapterContext,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  ULONG               ReturnFlags
    )
{
    PXENNET_ADAPTER         Adapter = (PXENNET_ADAPTER)MiniportAdapterContext;
    PXENNET_RECEIVER        Receiver = AdapterGetReceiver(Adapter);

    ReceiverReturnNetBufferLists(Receiver,
                                 NetBufferLists,
                                 ReturnFlags);
}

static
_Function_class_(MINIPORT_CANCEL_SEND)
VOID
MiniportCancelSend(
    IN  NDIS_HANDLE MiniportAdapterContext,
    IN  PVOID       CancelId
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(CancelId);
}

static
_Function_class_(MINIPORT_CHECK_FOR_HANG)
BOOLEAN
MiniportCheckForHangEx(
    IN  NDIS_HANDLE MiniportAdapterContext
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);

    return FALSE;
}

static
_Function_class_(MINIPORT_RESET)
NDIS_STATUS
MiniportResetEx(
    IN  NDIS_HANDLE MiniportAdapterContext,
    OUT PBOOLEAN    AddressingReset
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);

    Trace("<===>\n");

    *AddressingReset = FALSE;

    return NDIS_STATUS_SUCCESS;
}

static
_Function_class_(MINIPORT_DEVICE_PNP_EVENT_NOTIFY)
VOID
MiniportDevicePnPEventNotify(
    IN  NDIS_HANDLE             MiniportAdapterContext,
    IN  PNET_DEVICE_PNP_EVENT   NetDevicePnPEvent
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(NetDevicePnPEvent);

    Trace("<===>\n");
}

static
_Function_class_(MINIPORT_SHUTDOWN)
VOID
MiniportShutdownEx(
    IN  NDIS_HANDLE             MiniportAdapterContext,
    IN  NDIS_SHUTDOWN_ACTION    ShutdownAction
    )
{
    PXENNET_ADAPTER             Adapter = (PXENNET_ADAPTER)MiniportAdapterContext;

    if (ShutdownAction == NdisShutdownBugCheck)
        return;

    Trace("====>\n");

    AdapterDisable(Adapter);

    Trace("<====\n");
}

static
_Function_class_(MINIPORT_CANCEL_OID_REQUEST)
VOID
MiniportCancelOidRequest(
    IN  NDIS_HANDLE MiniportAdapterContext,
    IN  PVOID       RequestId
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(RequestId);

    Trace("<===>\n");
}

static
_Function_class_(MINIPORT_DIRECT_OID_REQUEST)
NDIS_STATUS
MiniportDirectOidRequest(
    IN  NDIS_HANDLE         MiniportAdapterContext,
    IN  PNDIS_OID_REQUEST   OidRequest
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(OidRequest);

    return NDIS_STATUS_INVALID_OID;
}

static
_Function_class_(MINIPORT_CANCEL_DIRECT_OID_REQUEST)
VOID
MiniportCancelDirectOidRequest(
    IN  NDIS_HANDLE MiniportAdapterContext,
    IN  PVOID       RequestId
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(RequestId);
}

NDIS_STATUS
MiniportRegister(
    IN  PDRIVER_OBJECT                      DriverObject,
    IN  PUNICODE_STRING                     RegistryPath,
    OUT PNDIS_HANDLE                        NdisMiniportDriverHandle
    )
{
    NDIS_STATUS                             NdisStatus;
    NDIS_MINIPORT_DRIVER_CHARACTERISTICS    MiniportDriverCharacteristics;

    Trace("====>\n");

    NdisZeroMemory(&MiniportDriverCharacteristics, sizeof (MiniportDriverCharacteristics));

    MiniportDriverCharacteristics.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS,
    MiniportDriverCharacteristics.Header.Size = NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
    MiniportDriverCharacteristics.Header.Revision = NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;

    MiniportDriverCharacteristics.MajorNdisVersion = NDIS_MINIPORT_MAJOR_VERSION;
    MiniportDriverCharacteristics.MinorNdisVersion = NDIS_MINIPORT_MINOR_VERSION;
    MiniportDriverCharacteristics.MajorDriverVersion = MAJOR_VERSION;
    MiniportDriverCharacteristics.MinorDriverVersion = MINOR_VERSION;
    MiniportDriverCharacteristics.Flags = NDIS_WDM_DRIVER;

    MiniportDriverCharacteristics.CancelOidRequestHandler = MiniportCancelOidRequest;
    MiniportDriverCharacteristics.CancelSendHandler = MiniportCancelSend;
    MiniportDriverCharacteristics.CheckForHangHandlerEx = MiniportCheckForHangEx;
    MiniportDriverCharacteristics.InitializeHandlerEx = MiniportInitializeEx;
    MiniportDriverCharacteristics.HaltHandlerEx = MiniportHaltEx;
    MiniportDriverCharacteristics.OidRequestHandler = MiniportOidRequest;
    MiniportDriverCharacteristics.PauseHandler = MiniportPause;
    MiniportDriverCharacteristics.DevicePnPEventNotifyHandler  = MiniportDevicePnPEventNotify;
    MiniportDriverCharacteristics.ResetHandlerEx = MiniportResetEx;
    MiniportDriverCharacteristics.RestartHandler = MiniportRestart;
    MiniportDriverCharacteristics.ReturnNetBufferListsHandler = MiniportReturnNetBufferLists;
    MiniportDriverCharacteristics.SendNetBufferListsHandler = MiniportSendNetBufferLists;
    MiniportDriverCharacteristics.ShutdownHandlerEx = MiniportShutdownEx;
    MiniportDriverCharacteristics.UnloadHandler = MiniportDriverUnload;
    MiniportDriverCharacteristics.DirectOidRequestHandler = MiniportDirectOidRequest;
    MiniportDriverCharacteristics.CancelDirectOidRequestHandler = MiniportCancelDirectOidRequest;

    NdisStatus = NdisMRegisterMiniportDriver(DriverObject,
                                             RegistryPath,
                                             NULL,
                                             &MiniportDriverCharacteristics,
                                             NdisMiniportDriverHandle);
    if (NdisStatus != NDIS_STATUS_SUCCESS)
        goto fail1;

    Trace("<====\n");

    return NDIS_STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", NdisStatus);

    return NdisStatus;
}
