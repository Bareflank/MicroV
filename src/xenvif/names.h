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

#ifndef _XENVIF_NAMES_H_
#define _XENVIF_NAMES_H_

#include <ntddk.h>
#include <xen.h>

static FORCEINLINE const CHAR *
PowerTypeName(
    IN  POWER_STATE_TYPE    Type
    )
{
#define _POWER_TYPE_NAME(_Type) \
    case _Type:                 \
        return #_Type;

    switch (Type) {
    _POWER_TYPE_NAME(SystemPowerState);
    _POWER_TYPE_NAME(DevicePowerState);
    default:
        break;
    }

    return ("UNKNOWN");
#undef  _POWER_ACTION_NAME
}

static FORCEINLINE const CHAR *
PowerSystemStateName(
    IN  SYSTEM_POWER_STATE State
    )
{
#define _POWER_SYSTEM_STATE_NAME(_State)    \
    case PowerSystem ## _State:             \
        return #_State;

    switch (State) {
    _POWER_SYSTEM_STATE_NAME(Unspecified);
    _POWER_SYSTEM_STATE_NAME(Working);
    _POWER_SYSTEM_STATE_NAME(Sleeping1);
    _POWER_SYSTEM_STATE_NAME(Sleeping2);
    _POWER_SYSTEM_STATE_NAME(Sleeping3);
    _POWER_SYSTEM_STATE_NAME(Hibernate);
    _POWER_SYSTEM_STATE_NAME(Shutdown);
    _POWER_SYSTEM_STATE_NAME(Maximum);
    default:
        break;
    }

    return ("UNKNOWN");
#undef  _POWER_SYSTEM_STATE_NAME
}

static FORCEINLINE const CHAR *
PowerDeviceStateName(
    IN  DEVICE_POWER_STATE State
    )
{
#define _POWER_DEVICE_STATE_NAME(_State)    \
        case PowerDevice ## _State:         \
            return #_State;

    switch (State) {
    _POWER_DEVICE_STATE_NAME(Unspecified);
    _POWER_DEVICE_STATE_NAME(D0);
    _POWER_DEVICE_STATE_NAME(D1);
    _POWER_DEVICE_STATE_NAME(D2);
    _POWER_DEVICE_STATE_NAME(D3);
    _POWER_DEVICE_STATE_NAME(Maximum);
    default:
        break;
    }

    return ("UNKNOWN");
#undef  _POWER_DEVICE_STATE_NAME
}

static FORCEINLINE const CHAR *
PowerActionName(
    IN  POWER_ACTION    Type
    )
{
#define _POWER_ACTION_NAME(_Type)   \
    case PowerAction ## _Type:      \
        return #_Type;

    switch (Type) {
    _POWER_ACTION_NAME(None);
    _POWER_ACTION_NAME(Reserved);
    _POWER_ACTION_NAME(Sleep);
    _POWER_ACTION_NAME(Hibernate);
    _POWER_ACTION_NAME(Shutdown);
    _POWER_ACTION_NAME(ShutdownReset);
    _POWER_ACTION_NAME(ShutdownOff);
    _POWER_ACTION_NAME(WarmEject);
    default:
        break;
    }

    return ("UNKNOWN");
#undef  _POWER_ACTION_NAME
}

static FORCEINLINE const CHAR *
PowerMinorFunctionName(
    IN  ULONG   MinorFunction
    )
{
#define _POWER_MINOR_FUNCTION_NAME(_Function)   \
    case IRP_MN_ ## _Function:                  \
        return #_Function;

    switch (MinorFunction) {
    _POWER_MINOR_FUNCTION_NAME(WAIT_WAKE);
    _POWER_MINOR_FUNCTION_NAME(POWER_SEQUENCE);
    _POWER_MINOR_FUNCTION_NAME(SET_POWER);
    _POWER_MINOR_FUNCTION_NAME(QUERY_POWER);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _POWER_MINOR_FUNCTION_NAME
}

static FORCEINLINE const CHAR *
PnpMinorFunctionName(
    IN  ULONG   Function
    )
{
#define _PNP_MINOR_FUNCTION_NAME(_Function) \
    case IRP_MN_ ## _Function:              \
        return #_Function;

    switch (Function) {
    _PNP_MINOR_FUNCTION_NAME(START_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(QUERY_REMOVE_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(REMOVE_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(CANCEL_REMOVE_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(STOP_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(QUERY_STOP_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(CANCEL_STOP_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(QUERY_DEVICE_RELATIONS);
    _PNP_MINOR_FUNCTION_NAME(QUERY_INTERFACE);
    _PNP_MINOR_FUNCTION_NAME(QUERY_CAPABILITIES);
    _PNP_MINOR_FUNCTION_NAME(QUERY_RESOURCES);
    _PNP_MINOR_FUNCTION_NAME(QUERY_RESOURCE_REQUIREMENTS);
    _PNP_MINOR_FUNCTION_NAME(QUERY_DEVICE_TEXT);
    _PNP_MINOR_FUNCTION_NAME(FILTER_RESOURCE_REQUIREMENTS);
    _PNP_MINOR_FUNCTION_NAME(READ_CONFIG);
    _PNP_MINOR_FUNCTION_NAME(WRITE_CONFIG);
    _PNP_MINOR_FUNCTION_NAME(EJECT);
    _PNP_MINOR_FUNCTION_NAME(SET_LOCK);
    _PNP_MINOR_FUNCTION_NAME(QUERY_ID);
    _PNP_MINOR_FUNCTION_NAME(QUERY_PNP_DEVICE_STATE);
    _PNP_MINOR_FUNCTION_NAME(QUERY_BUS_INFORMATION);
    _PNP_MINOR_FUNCTION_NAME(DEVICE_USAGE_NOTIFICATION);
    _PNP_MINOR_FUNCTION_NAME(SURPRISE_REMOVAL);
    _PNP_MINOR_FUNCTION_NAME(QUERY_LEGACY_BUS_INFORMATION);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _PNP_MINOR_FUNCTION_NAME
}

static FORCEINLINE const CHAR *
PartialResourceDescriptorTypeName(
    IN  UCHAR   Type
    )
{
#define _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(_Type)   \
    case CmResourceType ## _Type:                       \
        return #_Type;

    switch (Type) {
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(Null);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(Port);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(Interrupt);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(Memory);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(Dma);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(DeviceSpecific);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(BusNumber);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(MemoryLarge);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(ConfigData);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(DevicePrivate);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME
}

static FORCEINLINE const CHAR *
DeviceUsageTypeName(
    IN  DEVICE_USAGE_NOTIFICATION_TYPE  Type
    )
{
#define _DEVICE_USAGE_TYPE_NAME(_Type)  \
    case DeviceUsageType ## _Type:      \
        return #_Type;

    switch (Type) {
    _DEVICE_USAGE_TYPE_NAME(Paging);
    _DEVICE_USAGE_TYPE_NAME(Hibernation);
    _DEVICE_USAGE_TYPE_NAME(DumpFile);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _DEVICE_USAGE_TYPE_NAME
}

static FORCEINLINE const CHAR *
InterfaceTypeName(
    IN  INTERFACE_TYPE  Type
    )
{
#define _INTERFACE_TYPE_NAME(_Type) \
    case _Type:                     \
        return #_Type;

    switch (Type) {
    _INTERFACE_TYPE_NAME(InterfaceTypeUndefined);
    _INTERFACE_TYPE_NAME(Internal);
    _INTERFACE_TYPE_NAME(Isa);
    _INTERFACE_TYPE_NAME(Eisa);
    _INTERFACE_TYPE_NAME(MicroChannel);
    _INTERFACE_TYPE_NAME(TurboChannel);
    _INTERFACE_TYPE_NAME(PCIBus);
    _INTERFACE_TYPE_NAME(VMEBus);
    _INTERFACE_TYPE_NAME(NuBus);
    _INTERFACE_TYPE_NAME(PCMCIABus);
    _INTERFACE_TYPE_NAME(CBus);
    _INTERFACE_TYPE_NAME(MPIBus);
    _INTERFACE_TYPE_NAME(MPSABus);
    _INTERFACE_TYPE_NAME(ProcessorInternal);
    _INTERFACE_TYPE_NAME(InternalPowerBus);
    _INTERFACE_TYPE_NAME(PNPISABus);
    _INTERFACE_TYPE_NAME(PNPBus);
    _INTERFACE_TYPE_NAME(Vmcs);
    _INTERFACE_TYPE_NAME(ACPIBus);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _INTERFACE_TYPE_NAME
}

static FORCEINLINE const CHAR *
DmaWidthName(
    IN  DMA_WIDTH   Width
    )
{
#define _DMA_WIDTH_NAME(_Width) \
    case Width ## _Width:       \
        return #_Width;

    switch (Width) {
    _DMA_WIDTH_NAME(8Bits);
    _DMA_WIDTH_NAME(16Bits);
    _DMA_WIDTH_NAME(32Bits);
    _DMA_WIDTH_NAME(64Bits);
    _DMA_WIDTH_NAME(NoWrap);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _DMA_WIDTH_NAME
}

static FORCEINLINE const CHAR *
DmaSpeedName(
    IN  DMA_SPEED   Speed
    )
{
#define _DMA_SPEED_NAME(_Speed) \
    case _Speed:                \
        return #_Speed;

    switch (Speed) {
    _DMA_SPEED_NAME(Compatible);
    _DMA_SPEED_NAME(TypeA);
    _DMA_SPEED_NAME(TypeB);
    _DMA_SPEED_NAME(TypeC);
    _DMA_SPEED_NAME(TypeF);
    _DMA_SPEED_NAME(MaximumDmaSpeed);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _DMA_SPEED_NAME
}

static FORCEINLINE const PCHAR
XenbusStateName(
    IN  XenbusState   State
    )
{
#define _STATE_NAME(_State)     \
    case  XenbusState ## _State:  \
        return #_State;

    switch (State) {
    _STATE_NAME(Unknown);
    _STATE_NAME(Initialising);
    _STATE_NAME(InitWait);
    _STATE_NAME(Initialised);
    _STATE_NAME(Connected);
    _STATE_NAME(Closing);
    _STATE_NAME(Closed);
    _STATE_NAME(Reconfiguring);
    _STATE_NAME(Reconfigured);
    default:
        break;
    }

    return "INVALID";

#undef  _STATE_NAME
}

#endif // _XENVIF_NAMES_H_
