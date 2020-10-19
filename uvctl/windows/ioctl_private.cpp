//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-vararg
//
// Reason:
//    The Linux APIs require the use of var-args, so this test has to be
//    disabled.
//

#include <ioctl_private.h>
#include <log.h>

#include <bfgsl.h>
#include <bfdriverinterface.h>

#include <Processthreadsapi.h>
#include <SetupAPI.h>

// -----------------------------------------------------------------------------
// Unit Test Seems
// -----------------------------------------------------------------------------

HANDLE
uvctl_ioctl_open(const GUID *guid)
{
    HANDLE hDevInfo;
    SP_INTERFACE_DEVICE_DETAIL_DATA *deviceDetailData = nullptr;

    SP_DEVINFO_DATA devInfo;
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);

    SP_INTERFACE_DEVICE_DATA ifInfo;
    ifInfo.cbSize = sizeof(SP_INTERFACE_DEVICE_DATA);

    hDevInfo = SetupDiGetClassDevs(guid,
                                   0,
                                   0,
                                   DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);

    if (hDevInfo == INVALID_HANDLE_VALUE) {
        log_msg("[ALERT]: SetupDiGetClassDevs failed\n");
        return hDevInfo;
    }

    if (!SetupDiEnumDeviceInfo(hDevInfo, 0, &devInfo)) {
        log_msg("[ALERT]: SetupDiEnumDeviceInfo failed\n");
        return INVALID_HANDLE_VALUE;
    }

    if (!SetupDiEnumDeviceInterfaces(hDevInfo,
                                    &devInfo,
                                    guid,
                                    0,
                                    &ifInfo)) {
        log_msg("[ALERT]: SetupDiEnumDeviceInterfaces failed\n");
        return INVALID_HANDLE_VALUE;
    }

    DWORD requiredSize = 0;

    if (SetupDiGetDeviceInterfaceDetail(hDevInfo,
                                        &ifInfo,
                                        NULL,
                                        0,
                                        &requiredSize,
                                        NULL)) {
        log_msg("[ALERT]: SetupDiGetDeviceInterfaceDetail failed (1)\n");
        return INVALID_HANDLE_VALUE;
    }

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        log_msg("[ALERT]: SetupDiGetDeviceInterfaceDetail failed (2)\n");
        return INVALID_HANDLE_VALUE;
    }

    deviceDetailData =
        static_cast<SP_INTERFACE_DEVICE_DETAIL_DATA *>(malloc(requiredSize));

    if (!deviceDetailData) {
        return INVALID_HANDLE_VALUE;
    }

    auto ___ = gsl::finally([&]
    { free(deviceDetailData); });

    deviceDetailData->cbSize = sizeof(SP_INTERFACE_DEVICE_DETAIL_DATA);

    if (!SetupDiGetDeviceInterfaceDetail(hDevInfo,
                                         &ifInfo,
                                         deviceDetailData,
                                         requiredSize,
                                         NULL,
                                         NULL)) {
        log_msg("[ALERT]: SetupDiGetDeviceInterfaceDetail failed (3)\n");
        return INVALID_HANDLE_VALUE;
    }

    log_msg("[DEBUG]: Creating file: %s\n", deviceDetailData->DevicePath);

    return CreateFile(deviceDetailData->DevicePath,
                      GENERIC_READ | GENERIC_WRITE,
                      0,
                      NULL,
                      OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL,
                      NULL);
}

int64_t
uvctl_rw_ioctl(HANDLE fd, DWORD request, void *data, DWORD size)
{
    DWORD bytes = 0;

    if (!DeviceIoControl(fd, request, data, size, data, size, &bytes, NULL)) {
        return BF_IOCTL_FAILURE;
    }

    return 0;
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

ioctl_private::ioctl_private()
{
    log_msg("[DEBUG]: uvctl process id: %u\n", GetCurrentProcessId());

    builder_fd = uvctl_ioctl_open(&GUID_DEVINTERFACE_builder);

    if (builder_fd == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Failed to open builder driver. Is it loaded?");
    }

    xenbus_fd = uvctl_ioctl_open(&GUID_DEVINTERFACE_XENBUS);
    uint64_t rc = GetLastError();

    if (xenbus_fd == INVALID_HANDLE_VALUE) {
        log_msg("[ALERT]: Failed to open xenbus driver. Is it loaded? err=0x%x\n", rc);
    }
}

ioctl_private::~ioctl_private()
{
    if (builder_fd != INVALID_HANDLE_VALUE) {
        CloseHandle(builder_fd);
    }

    if (xenbus_fd != INVALID_HANDLE_VALUE) {
        CloseHandle(xenbus_fd);
    }
}

void ioctl_private::call_ioctl_create_vm(create_vm_args &args)
{
    auto fd = builder_fd;
    auto rc = uvctl_rw_ioctl(fd, IOCTL_CREATE_VM, &args, sizeof(create_vm_args));

    if (rc < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_CREATE_VM");
    }
}

void ioctl_private::call_ioctl_destroy(domainid_t domid) noexcept
{
    auto fd = builder_fd;
    auto rc = uvctl_rw_ioctl(fd, IOCTL_DESTROY_VM, &domid, sizeof(domid));

    if (rc < 0) {
        log_msg("[ERROR] ioctl failed: IOCTL_DESTROY_VM\n");
    }
}

void ioctl_private::call_ioctl_xenbus_acquire() noexcept
{
    if (xenbus_fd == INVALID_HANDLE_VALUE) {
        return;
    }

    auto id = GetCurrentProcessId();
    auto fd = xenbus_fd;
    auto rc = uvctl_rw_ioctl(fd, IOCTL_XENBUS_ACQUIRE, &id, sizeof(id));

    if (rc < 0) {
        log_msg("[ERROR] ioctl failed: IOCTL_XENBUS_ACQUIRE\n");
    }
}
