//
// Copyright (C) 2018 Assured Information Security, Inc.
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

#include <bfgsl.h>
#include <bfdriverinterface.h>

#include <SetupAPI.h>

// -----------------------------------------------------------------------------
// Unit Test Seems
// -----------------------------------------------------------------------------

HANDLE
bfm_ioctl_open()
{
    HANDLE hDevInfo;
    SP_INTERFACE_DEVICE_DETAIL_DATA *deviceDetailData = nullptr;

    SP_DEVINFO_DATA devInfo;
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);

    SP_INTERFACE_DEVICE_DATA ifInfo;
    ifInfo.cbSize = sizeof(SP_INTERFACE_DEVICE_DATA);

    hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_builder, 0, 0, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        return hDevInfo;
    }

    if (SetupDiEnumDeviceInfo(hDevInfo, 0, &devInfo) == false) {
        return INVALID_HANDLE_VALUE;
    }

    if (SetupDiEnumDeviceInterfaces(hDevInfo, &devInfo, &(GUID_DEVINTERFACE_builder), 0, &ifInfo) == false) {
        return INVALID_HANDLE_VALUE;
    }

    DWORD requiredSize = 0;

    if (SetupDiGetDeviceInterfaceDetail(hDevInfo, &ifInfo, NULL, 0, &requiredSize, NULL) == TRUE) {
        return INVALID_HANDLE_VALUE;
    }

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return INVALID_HANDLE_VALUE;
    }

    deviceDetailData = static_cast<SP_INTERFACE_DEVICE_DETAIL_DATA *>(malloc(requiredSize));

    if (deviceDetailData == nullptr) {
        return INVALID_HANDLE_VALUE;
    }

    auto ___ = gsl::finally([&]
    { free(deviceDetailData); });

    deviceDetailData->cbSize = sizeof(SP_INTERFACE_DEVICE_DETAIL_DATA);

    if (SetupDiGetDeviceInterfaceDetail(hDevInfo, &ifInfo, deviceDetailData, requiredSize, NULL, NULL) == false) {
        return INVALID_HANDLE_VALUE;
    }

    return CreateFile(deviceDetailData->DevicePath,
                      GENERIC_READ | GENERIC_WRITE,
                      0,
                      NULL,
                      CREATE_ALWAYS,
                      FILE_ATTRIBUTE_NORMAL,
                      NULL);
}

int64_t
bfm_read_write_ioctl(HANDLE fd, DWORD request, void *data, DWORD size)
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
    if ((fd = bfm_ioctl_open()) == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("failed to open to builder");
    }
}

ioctl_private::~ioctl_private()
{ CloseHandle(fd); }

void
ioctl_private::call_ioctl_create_vm_from_bzimage(create_vm_from_bzimage_args &args)
{
    if (bfm_read_write_ioctl(fd, IOCTL_CREATE_VM_FROM_BZIMAGE_CMD, &args, sizeof(create_vm_from_bzimage_args)) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_CREATE_VM_FROM_BZIMAGE_CMD");
    }
}

void
ioctl_private::call_ioctl_destroy(domainid_t domainid) noexcept
{
    if (bfm_read_write_ioctl(fd, IOCTL_DESTROY_CMD, &domainid, sizeof(domainid_t)) < 0) {
        std::cerr << "[ERROR] ioctl failed: IOCTL_DESTROY_CMD\n";
    }
}
