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

#include <windows.h>
#include <winioctl.h>

#include "xenifacedevice.h"
#include "devicelist.h"
#include "xeniface_ioctls.h"

CXenIfaceDevice::CXenIfaceDevice(const wchar_t* path) : CDevice(path)
{}

/*virtual*/ CXenIfaceDevice::~CXenIfaceDevice()
{}

// store interface
bool CXenIfaceDevice::StoreRead(const std::string& path, std::string& value)
{
    DWORD   bytes(0);
    char*   buffer;
    bool    result;

    Ioctl(IOCTL_XENIFACE_STORE_READ,
          (void*)path.c_str(), (DWORD)path.length() + 1,
          NULL, 0,
          &bytes);

    buffer = new char[(size_t)bytes + 1];
    if (buffer == NULL)
        return false;

    result = Ioctl(IOCTL_XENIFACE_STORE_READ,
                   (void*)path.c_str(), (DWORD)path.length() + 1,
                   buffer, bytes);

    buffer[bytes] = 0;
    if (result)
        value = buffer;

    delete [] buffer;
    return result;
}

bool CXenIfaceDevice::StoreWrite(const std::string& path, const std::string& value)
{
    bool   result;
    size_t length = path.length() + 1 + value.length() + 1 + 1;
    char*  buffer = new char[length];
    if (buffer == NULL)
        return false;

    memcpy(buffer, path.c_str(), path.length());
    buffer[path.length()] = 0;

    memcpy(buffer + path.length() + 1, value.c_str(), value.length());
    buffer[path.length() + 1 + value.length()] = 0;
    buffer[length - 1] = 0;

    result = Ioctl(IOCTL_XENIFACE_STORE_WRITE, buffer, (DWORD)length, NULL, 0);
    delete [] buffer;
    return result;
}

bool CXenIfaceDevice::StoreRemove(const std::string& path)
{
    return Ioctl(IOCTL_XENIFACE_STORE_REMOVE,
                 (void*)path.c_str(), (DWORD)path.length() + 1,
                 NULL, 0);
}

bool CXenIfaceDevice::StoreAddWatch(const std::string& path, HANDLE evt, void** ctxt)
{
    XENIFACE_STORE_ADD_WATCH_IN  in  = { (PCHAR)path.c_str(), (DWORD)path.length() + 1, evt };
    XENIFACE_STORE_ADD_WATCH_OUT out = { NULL };
    if (!Ioctl(IOCTL_XENIFACE_STORE_ADD_WATCH,
               &in, (DWORD)sizeof(in),
               &out, (DWORD)sizeof(out)))
        return false;
    *ctxt = out.Context;
    return true;
}

bool CXenIfaceDevice::StoreRemoveWatch(void* ctxt)
{
    XENIFACE_STORE_REMOVE_WATCH_IN in = { ctxt };
    return Ioctl(IOCTL_XENIFACE_STORE_REMOVE_WATCH,
                 &in, (DWORD)sizeof(in),
                 NULL, 0);
}

// suspend interface
bool CXenIfaceDevice::SuspendRegister(HANDLE evt, void** ctxt)
{
    XENIFACE_SUSPEND_REGISTER_IN  in  = { evt };
    XENIFACE_SUSPEND_REGISTER_OUT out = { NULL };
    if (!Ioctl(IOCTL_XENIFACE_SUSPEND_REGISTER,
               &in, (DWORD)sizeof(in),
               &out, (DWORD)sizeof(out)))
        return false;
    *ctxt = out.Context;
    return true;
}

bool CXenIfaceDevice::SuspendDeregister(void* ctxt)
{
    XENIFACE_SUSPEND_REGISTER_OUT in = { ctxt };
    return Ioctl(IOCTL_XENIFACE_SUSPEND_DEREGISTER,
                 &in, (DWORD)sizeof(in),
                 NULL, 0);
}

bool CXenIfaceDevice::SuspendGetCount(DWORD *count)
{
    DWORD out;
    if (!Ioctl(IOCTL_XENIFACE_SUSPEND_GET_COUNT,
                NULL, 0,
                &out, (DWORD)sizeof(out)))
        return false;
    *count = out;
    return true;
}

// sharedinfo interface
bool CXenIfaceDevice::SharedInfoGetTime(FILETIME* time, bool* local)
{
    XENIFACE_SHAREDINFO_GET_TIME_OUT out = { NULL };
    if (!Ioctl(IOCTL_XENIFACE_SHAREDINFO_GET_TIME,
               NULL, 0,
               &out, sizeof(out)))
        return false;
    *time = out.Time;
    *local = out.Local;
    return true;
}

// logging
bool CXenIfaceDevice::Log(const std::string& msg)
{
    return Ioctl(IOCTL_XENIFACE_LOG,
                 (void*)msg.c_str(), (DWORD)msg.length() + 1,
                 NULL, 0);
}
