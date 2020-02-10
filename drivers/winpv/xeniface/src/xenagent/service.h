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

#ifndef __XENAGENT_SERVICE_H__
#define __XENAGENT_SERVICE_H__

#include <version.h>

#define stringify_literal(_text) #_text
#define stringify(_text) stringify_literal(_text)
#define __MODULE__ stringify(PROJECT)

#define SVC_NAME        __MODULE__
#define SVC_DISPLAYNAME SVC_NAME

#include "devicelist.h"
#include "xenifacedevice.h"
#include "convdevice.h"

class CXenAgent;

class CXenIfaceCreator : public IDeviceCreator
{
public:
    CXenIfaceCreator(CXenAgent&);
    virtual ~CXenIfaceCreator();
    CXenIfaceCreator& operator=(const CXenIfaceCreator&);

    bool Start(HANDLE svc);
    void Stop();
    void OnDeviceEvent(DWORD evt, LPVOID data);
    void OnPowerEvent(DWORD evt, LPVOID data);
    void Log(const char *message);

public: // IDeviceCreator
    virtual CDevice* Create(const wchar_t* path);
    virtual void OnDeviceAdded(CDevice* dev);
    virtual void OnDeviceRemoved(CDevice* dev);
    virtual void OnDeviceSuspend(CDevice* dev);
    virtual void OnDeviceResume(CDevice* dev);

public:
    bool CheckShutdown();
    void CheckXenTime();
    void CheckSuspend();
    bool CheckSlateMode(std::string *mode);

public:
    HANDLE  m_evt_shutdown;
    HANDLE  m_evt_suspend;
    HANDLE  m_evt_slate_mode;

private:
    void LogIfRebootPending();
    void StartShutdownWatch();
    void StopShutdownWatch();
    void StartSlateModeWatch();
    void StopSlateModeWatch();
    void AcquireShutdownPrivilege();
    bool IsRTCInUTC();
    void SetXenTime();

private:
    CXenAgent&          m_agent;
    CDeviceList         m_devlist;
    CXenIfaceDevice*    m_device;
    CRITICAL_SECTION    m_crit;
    void*               m_ctxt_shutdown;
    void*               m_ctxt_suspend;
    void*               m_ctxt_slate_mode;
    DWORD               m_count;
};

class CConvCreator : public IDeviceCreator
{
public:
    CConvCreator(CXenAgent&);
    virtual ~CConvCreator();
    CConvCreator& operator=(const CConvCreator&);

    bool Start(HANDLE svc);
    void Stop();
    void OnDeviceEvent(DWORD evt, LPVOID data);
    void OnPowerEvent(DWORD evt, LPVOID data);
    void SetSlateMode(std::string mode);
    bool DevicePresent();

public:
    virtual CDevice* Create(const wchar_t* path);
    virtual void OnDeviceAdded(CDevice* dev);
    virtual void OnDeviceRemoved(CDevice* dev);
    virtual void OnDeviceSuspend(CDevice* dev);
    virtual void OnDeviceResume(CDevice* dev);

private:
    CXenAgent&          m_agent;
    CDeviceList         m_devlist;
    CConvDevice*        m_device;
    CRITICAL_SECTION    m_crit;
};

class CXenAgent
{
public: // statics
    static void Log(const char* fmt, ...);

    static int ServiceInstall();
    static int ServiceUninstall();
    static int ServiceEntry();

    static void WINAPI ServiceMain(int argc, char** argv);
    static DWORD WINAPI ServiceControlHandlerEx(DWORD, DWORD, LPVOID, LPVOID);

public: // ctor/dtor
    CXenAgent() noexcept;
    virtual ~CXenAgent();

public:
    void EventLog(DWORD evt);

public:
    bool ConvDevicePresent();

private: // service events
    void OnServiceStart();
    void OnServiceStop();
    void OnDeviceEvent(DWORD, LPVOID);
    void OnPowerEvent(DWORD, LPVOID);
    bool ServiceMainLoop();

private: // service support
    void SetServiceStatus(DWORD state, DWORD exit = 0, DWORD hint = 0);
    void WINAPI __ServiceMain(int argc, char** argv);
    DWORD WINAPI __ServiceControlHandlerEx(DWORD, DWORD, LPVOID, LPVOID);

    SERVICE_STATUS          m_status;
    SERVICE_STATUS_HANDLE   m_handle;
    HANDLE                  m_evtlog;
    HANDLE                  m_svc_stop;
    CXenIfaceCreator        m_xeniface;
    CConvCreator            m_conv;
};

#endif
