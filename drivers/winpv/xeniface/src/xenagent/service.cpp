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

#define INITGUID
#include <windows.h>
#include <stdio.h>
#include <powrprof.h>
#include <winuser.h>

#include <xeniface_ioctls.h>

#include "service.h"
#include "messages.h"

class CCritSec
{
public:
    CCritSec(LPCRITICAL_SECTION crit);
    ~CCritSec();
private:
    LPCRITICAL_SECTION m_crit;
};

CCritSec::CCritSec(LPCRITICAL_SECTION crit) : m_crit(crit)
{
    EnterCriticalSection(m_crit);
}
CCritSec::~CCritSec()
{
    LeaveCriticalSection(m_crit);
}

CXenIfaceCreator::CXenIfaceCreator(CXenAgent& agent) :
    m_devlist(GUID_INTERFACE_XENIFACE), m_device(NULL),
    m_ctxt_shutdown(NULL), m_ctxt_suspend(NULL),
    m_ctxt_slate_mode(NULL), m_agent(agent)
{
    m_evt_shutdown = CreateEvent(NULL, TRUE, FALSE, NULL);
    m_evt_suspend = CreateEvent(NULL, TRUE, FALSE, NULL);
    m_evt_slate_mode = CreateEvent(NULL, TRUE, FALSE, NULL);
    m_count = 0;

    InitializeCriticalSection(&m_crit);
}

CXenIfaceCreator::~CXenIfaceCreator()
{
    CloseHandle(m_evt_slate_mode);
    CloseHandle(m_evt_suspend);
    CloseHandle(m_evt_shutdown);

    DeleteCriticalSection(&m_crit);
}

bool CXenIfaceCreator::Start(HANDLE svc)
{
    return m_devlist.Start(svc, this);
}

void CXenIfaceCreator::Stop()
{
    // Check if registry key is present, implies Windows Update
    // require a reboot, which may spend time installing updates
    LogIfRebootPending();

    m_devlist.Stop();
}

void CXenIfaceCreator::OnDeviceEvent(DWORD evt, LPVOID data)
{
    m_devlist.OnDeviceEvent(evt, data);
}

void CXenIfaceCreator::OnPowerEvent(DWORD evt, LPVOID data)
{
    m_devlist.OnPowerEvent(evt, data);
}

void CXenIfaceCreator::Log(const char* message)
{
    // if possible, send to xeniface to forward to logs
    CCritSec crit(&m_crit);
    if (m_device) {
        m_device->Log(message);
    }
}

/*virtual*/ CDevice* CXenIfaceCreator::Create(const wchar_t* path)
{
    return new CXenIfaceDevice(path);
}

/*virtual*/ void CXenIfaceCreator::OnDeviceAdded(CDevice* dev)
{
    CXenAgent::Log("OnDeviceAdded(%ws)\n", dev->Path());

    CCritSec crit(&m_crit);
    if (m_device == NULL) {
        m_device = (CXenIfaceDevice*)dev;

        m_device->SuspendRegister(m_evt_suspend, &m_ctxt_suspend);

        StartShutdownWatch();

        if (m_agent.ConvDevicePresent())
            StartSlateModeWatch();

        SetXenTime();
    }
}

/*virtual*/ void CXenIfaceCreator::OnDeviceRemoved(CDevice* dev)
{
    CXenAgent::Log("OnDeviceRemoved(%ws)\n", dev->Path());

    CCritSec crit(&m_crit);
    if (m_device == dev) {
        if (m_ctxt_suspend) {
            m_device->SuspendDeregister(m_ctxt_suspend);
            m_ctxt_suspend = NULL;
        }

        if (m_agent.ConvDevicePresent())
            StopSlateModeWatch();

        StopShutdownWatch();

        m_device = NULL;
    }
}

/*virtual*/ void CXenIfaceCreator::OnDeviceSuspend(CDevice* dev)
{
    CXenAgent::Log("OnDeviceSuspend(%ws)\n", dev->Path());

    if (m_agent.ConvDevicePresent())
        StopSlateModeWatch();

    StopShutdownWatch();
}

/*virtual*/ void CXenIfaceCreator::OnDeviceResume(CDevice* dev)
{
    CXenAgent::Log("OnDeviceResume(%ws)\n", dev->Path());

    StartShutdownWatch();

    if (m_agent.ConvDevicePresent())
        StartSlateModeWatch();
}

bool CXenIfaceCreator::CheckShutdown()
{
    CCritSec crit(&m_crit);
    if (m_device == NULL)
        return false;

    std::string type;
    if (!m_device->StoreRead("control/shutdown", type))
        return false;

    if (type != "")
        CXenAgent::Log("Shutdown(%ws) = '%s'\n", m_device->Path(), type.c_str());

    if (type == "poweroff") {
        m_device->StoreWrite("control/shutdown", "");
        m_agent.EventLog(EVENT_XENUSER_POWEROFF);

        AcquireShutdownPrivilege();
#pragma warning(suppress:28159) /* Consider using a design alternative... Rearchitect to avoid Reboot */
        if (!InitiateSystemShutdownEx(NULL, NULL, 0, TRUE, FALSE,
                                      SHTDN_REASON_MAJOR_OTHER |
                                      SHTDN_REASON_MINOR_ENVIRONMENT |
                                      SHTDN_REASON_FLAG_PLANNED)) {
            CXenAgent::Log("InitiateSystemShutdownEx failed %08x\n", GetLastError());
        }
        return true;
    } else if (type == "reboot") {
        m_device->StoreWrite("control/shutdown", "");
        m_agent.EventLog(EVENT_XENUSER_REBOOT);

        AcquireShutdownPrivilege();
#pragma warning(suppress:28159) /* Consider using a design alternative... Rearchitect to avoid Reboot */
        if (!InitiateSystemShutdownEx(NULL, NULL, 0, TRUE, TRUE,
                                      SHTDN_REASON_MAJOR_OTHER |
                                      SHTDN_REASON_MINOR_ENVIRONMENT |
                                      SHTDN_REASON_FLAG_PLANNED)) {
            CXenAgent::Log("InitiateSystemShutdownEx failed %08x\n", GetLastError());
        }
        return true;
    } else if (type == "s4") {
        m_device->StoreWrite("control/shutdown", "");
        m_agent.EventLog(EVENT_XENUSER_S4);

        AcquireShutdownPrivilege();
        if (!SetSystemPowerState(FALSE, FALSE)) {
            CXenAgent::Log("SetSystemPowerState failed %08x\n", GetLastError());
        }
        return true;
    } else if (type == "s3") {
        m_device->StoreWrite("control/shutdown", "");
        m_agent.EventLog(EVENT_XENUSER_S3);

        AcquireShutdownPrivilege();
        if (!SetSuspendState(FALSE, TRUE, FALSE)) {
            CXenAgent::Log("SetSuspendState failed %08x\n", GetLastError());
        }
        return true;
    }

    return false;
}

void CXenIfaceCreator::CheckXenTime()
{
    CCritSec crit(&m_crit);
    if (m_device == NULL)
        return;

    SetXenTime();
}

void CXenIfaceCreator::CheckSuspend()
{
    CCritSec crit(&m_crit);
    if (m_device == NULL)
        return;

    DWORD count = 0;

    if (!m_device->SuspendGetCount(&count))
        return;

    if (m_count == count)
        return;

    CXenAgent::Log("Suspend(%ws)\n", m_device->Path());

    m_agent.EventLog(EVENT_XENUSER_UNSUSPENDED);

    // recreate watches, as suspending deactivated the watch
    if (m_agent.ConvDevicePresent())
        StopSlateModeWatch();

    StopShutdownWatch();

    StartShutdownWatch();

    if (m_agent.ConvDevicePresent())
        StartSlateModeWatch();

    m_count = count;
}

bool CXenIfaceCreator::CheckSlateMode(std::string *mode)
{
    CCritSec crit(&m_crit);
    if (m_device == NULL)
        return false;

    if (!m_device->StoreRead("control/laptop-slate-mode", *mode))
        return false;

    if (*mode != "")
        m_device->StoreWrite("control/laptop-slate-mode", "");

    return true;
}

void CXenIfaceCreator::LogIfRebootPending()
{
    HKEY Key;
    LONG lResult;

    lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                           "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired",
                           0,
                           KEY_READ,
                           &Key);
    if (lResult != ERROR_SUCCESS)
        return; // key doesnt exist, dont log anything

    RegCloseKey(Key);

    CXenAgent::Log("RebootRequired detected\n");
}

void CXenIfaceCreator::StartShutdownWatch()
{
    if (m_ctxt_shutdown)
        return;

    m_device->StoreAddWatch("control/shutdown", m_evt_shutdown, &m_ctxt_shutdown);

    m_device->StoreWrite("control/feature-poweroff", "1");
    m_device->StoreWrite("control/feature-reboot", "1");
    m_device->StoreWrite("control/feature-s3", "1");
    m_device->StoreWrite("control/feature-s4", "1");
}

void CXenIfaceCreator::StopShutdownWatch()
{
    if (!m_ctxt_shutdown)
        return;

    m_device->StoreRemove("control/feature-poweroff");
    m_device->StoreRemove("control/feature-reboot");
    m_device->StoreRemove("control/feature-s3");
    m_device->StoreRemove("control/feature-s4");

    m_device->StoreRemoveWatch(m_ctxt_shutdown);
    m_ctxt_shutdown = NULL;
}

void CXenIfaceCreator::StartSlateModeWatch()
{
    if (m_ctxt_slate_mode)
        return;

    m_device->StoreAddWatch("control/laptop-slate-mode", m_evt_slate_mode, &m_ctxt_slate_mode);
    m_device->StoreWrite("control/feature-laptop-slate-mode", "1");
}

void CXenIfaceCreator::StopSlateModeWatch()
{
    if (!m_ctxt_slate_mode)
        return;

    m_device->StoreRemove("control/feature-laptop-slate-mode");

    m_device->StoreRemoveWatch(m_ctxt_slate_mode);
    m_ctxt_slate_mode = NULL;
}

void CXenIfaceCreator::AcquireShutdownPrivilege()
{
    HANDLE          token;
    TOKEN_PRIVILEGES tp;

    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    tp.PrivilegeCount = 1;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &token))
        return;

    AdjustTokenPrivileges(token, FALSE, &tp, NULL, 0, NULL);
    CloseHandle(token);
}

void CXenIfaceCreator::SetXenTime()
{
    bool local;

    FILETIME now = { 0 };
    if (!m_device->SharedInfoGetTime(&now, &local))
        return;

    SYSTEMTIME cur = { 0 };
    if (local)
        GetLocalTime(&cur);
    else
        GetSystemTime(&cur);

    SYSTEMTIME sys = { 0 };
    if (!FileTimeToSystemTime(&now, &sys))
        return;

    if (memcmp(&cur, &sys, sizeof(SYSTEMTIME)) == 0)
        return;

    CXenAgent::Log("RTC is in %s\n", local ? "local time" : "UTC");
    CXenAgent::Log("Time Now = %d/%d/%d %d:%02d:%02d.%d\n",
                   cur.wYear, cur.wMonth, cur.wDay,
                   cur.wHour, cur.wMinute, cur.wSecond, cur.wMilliseconds);
    CXenAgent::Log("New Time = %d/%d/%d %d:%02d:%02d.%d\n",
                   sys.wYear, sys.wMonth, sys.wDay,
                   sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);

    if (local)
        SetLocalTime(&sys);
    else
        SetSystemTime(&sys);
}

/* 317fc439-3f77-41c8-b09e-08ad63272aa3 */
DEFINE_GUID(GUID_GPIOBUTTONS_LAPTOPSLATE_INTERFACE, \
            0x317fc439, 0x3f77, 0x41c8, 0xb0, 0x9e, 0x08, 0xad, 0x63, 0x27, 0x2a, 0xa3);

CConvCreator::CConvCreator(CXenAgent& agent) :
    m_devlist(GUID_GPIOBUTTONS_LAPTOPSLATE_INTERFACE), m_device(NULL),
    m_agent(agent)
{
    InitializeCriticalSection(&m_crit);
}

CConvCreator::~CConvCreator()
{
    DeleteCriticalSection(&m_crit);
}

bool CConvCreator::Start(HANDLE svc)
{
    return m_devlist.Start(svc, this);
}

void CConvCreator::Stop()
{
    m_devlist.Stop();
}

void CConvCreator::OnDeviceEvent(DWORD evt, LPVOID data)
{
    m_devlist.OnDeviceEvent(evt, data);
}

void CConvCreator::OnPowerEvent(DWORD evt, LPVOID data)
{
    m_devlist.OnPowerEvent(evt, data);
}

void CConvCreator::SetSlateMode(std::string mode)
{
    CCritSec crit(&m_crit);
    if (m_device == NULL)
        return;

    m_agent.EventLog(EVENT_XENUSER_MODE_SWITCH);

    if (mode == "laptop")
        m_device->SetMode(CCONV_DEVICE_LAPTOP_MODE);
    else if (mode == "slate")
        m_device->SetMode(CCONV_DEVICE_SLATE_MODE);
}

bool CConvCreator::DevicePresent()
{
    return m_device != NULL;
}

/*virtual*/ CDevice* CConvCreator::Create(const wchar_t* path)
{
    return new CConvDevice(path);
}

/*virtual*/ void CConvCreator::OnDeviceAdded(CDevice* dev)
{
    CXenAgent::Log("OnDeviceAdded(%ws)\n", dev->Path());

    CCritSec crit(&m_crit);
    if (m_device == NULL)
        m_device = (CConvDevice*)dev;
}

/*virtual*/ void CConvCreator::OnDeviceRemoved(CDevice* dev)
{
    CXenAgent::Log("OnDeviceRemoved(%ws)\n", dev->Path());

    CCritSec crit(&m_crit);
    if (m_device == dev)
        m_device = NULL;
}

/*virtual*/ void CConvCreator::OnDeviceSuspend(CDevice* dev)
{
    CXenAgent::Log("OnDeviceSuspend(%ws)\n", dev->Path());
}

/*virtual*/ void CConvCreator::OnDeviceResume(CDevice* dev)
{
    CXenAgent::Log("OnDeviceResume(%ws)\n", dev->Path());
}

static CXenAgent s_service;

/*static*/ void CXenAgent::Log(const char* fmt, ...)
{
    char message[XENIFACE_LOG_MAX_LENGTH];
    va_list args;

    va_start(args, fmt);
    vsnprintf_s(message, sizeof(message), sizeof(message)/sizeof(message[0]) - 1, fmt, args);
    va_end(args);

    OutputDebugString(message);

    s_service.m_xeniface.Log(message);
}

/*static*/ int CXenAgent::ServiceInstall()
{
    SC_HANDLE   svc, mgr;
    char        path[MAX_PATH+1];

    mgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (mgr == NULL)
        return -1;

    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) {
        CloseServiceHandle(mgr);
        return -1;
    }
    path[MAX_PATH] = 0;

    svc = CreateServiceA(mgr, SVC_NAME, SVC_DISPLAYNAME, SERVICE_ALL_ACCESS,
                        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL, path,
                        NULL, NULL, NULL, NULL, NULL);
    if (svc == NULL) {
        CloseServiceHandle(mgr);
        return -2;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(mgr);
    return 0;
}

/*static*/ int CXenAgent::ServiceUninstall()
{
    SC_HANDLE   svc, mgr;

    mgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (mgr == NULL)
        return -1;

    svc = OpenService(mgr, SVC_NAME, SERVICE_ALL_ACCESS);
    if (svc == NULL) {
        CloseServiceHandle(mgr);
        return -2;
    }

    // try to stop the service
    if (ControlService(svc, SERVICE_CONTROL_STOP, &s_service.m_status))
    {
        Sleep( 1000 );

        while (QueryServiceStatus(svc, &s_service.m_status))
        {
            if (s_service.m_status.dwCurrentState != SERVICE_STOP_PENDING)
                break;
            Sleep(1000);
        }
    }

    // now remove the service
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(mgr);
    return 0;
}

/*static*/ int CXenAgent::ServiceEntry()
{
    SERVICE_TABLE_ENTRY ServiceTable[2] =
    {
        { SVC_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        CXenAgent::Log("Failed to start dispatcher\n");
        return -1;
    }
    return 0;
}

/*static*/ void WINAPI CXenAgent::ServiceMain(int argc, char** argv)
{
    s_service.__ServiceMain(argc, argv);
}

/*static*/ DWORD WINAPI CXenAgent::ServiceControlHandlerEx(DWORD req, DWORD evt, LPVOID data, LPVOID ctxt)
{
    return s_service.__ServiceControlHandlerEx(req, evt, data, ctxt);
}

#pragma warning(push)
#pragma warning(disable:4355)

CXenAgent::CXenAgent() noexcept : m_handle(NULL), m_evtlog(NULL), m_xeniface(*this),
                         m_conv(*this)
{
    m_status.dwServiceType        = SERVICE_WIN32;
    m_status.dwCurrentState       = SERVICE_START_PENDING;
    m_status.dwControlsAccepted   = SERVICE_ACCEPT_STOP |
                                    SERVICE_ACCEPT_SHUTDOWN |
                                    SERVICE_ACCEPT_POWEREVENT;
    m_status.dwWin32ExitCode      = 0;
    m_status.dwServiceSpecificExitCode = 0;
    m_status.dwCheckPoint         = 0;
    m_status.dwWaitHint           = 0;

    m_svc_stop = CreateEvent(FALSE, NULL, NULL, FALSE);
}

#pragma warning(pop)

CXenAgent::~CXenAgent()
{
    CloseHandle(m_svc_stop);
}

void CXenAgent::OnServiceStart()
{
    CXenAgent::Log("OnServiceStart()\n");
    m_conv.Start(m_handle);
    m_xeniface.Start(m_handle);
}

void CXenAgent::OnServiceStop()
{
    CXenAgent::Log("OnServiceStop()\n");
    m_xeniface.Stop();
    m_conv.Stop();
}

void CXenAgent::OnDeviceEvent(DWORD evt, LPVOID data)
{
    m_conv.OnDeviceEvent(evt, data);
    m_xeniface.OnDeviceEvent(evt, data);
}

void CXenAgent::OnPowerEvent(DWORD evt, LPVOID data)
{
    m_conv.OnPowerEvent(evt, data);
    m_xeniface.OnPowerEvent(evt, data);
}

bool CXenAgent::ServiceMainLoop()
{
    DWORD   timeout = 30 * 60 * 1000;
    HANDLE  events[] = { m_svc_stop,
                         m_xeniface.m_evt_shutdown,
                         m_xeniface.m_evt_suspend,
                         m_xeniface.m_evt_slate_mode };
    DWORD   wait = WaitForMultipleObjectsEx(4, events, FALSE, timeout, TRUE);

    switch (wait) {
    case WAIT_OBJECT_0:
        ResetEvent(m_svc_stop);
        return false; // exit loop

    case WAIT_OBJECT_0+1:
        ResetEvent(m_xeniface.m_evt_shutdown);
        return !m_xeniface.CheckShutdown();

    case WAIT_OBJECT_0+2:
        ResetEvent(m_xeniface.m_evt_suspend);
        m_xeniface.CheckXenTime();
        m_xeniface.CheckSuspend();
        return true; // continue loop

    case WAIT_OBJECT_0+3: {
        std::string mode;

        ResetEvent(m_xeniface.m_evt_slate_mode);
        if (m_xeniface.CheckSlateMode(&mode))
            m_conv.SetSlateMode(mode);

        return true; // continue loop
    }
    case WAIT_TIMEOUT:
        m_xeniface.CheckXenTime();
        __fallthrough;
    case WAIT_IO_COMPLETION:
        m_xeniface.CheckSuspend();
        return !m_xeniface.CheckShutdown();

    default:
        CXenAgent::Log("WaitForMultipleObjects failed (%08x)\n", wait);
        EventLog(EVENT_XENUSER_UNEXPECTED);
        return true; // continue loop
    }
}

void CXenAgent::EventLog(DWORD evt)
{
    if (m_evtlog) {
        ReportEvent(m_evtlog,
                    EVENTLOG_SUCCESS,
                    0,
                    evt,
                    NULL,
                    0,
                    0,
                    NULL,
                    NULL);
    }
}

bool CXenAgent::ConvDevicePresent()
{
    return m_conv.DevicePresent();
}

void CXenAgent::SetServiceStatus(DWORD state, DWORD exit /*= 0*/, DWORD hint /*= 0*/)
{
    m_status.dwCurrentState = state;
    m_status.dwWin32ExitCode = exit;
    m_status.dwWaitHint = hint;
    ::SetServiceStatus(m_handle, &m_status);
}

void WINAPI CXenAgent::__ServiceMain(int argc, char** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    m_handle = RegisterServiceCtrlHandlerEx(SVC_NAME, ServiceControlHandlerEx, NULL);
    if (m_handle == NULL)
        return;

    m_evtlog = RegisterEventSource(NULL, SVC_NAME);
    SetServiceStatus(SERVICE_RUNNING);

    OnServiceStart();
    while (ServiceMainLoop()) ;
    OnServiceStop();

    if (m_evtlog)
        DeregisterEventSource(m_evtlog);
    m_evtlog = NULL;
    SetServiceStatus(SERVICE_STOPPED);
}

DWORD WINAPI CXenAgent::__ServiceControlHandlerEx(DWORD req, DWORD evt, LPVOID data, LPVOID ctxt)
{
    UNREFERENCED_PARAMETER(ctxt);

    switch (req)
    {
    case SERVICE_CONTROL_STOP:
        SetServiceStatus(SERVICE_STOP_PENDING);
        SetEvent(m_svc_stop);
        return NO_ERROR;

    case SERVICE_CONTROL_SHUTDOWN:
        SetServiceStatus(SERVICE_STOP_PENDING);
        SetEvent(m_svc_stop);
        return NO_ERROR;

    case SERVICE_CONTROL_DEVICEEVENT:
        SetServiceStatus(SERVICE_RUNNING);
        OnDeviceEvent(evt, data);
        return NO_ERROR;

    case SERVICE_CONTROL_POWEREVENT:
        SetServiceStatus(SERVICE_RUNNING);
        OnPowerEvent(evt, data);
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        SetServiceStatus(SERVICE_RUNNING);
        return NO_ERROR;

    default:
        break;
    }

    SetServiceStatus(SERVICE_RUNNING);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

int CALLBACK WinMain(
    _In_     HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevious,
    _In_     LPSTR     lpCmdLine,
    _In_     int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevious);
    UNREFERENCED_PARAMETER(nCmdShow);

    if (strlen(lpCmdLine) != 0) {
        if (!strcmp(lpCmdLine, "-i") || !strcmp(lpCmdLine, "\"-i\""))
            return CXenAgent::ServiceInstall();
        if (!strcmp(lpCmdLine, "-u") || !strcmp(lpCmdLine, "\"-u\""))
            return CXenAgent::ServiceUninstall();
    }
    return CXenAgent::ServiceEntry();
}
