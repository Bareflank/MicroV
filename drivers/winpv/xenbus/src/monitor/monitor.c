/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source 1and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above
 *     copyright notice, this list of conditions and the23
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
#include <tchar.h>
#include <stdlib.h>
#include <strsafe.h>
#include <wtsapi32.h>
#include <cfgmgr32.h>
#include <malloc.h>
#include <assert.h>

#include <version.h>

#include "messages.h"

#define stringify_literal(_text) #_text
#define stringify(_text) stringify_literal(_text)
#define __MODULE__ stringify(PROJECT)

#define MONITOR_NAME        __MODULE__
#define MONITOR_DISPLAYNAME MONITOR_NAME

typedef struct _MONITOR_CONTEXT {
    SERVICE_STATUS          Status;
    SERVICE_STATUS_HANDLE   Service;
    HKEY                    ParametersKey;
    HANDLE                  EventLog;
    HANDLE                  StopEvent;
    HANDLE                  RequestEvent;
    HKEY                    RequestKey;
    PTCHAR                  Title;
    PTCHAR                  Text;
    BOOL                    RebootPending;
} MONITOR_CONTEXT, *PMONITOR_CONTEXT;

MONITOR_CONTEXT MonitorContext;

#define MAXIMUM_BUFFER_SIZE 1024

#define SERVICES_KEY "SYSTEM\\CurrentControlSet\\Services"

#define SERVICE_KEY(_Service) \
        SERVICES_KEY ## "\\" ## _Service

#define PARAMETERS_KEY(_Service) \
        SERVICE_KEY(_Service) ## "\\Parameters"

static VOID
#pragma prefast(suppress:6262) // Function uses '1036' bytes of stack: exceeds /analyze:stacksize'1024'
__Log(
    IN  const CHAR      *Format,
    IN  ...
    )
{
#if DBG
    PMONITOR_CONTEXT    Context = &MonitorContext;
    const TCHAR         *Strings[1];
#endif
    TCHAR               Buffer[MAXIMUM_BUFFER_SIZE];
    va_list             Arguments;
    size_t              Length;
    HRESULT             Result;

    va_start(Arguments, Format);
    Result = StringCchVPrintf(Buffer, MAXIMUM_BUFFER_SIZE, Format, Arguments);
    va_end(Arguments);

    if (Result != S_OK && Result != STRSAFE_E_INSUFFICIENT_BUFFER)
        return;

    Result = StringCchLength(Buffer, MAXIMUM_BUFFER_SIZE, &Length);
    if (Result != S_OK)
        return;

    Length = __min(MAXIMUM_BUFFER_SIZE - 1, Length + 2);

    __analysis_assume(Length < MAXIMUM_BUFFER_SIZE);
    __analysis_assume(Length >= 2);
    Buffer[Length] = '\0';
    Buffer[Length - 1] = '\n';
    Buffer[Length - 2] = '\r';

    OutputDebugString(Buffer);

#if DBG
    Strings[0] = Buffer;

    if (Context->EventLog != NULL)
        ReportEvent(Context->EventLog,
                    EVENTLOG_INFORMATION_TYPE,
                    0,
                    MONITOR_LOG,
                    NULL,
                    ARRAYSIZE(Strings),
                    0,
                    Strings,
                    NULL);
#endif
}

#define Log(_Format, ...) \
        __Log(__MODULE__ "|" __FUNCTION__ ": " _Format, __VA_ARGS__)

static PTCHAR
GetErrorMessage(
    IN  HRESULT Error
    )
{
    PTCHAR      Message;
    ULONG       Index;

    if (!FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                       FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL,
                       Error,
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       (LPTSTR)&Message,
                       0,
                       NULL))
        return NULL;

    for (Index = 0; Message[Index] != '\0'; Index++) {
        if (Message[Index] == '\r' || Message[Index] == '\n') {
            Message[Index] = '\0';
            break;
        }
    }

    return Message;
}

static const CHAR *
ServiceStateName(
    IN  DWORD   State
    )
{
#define _STATE_NAME(_State) \
    case SERVICE_ ## _State: \
        return #_State

    switch (State) {
    _STATE_NAME(START_PENDING);
    _STATE_NAME(RUNNING);
    _STATE_NAME(STOP_PENDING);
    _STATE_NAME(STOPPED);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _STATE_NAME
}

static VOID
ReportStatus(
    IN  DWORD           CurrentState,
    IN  DWORD           Win32ExitCode,
    IN  DWORD           WaitHint)
{
    PMONITOR_CONTEXT    Context = &MonitorContext;
    static DWORD        CheckPoint = 1;
    BOOL                Success;
    HRESULT             Error;

    Log("====> (%s)", ServiceStateName(CurrentState));

    Context->Status.dwCurrentState = CurrentState;
    Context->Status.dwWin32ExitCode = Win32ExitCode;
    Context->Status.dwWaitHint = WaitHint;

    if (CurrentState == SERVICE_START_PENDING)
        Context->Status.dwControlsAccepted = 0;
    else
        Context->Status.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                             SERVICE_ACCEPT_SHUTDOWN |
                                             SERVICE_ACCEPT_SESSIONCHANGE;

    if (CurrentState == SERVICE_RUNNING ||
        CurrentState == SERVICE_STOPPED )
        Context->Status.dwCheckPoint = 0;
    else
        Context->Status.dwCheckPoint = CheckPoint++;

    Success = SetServiceStatus(Context->Service, &Context->Status);

    if (!Success)
        goto fail1;

    Log("<====");

    return;

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }
}

DWORD WINAPI
MonitorCtrlHandlerEx(
    IN  DWORD           Ctrl,
    IN  DWORD           EventType,
    IN  LPVOID          EventData,
    IN  LPVOID          Argument
    )
{
    PMONITOR_CONTEXT    Context = &MonitorContext;

    UNREFERENCED_PARAMETER(EventType);
    UNREFERENCED_PARAMETER(EventData);
    UNREFERENCED_PARAMETER(Argument);

    switch (Ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
        SetEvent(Context->StopEvent);
        return NO_ERROR;

    case SERVICE_CONTROL_SESSIONCHANGE:
        SetEvent(Context->RequestEvent);
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        ReportStatus(SERVICE_RUNNING, NO_ERROR, 0);
        return NO_ERROR;

    default:
        break;
    }

    ReportStatus(SERVICE_RUNNING, NO_ERROR, 0);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static const CHAR *
WTSStateName(
    IN  DWORD   State
    )
{
#define _STATE_NAME(_State) \
    case WTS ## _State: \
        return #_State

    switch (State) {
    _STATE_NAME(Active);
    _STATE_NAME(Connected);
    _STATE_NAME(ConnectQuery);
    _STATE_NAME(Shadow);
    _STATE_NAME(Disconnected);
    _STATE_NAME(Idle);
    _STATE_NAME(Listen);
    _STATE_NAME(Reset);
    _STATE_NAME(Down);
    _STATE_NAME(Init);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _STATE_NAME
}

static VOID
DoReboot(
    VOID
    )
{
    Log("waiting for pending install events...");

    (VOID) CM_WaitNoPendingInstallEvents(INFINITE);

    Log("initiating shutdown...");

#pragma prefast(suppress:28159)
    (VOID) InitiateSystemShutdownEx(NULL,
                                    NULL,
                                    0,
                                    TRUE,
                                    TRUE,
                                    SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
                                    SHTDN_REASON_MINOR_INSTALLATION |
                                    SHTDN_REASON_FLAG_PLANNED);
}

static DWORD
GetPromptTimeout(
    VOID
    )
{
    PMONITOR_CONTEXT    Context = &MonitorContext;
    DWORD               Type;
    DWORD               Value;
    DWORD               ValueLength;
    HRESULT             Error;

    ValueLength = sizeof (Value);

    Error = RegQueryValueEx(Context->ParametersKey,
                            "PromptTimeout",
                            NULL,
                            &Type,
                            (LPBYTE)&Value,
                            &ValueLength);
    if (Error != ERROR_SUCCESS ||
        Type != REG_DWORD)
        Value = 0;

    Log("%u", Value);

    return Value;
}

static VOID
PromptForReboot(
    IN PTCHAR           DriverName
    )
{
    PMONITOR_CONTEXT    Context = &MonitorContext;
    PTCHAR              Title;
    DWORD               TitleLength;
    HRESULT             Result;
    TCHAR               ServiceKeyName[MAX_PATH];
    HKEY                ServiceKey;
    DWORD               MaxValueLength;
    DWORD               DisplayNameLength;
    PTCHAR              DisplayName;
    DWORD               Type;
    PTCHAR              Description;
    PTCHAR              Text;
    DWORD               TextLength;
    PWTS_SESSION_INFO   SessionInfo;
    DWORD               Count;
    DWORD               Index;
    BOOL                Success;
    HRESULT             Error;

    Log("====> (%s)", DriverName);

    Title = Context->Title;
    TitleLength = (DWORD)((_tcslen(Context->Title) +
                           1) * sizeof (TCHAR));

    Result = StringCbPrintf(ServiceKeyName,
                            MAX_PATH,
                            SERVICES_KEY "\\%s",
                            DriverName);
    assert(SUCCEEDED(Result));

    Error = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                         ServiceKeyName,
                         0,
                         KEY_READ,
                         &ServiceKey);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail1;
    }

    Error = RegQueryInfoKey(ServiceKey,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            &MaxValueLength,
                            NULL,
                            NULL);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail2;
    }

    DisplayNameLength = MaxValueLength + sizeof (TCHAR);

    DisplayName = calloc(1, DisplayNameLength);
    if (DisplayName == NULL)
        goto fail3;

    Error = RegQueryValueEx(ServiceKey,
                            "DisplayName",
                            NULL,
                            &Type,
                            (LPBYTE)DisplayName,
                            &DisplayNameLength);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail4;
    }

    if (Type != REG_SZ) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail5;
    }

    Description = _tcsrchr(DisplayName, ';');
    if (Description == NULL)
        Description = DisplayName;
    else
        Description++;

    TextLength = (DWORD)((_tcslen(Description) +
                          1 + // ' '
                          _tcslen(Context->Text) +
                          1) * sizeof (TCHAR));

    Text = calloc(1, TextLength);
    if (Text == NULL)
        goto fail6;

    Result = StringCbPrintf(Text,
                            TextLength,
                            TEXT("%s %s"),
                            Description,
                            Context->Text);
    assert(SUCCEEDED(Result));

    Success = WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE,
                                   0,
                                   1,
                                   &SessionInfo,
                                   &Count);
    if (!Success)
        goto fail7;

    for (Index = 0; Index < Count; Index++) {
        DWORD                   SessionId = SessionInfo[Index].SessionId;
        PTCHAR                  Name = SessionInfo[Index].pWinStationName;
        WTS_CONNECTSTATE_CLASS  State = SessionInfo[Index].State;
        DWORD                   Timeout;
        DWORD                   Response;

        Log("[%u]: %s [%s]",
            SessionId,
            Name,
            WTSStateName(State));

        if (State != WTSActive)
            continue;

        Timeout = GetPromptTimeout();

        Success = WTSSendMessage(WTS_CURRENT_SERVER_HANDLE,
                                 SessionId,
                                 Title,
                                 TitleLength,
                                 Text,
                                 TextLength,
                                 MB_YESNO | MB_ICONEXCLAMATION,
                                 Timeout,
                                 &Response,
                                 TRUE);

        if (!Success)
            goto fail8;

        Context->RebootPending = TRUE;

        if (Response == IDYES || Response == IDTIMEOUT)
            DoReboot();

        break;
    }

    WTSFreeMemory(SessionInfo);

    free(DisplayName);

    RegCloseKey(ServiceKey);

    Log("<====");

    return;

fail8:
    Log("fail8");

    WTSFreeMemory(SessionInfo);

fail7:
    Log("fail7");

fail6:
    Log("fail6");

fail5:
    Log("fail5");

fail4:
    Log("fail4");

    free(DisplayName);

fail3:
    Log("fail3");

fail2:
    Log("fail2");

    RegCloseKey(ServiceKey);

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }
}

static VOID
CheckRequestSubKeys(
    VOID
    )
{
    PMONITOR_CONTEXT    Context = &MonitorContext;
    DWORD               SubKeys;
    DWORD               MaxSubKeyLength;
    DWORD               SubKeyLength;
    PTCHAR              SubKeyName;
    DWORD               Index;
    HKEY                SubKey;
    HRESULT             Error;

    Log("====>");

    Error = RegQueryInfoKey(Context->RequestKey,
                            NULL,
                            NULL,
                            NULL,
                            &SubKeys,
                            &MaxSubKeyLength,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail1;
    }

    SubKeyLength = MaxSubKeyLength + sizeof (TCHAR);

    SubKeyName = calloc(1, SubKeyLength);
    if (SubKeyName == NULL)
        goto fail2;

    for (Index = 0; Index < SubKeys; Index++) {
        DWORD   Length;
        DWORD   Type;
        DWORD   Reboot;

        SubKeyLength = MaxSubKeyLength + sizeof (TCHAR);
        memset(SubKeyName, 0, SubKeyLength);

        Error = RegEnumKeyEx(Context->RequestKey,
                             Index,
                             (LPTSTR)SubKeyName,
                             &SubKeyLength,
                             NULL,
                             NULL,
                             NULL,
                             NULL);
        if (Error != ERROR_SUCCESS) {
            SetLastError(Error);
            goto fail3;
        }

        Log("%s", SubKeyName);

        Error = RegOpenKeyEx(Context->RequestKey,
                             SubKeyName,
                             0,
                             KEY_READ,
                             &SubKey);
        if (Error != ERROR_SUCCESS)
            continue;

        Length = sizeof (DWORD);
        Error = RegQueryValueEx(SubKey,
                                "Reboot",
                                NULL,
                                &Type,
                                (LPBYTE)&Reboot,
                                &Length);
        if (Error != ERROR_SUCCESS ||
            Type != REG_DWORD)
            goto loop;

        if (Reboot != 0)
            goto found;

loop:
        RegCloseKey(SubKey);
    }

    goto done;

found:
    RegCloseKey(SubKey);

    if (!Context->RebootPending)
        PromptForReboot(SubKeyName);

done:
    free(SubKeyName);

    Log("<====");

    return;

fail3:
    Log("fail3");

    free(SubKeyName);

fail2:
    Log("fail2");

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }
}

static VOID
CheckRequestKey(
    VOID
    )
{
    PMONITOR_CONTEXT    Context = &MonitorContext;
    HRESULT             Error;

    Log("====>");

    CheckRequestSubKeys();

    Error = RegNotifyChangeKeyValue(Context->RequestKey,
                                    TRUE,
                                    REG_NOTIFY_CHANGE_LAST_SET,
                                    Context->RequestEvent,
                                    TRUE);

    if (Error != ERROR_SUCCESS)
        goto fail1;

    Log("<====");

    return;

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }
}

static BOOL
AcquireShutdownPrivilege(
    VOID
    )
{
    HANDLE              Token;
    TOKEN_PRIVILEGES    New;
    BOOL                Success;
    HRESULT             Error;

    Log("====>");

    New.PrivilegeCount = 1;

    Success = LookupPrivilegeValue(NULL,
                                   SE_SHUTDOWN_NAME,
                                   &New.Privileges[0].Luid);

    if (!Success)
        goto fail1;

    New.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    Success = OpenProcessToken(GetCurrentProcess(),
                               TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                               &Token);

    if (!Success)
        goto fail2;

    Success = AdjustTokenPrivileges(Token,
                                    FALSE,
                                    &New,
                                    0,
                                    NULL,
                                    NULL);

    if (!Success)
        goto fail3;

    CloseHandle(Token);

    Log("<====");

    return TRUE;

fail3:
    Log("fail3");

    CloseHandle(Token);

fail2:
    Log("fail2");

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOL
GetRequestKeyName(
    OUT PTCHAR          *RequestKeyName
    )
{
    PMONITOR_CONTEXT    Context = &MonitorContext;
    DWORD               MaxValueLength;
    DWORD               RequestKeyNameLength;
    DWORD               Type;
    HRESULT             Error;

    Error = RegQueryInfoKey(Context->ParametersKey,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            &MaxValueLength,
                            NULL,
                            NULL);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail1;
    }

    RequestKeyNameLength = MaxValueLength + sizeof (TCHAR);

    *RequestKeyName = calloc(1, RequestKeyNameLength);
    if (RequestKeyName == NULL)
        goto fail2;

    Error = RegQueryValueEx(Context->ParametersKey,
                            "RequestKey",
                            NULL,
                            &Type,
                            (LPBYTE)(*RequestKeyName),
                            &RequestKeyNameLength);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail3;
    }

    if (Type != REG_SZ) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail4;
    }

    Log("%s", *RequestKeyName);

    return TRUE;

fail4:
    Log("fail4");

fail3:
    Log("fail3");

    free(*RequestKeyName);

fail2:
    Log("fail2");

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOL
GetDialogParameters(
    VOID
    )
{
    PMONITOR_CONTEXT    Context = &MonitorContext;
    DWORD               MaxValueLength;
    DWORD               TitleLength;
    DWORD               TextLength;
    DWORD               Type;
    HRESULT             Error;

    Error = RegQueryInfoKey(Context->ParametersKey,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            &MaxValueLength,
                            NULL,
                            NULL);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail1;
    }

    TitleLength = MaxValueLength + sizeof (TCHAR);

    Context->Title = calloc(1, TitleLength);
    if (Context == NULL)
        goto fail2;

    Error = RegQueryValueEx(Context->ParametersKey,
                            "DialogTitle",
                            NULL,
                            &Type,
                            (LPBYTE)Context->Title,
                            &TitleLength);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail3;
    }

    if (Type != REG_SZ) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail4;
    }

    TextLength = MaxValueLength + sizeof (TCHAR);

    Context->Text = calloc(1, TextLength);
    if (Context == NULL)
        goto fail5;

    Error = RegQueryValueEx(Context->ParametersKey,
                            "DialogText",
                            NULL,
                            &Type,
                            (LPBYTE)Context->Text,
                            &TextLength);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail6;
    }

    if (Type != REG_SZ) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail7;
    }

    return TRUE;

fail7:
    Log("fail7");

fail6:
    Log("fail6");

    free(Context->Text);

fail5:
    Log("fail5");

fail4:
    Log("fail4");

fail3:
    Log("fail3");

    free(Context->Title);

fail2:
    Log("fail2");

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}



VOID WINAPI
MonitorMain(
    _In_    DWORD       argc,
    _In_    LPTSTR      *argv
    )
{
    PMONITOR_CONTEXT    Context = &MonitorContext;
    PTCHAR              RequestKeyName;
    BOOL                Success;
    HRESULT             Error;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    Log("====>");

    Error = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                         PARAMETERS_KEY(__MODULE__),
                         0,
                         KEY_READ,
                         &Context->ParametersKey);
    if (Error != ERROR_SUCCESS)
        goto fail1;

    Success = AcquireShutdownPrivilege();
    if (!Success)
        goto fail2;

    Context->Service = RegisterServiceCtrlHandlerEx(MONITOR_NAME,
                                                    MonitorCtrlHandlerEx,
                                                    NULL);
    if (Context->Service == NULL)
        goto fail3;

    Context->EventLog = RegisterEventSource(NULL,
                                            MONITOR_NAME);
    if (Context->EventLog == NULL)
        goto fail4;

    Context->Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    Context->Status.dwServiceSpecificExitCode = 0;

    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    Context->StopEvent = CreateEvent(NULL,
                                     TRUE,
                                     FALSE,
                                     NULL);

    if (Context->StopEvent == NULL)
        goto fail5;

    Context->RequestEvent = CreateEvent(NULL,
                                        TRUE,
                                        FALSE,
                                        NULL);
    if (Context->RequestEvent == NULL)
        goto fail6;

    Success = GetRequestKeyName(&RequestKeyName);
    if (!Success)
        goto fail7;

    Error = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                           RequestKeyName,
                           0,
                           NULL,
                           REG_OPTION_NON_VOLATILE,
                           KEY_ALL_ACCESS,
                           NULL,
                           &Context->RequestKey,
                           NULL);
    if (Error != ERROR_SUCCESS)
        goto fail8;

    Success = GetDialogParameters();
    if (!Success)
        goto fail9;

    SetEvent(Context->RequestEvent);

    ReportStatus(SERVICE_RUNNING, NO_ERROR, 0);

    for (;;) {
        HANDLE  Events[2];
        DWORD   Object;

        Events[0] = Context->StopEvent;
        Events[1] = Context->RequestEvent;

        Log("waiting (%u)...", ARRAYSIZE(Events));
        Object = WaitForMultipleObjects(ARRAYSIZE(Events),
                                        Events,
                                        FALSE,
                                        INFINITE);
        Log("awake");

        switch (Object) {
        case WAIT_OBJECT_0:
            ResetEvent(Events[0]);
            goto done;

        case WAIT_OBJECT_0 + 1:
            ResetEvent(Events[1]);
            CheckRequestKey();
            break;

        default:
            break;
        }
    }

done:
    (VOID) RegDeleteTree(Context->RequestKey, NULL);

    free(Context->Text);
    free(Context->Title);
    CloseHandle(Context->RequestKey);
    free(RequestKeyName);
    CloseHandle(Context->RequestEvent);
    CloseHandle(Context->StopEvent);

    ReportStatus(SERVICE_STOPPED, NO_ERROR, 0);

    (VOID) DeregisterEventSource(Context->EventLog);

    CloseHandle(Context->ParametersKey);

    Log("<====");

    return;

fail9:
    Log("fail9");

    CloseHandle(Context->RequestKey);

fail8:
    Log("fail8");

    free(RequestKeyName);

fail7:
    Log("fail7");

    CloseHandle(Context->RequestEvent);

fail6:
    Log("fail6");

    CloseHandle(Context->StopEvent);

fail5:
    Log("fail5");

    ReportStatus(SERVICE_STOPPED, GetLastError(), 0);

    (VOID) DeregisterEventSource(Context->EventLog);

fail4:
    Log("fail4");

fail3:
    Log("fail3");

fail2:
    Log("fail2");

    CloseHandle(Context->ParametersKey);

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }
}

static BOOL
MonitorCreate(
    VOID
    )
{
    SC_HANDLE   SCManager;
    SC_HANDLE   Service;
    TCHAR       Path[MAX_PATH];
    HRESULT     Error;

    Log("====>");

    if(!GetModuleFileName(NULL, Path, MAX_PATH))
        goto fail1;

    SCManager = OpenSCManager(NULL,
                              NULL,
                              SC_MANAGER_ALL_ACCESS);

    if (SCManager == NULL)
        goto fail2;

    Service = CreateService(SCManager,
                            MONITOR_NAME,
                            MONITOR_DISPLAYNAME,
                            SERVICE_ALL_ACCESS,
                            SERVICE_WIN32_OWN_PROCESS,
                            SERVICE_AUTO_START,
                            SERVICE_ERROR_NORMAL,
                            Path,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);

    if (Service == NULL)
        goto fail3;

    CloseServiceHandle(Service);
    CloseServiceHandle(SCManager);

    Log("<====");

    return TRUE;

fail3:
    Log("fail3");

    CloseServiceHandle(SCManager);

fail2:
    Log("fail2");

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOL
MonitorDelete(
    VOID
    )
{
    SC_HANDLE           SCManager;
    SC_HANDLE           Service;
    BOOL                Success;
    SERVICE_STATUS      Status;
    HRESULT             Error;

    Log("====>");

    SCManager = OpenSCManager(NULL,
                              NULL,
                              SC_MANAGER_ALL_ACCESS);

    if (SCManager == NULL)
        goto fail1;

    Service = OpenService(SCManager,
                          MONITOR_NAME,
                          SERVICE_ALL_ACCESS);

    if (Service == NULL)
        goto fail2;

    Success = ControlService(Service,
                             SERVICE_CONTROL_STOP,
                             &Status);

    if (!Success)
        goto fail3;

    Success = DeleteService(Service);

    if (!Success)
        goto fail4;

    CloseServiceHandle(Service);
    CloseServiceHandle(SCManager);

    Log("<====");

    return TRUE;

fail4:
    Log("fail4");

fail3:
    Log("fail3");

    CloseServiceHandle(Service);

fail2:
    Log("fail2");

    CloseServiceHandle(SCManager);

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOL
MonitorEntry(
    VOID
    )
{
    SERVICE_TABLE_ENTRY Table[] = {
        { MONITOR_NAME, MonitorMain },
        { NULL, NULL }
    };
    HRESULT             Error;

    Log("%s (%s) ====>",
        MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
        DAY_STR "/" MONTH_STR "/" YEAR_STR);

    if (!StartServiceCtrlDispatcher(Table))
        goto fail1;

    Log("%s (%s) <====",
        MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
        DAY_STR "/" MONTH_STR "/" YEAR_STR);

    return TRUE;

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

int CALLBACK
_tWinMain(
    _In_        HINSTANCE   Current,
    _In_opt_    HINSTANCE   Previous,
    _In_        LPSTR       CmdLine,
    _In_        int         CmdShow
    )
{
    BOOL                    Success;

    UNREFERENCED_PARAMETER(Current);
    UNREFERENCED_PARAMETER(Previous);
    UNREFERENCED_PARAMETER(CmdShow);

    if (_tcslen(CmdLine) != 0) {
         if (_tcsicmp(CmdLine, TEXT("create")) == 0)
             Success = MonitorCreate();
         else if (_tcsicmp(CmdLine, TEXT("delete")) == 0)
             Success = MonitorDelete();
         else
             Success = FALSE;
    } else
        Success = MonitorEntry();

    return Success ? 0 : 1;
}
