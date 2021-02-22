#ifndef _XENCONTROL_PRIVATE_H_
#define _XENCONTROL_PRIVATE_H_

#include <windows.h>
#include "xencontrol.h"

#define Log(level, format, ...) \
        _Log(Xc->Logger, level, Xc->LogLevel, __FUNCTION__, format, __VA_ARGS__)

#define InitializeListHead(ListHead) ( \
    (ListHead)->Flink = (ListHead)->Blink = (ListHead))

#define InsertTailList(ListHead, Entry) { \
    PLIST_ENTRY _EX_Blink; \
    PLIST_ENTRY _EX_ListHead; \
    _EX_ListHead = (ListHead); \
    _EX_Blink = _EX_ListHead->Blink; \
    (Entry)->Flink = _EX_ListHead; \
    (Entry)->Blink = _EX_Blink; \
    _EX_Blink->Flink = (Entry); \
    _EX_ListHead->Blink = (Entry); \
    }

#define RemoveEntryList(Entry) { \
    PLIST_ENTRY _EX_Blink; \
    PLIST_ENTRY _EX_Flink; \
    _EX_Flink = (Entry)->Flink; \
    _EX_Blink = (Entry)->Blink; \
    _EX_Blink->Flink = _EX_Flink; \
    _EX_Flink->Blink = _EX_Blink; \
    }

typedef struct _XENCONTROL_CONTEXT {
    HANDLE XenIface;
    XENCONTROL_LOGGER *Logger;
    XENCONTROL_LOG_LEVEL LogLevel;
    ULONG RequestId;
    LIST_ENTRY RequestList;
    CRITICAL_SECTION RequestListLock;
} XENCONTROL_CONTEXT, *PXENCONTROL_CONTEXT;

typedef struct _XENCONTROL_GNTTAB_REQUEST {
    LIST_ENTRY  ListEntry;
    OVERLAPPED  Overlapped;
    ULONG       Id;
    PVOID       Address;
} XENCONTROL_GNTTAB_REQUEST, *PXENCONTROL_GNTTAB_REQUEST;

#endif // _XENCONTROL_PRIVATE_H_
