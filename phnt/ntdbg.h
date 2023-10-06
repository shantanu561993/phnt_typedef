/*
 * This file is part of the Process Hacker project - https://processhacker.sourceforge.io/
 *
 * You can redistribute this file and/or modify it under the terms of the 
 * Attribution 4.0 International (CC BY 4.0) license. 
 * 
 * You must give appropriate credit, provide a link to the license, and 
 * indicate if changes were made. You may do so in any reasonable manner, but 
 * not in any way that suggests the licensor endorses you or your use.
 */

#ifndef _NTDBG_H
#define _NTDBG_H

// Debugging

typedef
VOID(
NTAPI*
DBGUSERBREAKPOINT)(
    VOID
    );

typedef
VOID(
NTAPI*
DBGBREAKPOINT)(
    VOID
    );

typedef
VOID(
NTAPI*
DBGBREAKPOINTWITHSTATUS)(
    _In_ ULONG Status
    );

#define DBG_STATUS_CONTROL_C 1
#define DBG_STATUS_SYSRQ 2
#define DBG_STATUS_BUGCHECK_FIRST 3
#define DBG_STATUS_BUGCHECK_SECOND 4
#define DBG_STATUS_FATAL 5
#define DBG_STATUS_DEBUG_CONTROL 6
#define DBG_STATUS_WORKER 7

typedef
ULONG(
STDAPIVCALLTYPE*
DBGPRINT)(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    );

typedef
ULONG(
STDAPIVCALLTYPE*
DBGPRINTEX)(
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    );

typedef
ULONG(
NTAPI*
VDBGPRINTEX)(
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_z_ PCCH Format,
    _In_ va_list arglist
    );

typedef
ULONG(
NTAPI*
VDBGPRINTEXWITHPREFIX)(
    _In_z_ PCCH Prefix,
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_z_ PCCH Format,
    _In_ va_list arglist
    );

typedef
NTSTATUS(
NTAPI*
DBGQUERYDEBUGFILTERSTATE)(
    _In_ ULONG ComponentId,
    _In_ ULONG Level
    );

typedef
NTSTATUS(
NTAPI*
DBGSETDEBUGFILTERSTATE)(
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_ BOOLEAN State
    );

typedef
ULONG(
NTAPI*
DBGPROMPT)(
    _In_ PCCH Prompt,
    _Out_writes_bytes_(Length) PCH Response,
    _In_ ULONG Length
    );

// Definitions

typedef struct _DBGKM_EXCEPTION
{
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD
{
    ULONG SubSystemKey;
    PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS
{
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL
{
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL
{
    PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

typedef enum _DBG_STATE
{
    DbgIdle,
    DbgReplyPending,
    DbgCreateThreadStateChange,
    DbgCreateProcessStateChange,
    DbgExitThreadStateChange,
    DbgExitProcessStateChange,
    DbgExceptionStateChange,
    DbgBreakpointStateChange,
    DbgSingleStepStateChange,
    DbgLoadDllStateChange,
    DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

typedef struct _DBGUI_CREATE_THREAD
{
    HANDLE HandleToThread;
    DBGKM_CREATE_THREAD NewThread;
} DBGUI_CREATE_THREAD, *PDBGUI_CREATE_THREAD;

typedef struct _DBGUI_CREATE_PROCESS
{
    HANDLE HandleToProcess;
    HANDLE HandleToThread;
    DBGKM_CREATE_PROCESS NewProcess;
} DBGUI_CREATE_PROCESS, *PDBGUI_CREATE_PROCESS;

typedef struct _DBGUI_WAIT_STATE_CHANGE
{
    DBG_STATE NewState;
    CLIENT_ID AppClientId;
    union
    {
        DBGKM_EXCEPTION Exception;
        DBGUI_CREATE_THREAD CreateThread;
        DBGUI_CREATE_PROCESS CreateProcessInfo;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;

#define DEBUG_READ_EVENT 0x0001
#define DEBUG_PROCESS_ASSIGN 0x0002
#define DEBUG_SET_INFORMATION 0x0004
#define DEBUG_QUERY_INFORMATION 0x0008
#define DEBUG_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
    DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | DEBUG_SET_INFORMATION | \
    DEBUG_QUERY_INFORMATION)

#define DEBUG_KILL_ON_CLOSE 0x1

typedef enum _DEBUGOBJECTINFOCLASS
{
    DebugObjectUnusedInformation,
    DebugObjectKillProcessOnExitInformation, // s: ULONG
    MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

// System calls

typedef
NTSTATUS(
NTAPI*
NTCREATEDEBUGOBJECT)(
    _Out_ PHANDLE DebugObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
NTDEBUGACTIVEPROCESS)(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle
    );

typedef
NTSTATUS(
NTAPI*
NTDEBUGCONTINUE)(
    _In_ HANDLE DebugObjectHandle,
    _In_ PCLIENT_ID ClientId,
    _In_ NTSTATUS ContinueStatus
    );

typedef
NTSTATUS(
NTAPI*
NTREMOVEPROCESSDEBUG)(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle
    );

typedef
NTSTATUS(
NTAPI*
NTSETINFORMATIONDEBUGOBJECT)(
    _In_ HANDLE DebugObjectHandle,
    _In_ DEBUGOBJECTINFOCLASS DebugObjectInformationClass,
    _In_ PVOID DebugInformation,
    _In_ ULONG DebugInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
NTWAITFORDEBUGEVENT)(
    _In_ HANDLE DebugObjectHandle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout,
    _Out_ PDBGUI_WAIT_STATE_CHANGE WaitStateChange
    );

// Debugging UI

typedef
NTSTATUS(
NTAPI*
DBGUICONNECTTODBG)(
    VOID
    );

typedef
HANDLE(
NTAPI*
DBGUIGETTHREADDEBUGOBJECT)(
    VOID
    );

typedef
VOID(
NTAPI*
DBGUISETTHREADDEBUGOBJECT)(
    _In_ HANDLE DebugObject
    );

typedef
NTSTATUS(
NTAPI*
DBGUIWAITSTATECHANGE)(
    _Out_ PDBGUI_WAIT_STATE_CHANGE StateChange,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
NTSTATUS(
NTAPI*
DBGUICONTINUE)(
    _In_ PCLIENT_ID AppClientId,
    _In_ NTSTATUS ContinueStatus
    );

typedef
NTSTATUS(
NTAPI*
DBGUISTOPDEBUGGING)(
    _In_ HANDLE Process
    );

typedef
NTSTATUS(
NTAPI*
DBGUIDEBUGACTIVEPROCESS)(
    _In_ HANDLE Process
    );

typedef
VOID(
NTAPI*
DBGUIREMOTEBREAKIN)(
    _In_ PVOID Context
    );

typedef
NTSTATUS(
NTAPI*
DBGUIISSUEREMOTEBREAKIN)(
    _In_ HANDLE Process
    );

typedef
NTSTATUS(
NTAPI*
DBGUICONVERTSTATECHANGESTRUCTURE)(
    _In_ PDBGUI_WAIT_STATE_CHANGE StateChange,
    _Out_ LPDEBUG_EVENT DebugEvent
    );

typedef
NTSTATUS(
NTAPI*
DBGUICONVERTSTATECHANGESTRUCTUREEX)(
    _In_ PDBGUI_WAIT_STATE_CHANGE StateChange,
    _Out_ LPDEBUG_EVENT DebugEvent
    );

struct _EVENT_FILTER_DESCRIPTOR;

typedef VOID (NTAPI *PENABLECALLBACK)(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ struct _EVENT_FILTER_DESCRIPTOR *FilterData,
    _Inout_opt_ PVOID CallbackContext
    );

typedef ULONGLONG REGHANDLE, *PREGHANDLE;

typedef
NTSTATUS(
NTAPI*
ETWEVENTREGISTER)(
    _In_ LPCGUID ProviderId,
    _In_opt_ PENABLECALLBACK EnableCallback,
    _In_opt_ PVOID CallbackContext,
    _Out_ PREGHANDLE RegHandle
    );

#endif
