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

#ifndef _NTTP_H
#define _NTTP_H

// Some types are already defined in winnt.h.

typedef struct _TP_ALPC TP_ALPC, *PTP_ALPC;

// private
typedef VOID (NTAPI *PTP_ALPC_CALLBACK)(
    _Inout_ PTP_CALLBACK_INSTANCE Instance,
    _Inout_opt_ PVOID Context,
    _In_ PTP_ALPC Alpc
    );

// rev
typedef VOID (NTAPI *PTP_ALPC_CALLBACK_EX)(
    _Inout_ PTP_CALLBACK_INSTANCE Instance,
    _Inout_opt_ PVOID Context,
    _In_ PTP_ALPC Alpc,
    _In_ PVOID ApcContext
    );

#if (PHNT_VERSION >= PHNT_VISTA)

// private
_Check_return_
typedef
NTSTATUS(
NTAPI*
TPALLOCPOOL)(
    _Out_ PTP_POOL *PoolReturn,
    _Reserved_ PVOID Reserved
    );

// winbase:CloseThreadpool
typedef
VOID(
NTAPI*
TPRELEASEPOOL)(
    _Inout_ PTP_POOL Pool
    );

// winbase:SetThreadpoolThreadMaximum
typedef
VOID(
NTAPI*
TPSETPOOLMAXTHREADS)(
    _Inout_ PTP_POOL Pool,
    _In_ ULONG MaxThreads
    );

// private
typedef
NTSTATUS(
NTAPI*
TPSETPOOLMINTHREADS)(
    _Inout_ PTP_POOL Pool,
    _In_ ULONG MinThreads
    );

#if (PHNT_VERSION >= PHNT_WIN7)
// rev
typedef
NTSTATUS(
NTAPI*
TPQUERYPOOLSTACKINFORMATION)(
    _In_ PTP_POOL Pool,
    _Out_ PTP_POOL_STACK_INFORMATION PoolStackInformation
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN7)
// rev
typedef
NTSTATUS(
NTAPI*
TPSETPOOLSTACKINFORMATION)(
    _Inout_ PTP_POOL Pool,
    _In_ PTP_POOL_STACK_INFORMATION PoolStackInformation
    );
#endif

// private
_Check_return_
typedef
NTSTATUS(
NTAPI*
TPALLOCCLEANUPGROUP)(
    _Out_ PTP_CLEANUP_GROUP *CleanupGroupReturn
    );

// winbase:CloseThreadpoolCleanupGroup
typedef
VOID(
NTAPI*
TPRELEASECLEANUPGROUP)(
    _Inout_ PTP_CLEANUP_GROUP CleanupGroup
    );

// winbase:CloseThreadpoolCleanupGroupMembers
typedef
VOID(
NTAPI*
TPRELEASECLEANUPGROUPMEMBERS)(
    _Inout_ PTP_CLEANUP_GROUP CleanupGroup,
    _In_ LOGICAL CancelPendingCallbacks,
    _Inout_opt_ PVOID CleanupParameter
    );

// winbase:SetEventWhenCallbackReturns
typedef
VOID(
NTAPI*
TPCALLBACKSETEVENTONCOMPLETION)(
    _Inout_ PTP_CALLBACK_INSTANCE Instance,
    _In_ HANDLE Event
    );

// winbase:ReleaseSemaphoreWhenCallbackReturns
typedef
VOID(
NTAPI*
TPCALLBACKRELEASESEMAPHOREONCOMPLETION)(
    _Inout_ PTP_CALLBACK_INSTANCE Instance,
    _In_ HANDLE Semaphore,
    _In_ ULONG ReleaseCount
    );

// winbase:ReleaseMutexWhenCallbackReturns
typedef
VOID(
NTAPI*
TPCALLBACKRELEASEMUTEXONCOMPLETION)(
    _Inout_ PTP_CALLBACK_INSTANCE Instance,
    _In_ HANDLE Mutex
    );

// winbase:LeaveCriticalSectionWhenCallbackReturns
typedef
VOID(
NTAPI*
TPCALLBACKLEAVECRITICALSECTIONONCOMPLETION)(
    _Inout_ PTP_CALLBACK_INSTANCE Instance,
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
    );

// winbase:FreeLibraryWhenCallbackReturns
typedef
VOID(
NTAPI*
TPCALLBACKUNLOADDLLONCOMPLETION)(
    _Inout_ PTP_CALLBACK_INSTANCE Instance,
    _In_ PVOID DllHandle
    );

// winbase:CallbackMayRunLong
typedef
NTSTATUS(
NTAPI*
TPCALLBACKMAYRUNLONG)(
    _Inout_ PTP_CALLBACK_INSTANCE Instance
    );

// winbase:DisassociateCurrentThreadFromCallback
typedef
VOID(
NTAPI*
TPDISASSOCIATECALLBACK)(
    _Inout_ PTP_CALLBACK_INSTANCE Instance
    );

// winbase:TrySubmitThreadpoolCallback
_Check_return_
typedef
NTSTATUS(
NTAPI*
TPSIMPLETRYPOST)(
    _In_ PTP_SIMPLE_CALLBACK Callback,
    _Inout_opt_ PVOID Context,
    _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
    );

// private
_Check_return_
typedef
NTSTATUS(
NTAPI*
TPALLOCWORK)(
    _Out_ PTP_WORK *WorkReturn,
    _In_ PTP_WORK_CALLBACK Callback,
    _Inout_opt_ PVOID Context,
    _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
    );

// winbase:CloseThreadpoolWork
typedef
VOID(
NTAPI*
TPRELEASEWORK)(
    _Inout_ PTP_WORK Work
    );

// winbase:SubmitThreadpoolWork
typedef
VOID(
NTAPI*
TPPOSTWORK)(
    _Inout_ PTP_WORK Work
    );

// winbase:WaitForThreadpoolWorkCallbacks
typedef
VOID(
NTAPI*
TPWAITFORWORK)(
    _Inout_ PTP_WORK Work,
    _In_ LOGICAL CancelPendingCallbacks
    );

// private
_Check_return_
typedef
NTSTATUS(
NTAPI*
TPALLOCTIMER)(
    _Out_ PTP_TIMER *Timer,
    _In_ PTP_TIMER_CALLBACK Callback,
    _Inout_opt_ PVOID Context,
    _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
    );

// winbase:CloseThreadpoolTimer
typedef
VOID(
NTAPI*
TPRELEASETIMER)(
    _Inout_ PTP_TIMER Timer
    );

// winbase:SetThreadpoolTimer
typedef
VOID(
NTAPI*
TPSETTIMER)(
    _Inout_ PTP_TIMER Timer,
    _In_opt_ PLARGE_INTEGER DueTime,
    _In_ ULONG Period,
    _In_opt_ ULONG WindowLength
    );

#if (PHNT_VERSION >= PHNT_WIN8)
// winbase:SetThreadpoolTimerEx
typedef
NTSTATUS(
NTAPI*
TPSETTIMEREX)(
    _Inout_ PTP_TIMER Timer,
    _In_opt_ PLARGE_INTEGER DueTime,
    _In_ ULONG Period,
    _In_opt_ ULONG WindowLength
    );
#endif

// winbase:IsThreadpoolTimerSet
typedef
LOGICAL(
NTAPI*
TPISTIMERSET)(
    _In_ PTP_TIMER Timer
    );

// winbase:WaitForThreadpoolTimerCallbacks
typedef
VOID(
NTAPI*
TPWAITFORTIMER)(
    _Inout_ PTP_TIMER Timer,
    _In_ LOGICAL CancelPendingCallbacks
    );

// private
_Check_return_
typedef
NTSTATUS(
NTAPI*
TPALLOCWAIT)(
    _Out_ PTP_WAIT *WaitReturn,
    _In_ PTP_WAIT_CALLBACK Callback,
    _Inout_opt_ PVOID Context,
    _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
    );

// winbase:CloseThreadpoolWait
typedef
VOID(
NTAPI*
TPRELEASEWAIT)(
    _Inout_ PTP_WAIT Wait
    );

// winbase:SetThreadpoolWait
typedef
VOID(
NTAPI*
TPSETWAIT)(
    _Inout_ PTP_WAIT Wait,
    _In_opt_ HANDLE Handle,
    _In_opt_ PLARGE_INTEGER Timeout
    );

#if (PHNT_VERSION >= PHNT_WIN8)
// winbase:SetThreadpoolWaitEx
typedef
NTSTATUS(
NTAPI*
TPSETWAITEX)(
    _Inout_ PTP_WAIT Wait,
    _In_opt_ HANDLE Handle,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_opt_ PVOID Reserved
    );
#endif

// winbase:WaitForThreadpoolWaitCallbacks
typedef
VOID(
NTAPI*
TPWAITFORWAIT)(
    _Inout_ PTP_WAIT Wait,
    _In_ LOGICAL CancelPendingCallbacks
    );

// private
typedef VOID (NTAPI *PTP_IO_CALLBACK)(
    _Inout_ PTP_CALLBACK_INSTANCE Instance,
    _Inout_opt_ PVOID Context,
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoSB,
    _In_ PTP_IO Io
    );

// private
_Check_return_
typedef
NTSTATUS(
NTAPI*
TPALLOCIOCOMPLETION)(
    _Out_ PTP_IO *IoReturn,
    _In_ HANDLE File,
    _In_ PTP_IO_CALLBACK Callback,
    _Inout_opt_ PVOID Context,
    _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
    );

// winbase:CloseThreadpoolIo
typedef
VOID(
NTAPI*
TPRELEASEIOCOMPLETION)(
    _Inout_ PTP_IO Io
    );

// winbase:StartThreadpoolIo
typedef
VOID(
NTAPI*
TPSTARTASYNCIOOPERATION)(
    _Inout_ PTP_IO Io
    );

// winbase:CancelThreadpoolIo
typedef
VOID(
NTAPI*
TPCANCELASYNCIOOPERATION)(
    _Inout_ PTP_IO Io
    );

// winbase:WaitForThreadpoolIoCallbacks
typedef
VOID(
NTAPI*
TPWAITFORIOCOMPLETION)(
    _Inout_ PTP_IO Io,
    _In_ LOGICAL CancelPendingCallbacks
    );

// private
typedef
NTSTATUS(
NTAPI*
TPALLOCALPCCOMPLETION)(
    _Out_ PTP_ALPC *AlpcReturn,
    _In_ HANDLE AlpcPort,
    _In_ PTP_ALPC_CALLBACK Callback,
    _Inout_opt_ PVOID Context,
    _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
    );

#if (PHNT_VERSION >= PHNT_WIN7)
// rev
typedef
NTSTATUS(
NTAPI*
TPALLOCALPCCOMPLETIONEX)(
    _Out_ PTP_ALPC *AlpcReturn,
    _In_ HANDLE AlpcPort,
    _In_ PTP_ALPC_CALLBACK_EX Callback,
    _Inout_opt_ PVOID Context,
    _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
    );
#endif

// private
typedef
VOID(
NTAPI*
TPRELEASEALPCCOMPLETION)(
    _Inout_ PTP_ALPC Alpc
    );

// private
typedef
VOID(
NTAPI*
TPWAITFORALPCCOMPLETION)(
    _Inout_ PTP_ALPC Alpc
    );

// private
typedef enum _TP_TRACE_TYPE
{
    TpTraceThreadPriority = 1,
    TpTraceThreadAffinity,
    MaxTpTraceType
} TP_TRACE_TYPE;

// private
typedef
VOID(
NTAPI*
TPCAPTURECALLER)(
    _In_ TP_TRACE_TYPE Type
    );

// private
typedef
VOID(
NTAPI*
TPCHECKTERMINATEWORKER)(
    _In_ HANDLE Thread
    );

#endif

#endif
