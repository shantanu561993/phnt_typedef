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

#ifndef _NTTMAPI_H
#define _NTTMAPI_H

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTCREATETRANSACTIONMANAGER)(
    _Out_ PHANDLE TmHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PUNICODE_STRING LogFileName,
    _In_opt_ ULONG CreateOptions,
    _In_opt_ ULONG CommitStrength
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTOPENTRANSACTIONMANAGER)(
    _Out_ PHANDLE TmHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PUNICODE_STRING LogFileName,
    _In_opt_ LPGUID TmIdentity,
    _In_opt_ ULONG OpenOptions
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTRENAMETRANSACTIONMANAGER)(
    _In_ PUNICODE_STRING LogFileName,
    _In_ LPGUID ExistingTransactionManagerGuid
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTROLLFORWARDTRANSACTIONMANAGER)(
    _In_ HANDLE TransactionManagerHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTRECOVERTRANSACTIONMANAGER)(
    _In_ HANDLE TransactionManagerHandle
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTQUERYINFORMATIONTRANSACTIONMANAGER)(
    _In_ HANDLE TransactionManagerHandle,
    _In_ TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    _Out_writes_bytes_(TransactionManagerInformationLength) PVOID TransactionManagerInformation,
    _In_ ULONG TransactionManagerInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTSETINFORMATIONTRANSACTIONMANAGER)(
    _In_opt_ HANDLE TmHandle,
    _In_ TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    _In_reads_bytes_(TransactionManagerInformationLength) PVOID TransactionManagerInformation,
    _In_ ULONG TransactionManagerInformationLength
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTENUMERATETRANSACTIONOBJECT)(
    _In_opt_ HANDLE RootObjectHandle,
    _In_ KTMOBJECT_TYPE QueryType,
    _Inout_updates_bytes_(ObjectCursorLength) PKTMOBJECT_CURSOR ObjectCursor,
    _In_ ULONG ObjectCursorLength,
    _Out_ PULONG ReturnLength
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTCREATETRANSACTION)(
    _Out_ PHANDLE TransactionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ LPGUID Uow,
    _In_opt_ HANDLE TmHandle,
    _In_opt_ ULONG CreateOptions,
    _In_opt_ ULONG IsolationLevel,
    _In_opt_ ULONG IsolationFlags,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_opt_ PUNICODE_STRING Description
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTOPENTRANSACTION)(
    _Out_ PHANDLE TransactionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ LPGUID Uow,
    _In_opt_ HANDLE TmHandle
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTQUERYINFORMATIONTRANSACTION)(
    _In_ HANDLE TransactionHandle,
    _In_ TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    _Out_writes_bytes_(TransactionInformationLength) PVOID TransactionInformation,
    _In_ ULONG TransactionInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTSETINFORMATIONTRANSACTION)(
    _In_ HANDLE TransactionHandle,
    _In_ TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    _In_reads_bytes_(TransactionInformationLength) PVOID TransactionInformation,
    _In_ ULONG TransactionInformationLength
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTCOMMITTRANSACTION)(
    _In_ HANDLE TransactionHandle,
    _In_ BOOLEAN Wait
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTROLLBACKTRANSACTION)(
    _In_ HANDLE TransactionHandle,
    _In_ BOOLEAN Wait
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTCREATEENLISTMENT)(
    _Out_ PHANDLE EnlistmentHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE ResourceManagerHandle,
    _In_ HANDLE TransactionHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ ULONG CreateOptions,
    _In_ NOTIFICATION_MASK NotificationMask,
    _In_opt_ PVOID EnlistmentKey
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTOPENENLISTMENT)(
    _Out_ PHANDLE EnlistmentHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE ResourceManagerHandle,
    _In_ LPGUID EnlistmentGuid,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTQUERYINFORMATIONENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_ ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    _Out_writes_bytes_(EnlistmentInformationLength) PVOID EnlistmentInformation,
    _In_ ULONG EnlistmentInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTSETINFORMATIONENLISTMENT)(
    _In_opt_ HANDLE EnlistmentHandle,
    _In_ ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    _In_reads_bytes_(EnlistmentInformationLength) PVOID EnlistmentInformation,
    _In_ ULONG EnlistmentInformationLength
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTRECOVERENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PVOID EnlistmentKey
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTPREPREPAREENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTPREPAREENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTCOMMITENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTROLLBACKENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTPREPREPARECOMPLETE)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTPREPARECOMPLETE)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTCOMMITCOMPLETE)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTREADONLYENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTROLLBACKCOMPLETE)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTSINGLEPHASEREJECT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTCREATERESOURCEMANAGER)(
    _Out_ PHANDLE ResourceManagerHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE TmHandle,
    _In_ LPGUID RmGuid,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ ULONG CreateOptions,
    _In_opt_ PUNICODE_STRING Description
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTOPENRESOURCEMANAGER)(
    _Out_ PHANDLE ResourceManagerHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE TmHandle,
    _In_opt_ LPGUID ResourceManagerGuid,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTRECOVERRESOURCEMANAGER)(
    _In_ HANDLE ResourceManagerHandle
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTGETNOTIFICATIONRESOURCEMANAGER)(
    _In_ HANDLE ResourceManagerHandle,
    _Out_ PTRANSACTION_NOTIFICATION TransactionNotification,
    _In_ ULONG NotificationLength,
    _In_opt_ PLARGE_INTEGER Timeout,
    _Out_opt_ PULONG ReturnLength,
    _In_ ULONG Asynchronous,
    _In_opt_ ULONG_PTR AsynchronousContext
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTQUERYINFORMATIONRESOURCEMANAGER)(
    _In_ HANDLE ResourceManagerHandle,
    _In_ RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    _Out_writes_bytes_(ResourceManagerInformationLength) PVOID ResourceManagerInformation,
    _In_ ULONG ResourceManagerInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTSETINFORMATIONRESOURCEMANAGER)(
    _In_ HANDLE ResourceManagerHandle,
    _In_ RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    _In_reads_bytes_(ResourceManagerInformationLength) PVOID ResourceManagerInformation,
    _In_ ULONG ResourceManagerInformationLength
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTREGISTERPROTOCOLADDRESSINFORMATION)(
    _In_ HANDLE ResourceManager,
    _In_ PCRM_PROTOCOL_ID ProtocolId,
    _In_ ULONG ProtocolInformationSize,
    _In_ PVOID ProtocolInformation,
    _In_opt_ ULONG CreateOptions
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTPROPAGATIONCOMPLETE)(
    _In_ HANDLE ResourceManagerHandle,
    _In_ ULONG RequestCookie,
    _In_ ULONG BufferLength,
    _In_ PVOID Buffer
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTPROPAGATIONFAILED)(
    _In_ HANDLE ResourceManagerHandle,
    _In_ ULONG RequestCookie,
    _In_ NTSTATUS PropStatus
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
NTFREEZETRANSACTIONS)(
    _In_ PLARGE_INTEGER FreezeTimeout,
    _In_ PLARGE_INTEGER ThawTimeout
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
NTTHAWTRANSACTIONS)(
    VOID
    );
#endif

#endif
