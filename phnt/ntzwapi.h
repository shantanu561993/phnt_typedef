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

#ifndef _NTZWAPI_H
#define _NTZWAPI_H

// This file was automatically generated. Do not edit.

typedef
NTSTATUS(
NTAPI*
ZWACCEPTCONNECTPORT)(
    _Out_ PHANDLE PortHandle,
    _In_opt_ PVOID PortContext,
    _In_ PPORT_MESSAGE ConnectionRequest,
    _In_ BOOLEAN AcceptConnection,
    _Inout_opt_ PPORT_VIEW ServerView,
    _Out_opt_ PREMOTE_PORT_VIEW ClientView
    );

typedef
NTSTATUS(
NTAPI*
ZWACCESSCHECK)(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ HANDLE ClientToken,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_writes_bytes_(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet,
    _Inout_ PULONG PrivilegeSetLength,
    _Out_ PACCESS_MASK GrantedAccess,
    _Out_ PNTSTATUS AccessStatus
    );

typedef
NTSTATUS(
NTAPI*
ZWACCESSCHECKANDAUDITALARM)(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ PUNICODE_STRING ObjectTypeName,
    _In_ PUNICODE_STRING ObjectName,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_ BOOLEAN ObjectCreation,
    _Out_ PACCESS_MASK GrantedAccess,
    _Out_ PNTSTATUS AccessStatus,
    _Out_ PBOOLEAN GenerateOnClose
    );

typedef
NTSTATUS(
NTAPI*
ZWACCESSCHECKBYTYPE)(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID PrincipalSelfSid,
    _In_ HANDLE ClientToken,
    _In_ ACCESS_MASK DesiredAccess,
    _In_reads_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_writes_bytes_(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet,
    _Inout_ PULONG PrivilegeSetLength,
    _Out_ PACCESS_MASK GrantedAccess,
    _Out_ PNTSTATUS AccessStatus
    );

typedef
NTSTATUS(
NTAPI*
ZWACCESSCHECKBYTYPEANDAUDITALARM)(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ PUNICODE_STRING ObjectTypeName,
    _In_ PUNICODE_STRING ObjectName,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID PrincipalSelfSid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ AUDIT_EVENT_TYPE AuditType,
    _In_ ULONG Flags,
    _In_reads_opt_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_ BOOLEAN ObjectCreation,
    _Out_ PACCESS_MASK GrantedAccess,
    _Out_ PNTSTATUS AccessStatus,
    _Out_ PBOOLEAN GenerateOnClose
    );

typedef
NTSTATUS(
NTAPI*
ZWACCESSCHECKBYTYPERESULTLIST)(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID PrincipalSelfSid,
    _In_ HANDLE ClientToken,
    _In_ ACCESS_MASK DesiredAccess,
    _In_reads_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_writes_bytes_(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet,
    _Inout_ PULONG PrivilegeSetLength,
    _Out_writes_(ObjectTypeListLength) PACCESS_MASK GrantedAccess,
    _Out_writes_(ObjectTypeListLength) PNTSTATUS AccessStatus
    );

typedef
NTSTATUS(
NTAPI*
ZWACCESSCHECKBYTYPERESULTLISTANDAUDITALARM)(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ PUNICODE_STRING ObjectTypeName,
    _In_ PUNICODE_STRING ObjectName,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID PrincipalSelfSid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ AUDIT_EVENT_TYPE AuditType,
    _In_ ULONG Flags,
    _In_reads_opt_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_ BOOLEAN ObjectCreation,
    _Out_writes_(ObjectTypeListLength) PACCESS_MASK GrantedAccess,
    _Out_writes_(ObjectTypeListLength) PNTSTATUS AccessStatus,
    _Out_ PBOOLEAN GenerateOnClose
    );

typedef
NTSTATUS(
NTAPI*
ZWACCESSCHECKBYTYPERESULTLISTANDAUDITALARMBYHANDLE)(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ HANDLE ClientToken,
    _In_ PUNICODE_STRING ObjectTypeName,
    _In_ PUNICODE_STRING ObjectName,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID PrincipalSelfSid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ AUDIT_EVENT_TYPE AuditType,
    _In_ ULONG Flags,
    _In_reads_opt_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_ BOOLEAN ObjectCreation,
    _Out_writes_(ObjectTypeListLength) PACCESS_MASK GrantedAccess,
    _Out_writes_(ObjectTypeListLength) PNTSTATUS AccessStatus,
    _Out_ PBOOLEAN GenerateOnClose
    );

typedef
NTSTATUS(
NTAPI*
ZWACQUIRECMFVIEWOWNERSHIP)(
    _Out_ PULONGLONG TimeStamp,
    _Out_ PBOOLEAN tokenTaken,
    _In_ BOOLEAN replaceExisting
    );

typedef
NTSTATUS(
NTAPI*
ZWADDATOM)(
    _In_reads_bytes_opt_(Length) PWSTR AtomName,
    _In_ ULONG Length,
    _Out_opt_ PRTL_ATOM Atom
    );

typedef
NTSTATUS(
NTAPI*
ZWADDATOMEX)(
    _In_reads_bytes_opt_(Length) PWSTR AtomName,
    _In_ ULONG Length,
    _Out_opt_ PRTL_ATOM Atom,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
ZWADDBOOTENTRY)(
    _In_ PBOOT_ENTRY BootEntry,
    _Out_opt_ PULONG Id
    );

typedef
NTSTATUS(
NTAPI*
ZWADDDRIVERENTRY)(
    _In_ PEFI_DRIVER_ENTRY DriverEntry,
    _Out_opt_ PULONG Id
    );

typedef
NTSTATUS(
NTAPI*
ZWADJUSTGROUPSTOKEN)(
    _In_ HANDLE TokenHandle,
    _In_ BOOLEAN ResetToDefault,
    _In_opt_ PTOKEN_GROUPS NewState,
    _In_opt_ ULONG BufferLength,
    _Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_GROUPS PreviousState,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWADJUSTPRIVILEGESTOKEN)(
    _In_ HANDLE TokenHandle,
    _In_ BOOLEAN DisableAllPrivileges,
    _In_opt_ PTOKEN_PRIVILEGES NewState,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWADJUSTTOKENCLAIMSANDDEVICEGROUPS)(
    _In_ HANDLE TokenHandle,
    _In_ BOOLEAN UserResetToDefault,
    _In_ BOOLEAN DeviceResetToDefault,
    _In_ BOOLEAN DeviceGroupsResetToDefault,
    _In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState,
    _In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState,
    _In_opt_ PTOKEN_GROUPS NewDeviceGroupsState,
    _In_ ULONG UserBufferLength,
    _Out_writes_bytes_to_opt_(UserBufferLength, *UserReturnLength) PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState,
    _In_ ULONG DeviceBufferLength,
    _Out_writes_bytes_to_opt_(DeviceBufferLength, *DeviceReturnLength) PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState,
    _In_ ULONG DeviceGroupsBufferLength,
    _Out_writes_bytes_to_opt_(DeviceGroupsBufferLength, *DeviceGroupsReturnBufferLength) PTOKEN_GROUPS PreviousDeviceGroups,
    _Out_opt_ PULONG UserReturnLength,
    _Out_opt_ PULONG DeviceReturnLength,
    _Out_opt_ PULONG DeviceGroupsReturnBufferLength
    );

typedef
NTSTATUS(
NTAPI*
ZWALERTRESUMETHREAD)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );

typedef
NTSTATUS(
NTAPI*
ZWALERTTHREAD)(
    _In_ HANDLE ThreadHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWALERTTHREADBYTHREADID)(
    _In_ HANDLE ThreadId
    );

typedef
NTSTATUS(
NTAPI*
ZWALLOCATELOCALLYUNIQUEID)(
    _Out_ PLUID Luid
    );

typedef
NTSTATUS(
NTAPI*
ZWALLOCATERESERVEOBJECT)(
    _Out_ PHANDLE MemoryReserveHandle,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ MEMORY_RESERVE_TYPE Type
    );

typedef
NTSTATUS(
NTAPI*
ZWALLOCATEUSERPHYSICALPAGES)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PULONG_PTR NumberOfPages,
    _Out_writes_(*NumberOfPages) PULONG_PTR UserPfnArray
    );

typedef
NTSTATUS(
NTAPI*
ZWALLOCATEUSERPHYSICALPAGESEX)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PULONG_PTR NumberOfPages,
    _Out_writes_(*NumberOfPages) PULONG_PTR UserPfnArray,
    _Inout_updates_opt_(ParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    );

typedef
NTSTATUS(
NTAPI*
ZWALLOCATEUUIDS)(
    _Out_ PULARGE_INTEGER Time,
    _Out_ PULONG Range,
    _Out_ PULONG Sequence,
    _Out_ PCHAR Seed
    );

typedef
NTSTATUS(
NTAPI*
ZWALLOCATEVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCACCEPTCONNECTPORT)(
    _Out_ PHANDLE PortHandle,
    _In_ HANDLE ConnectionPortHandle,
    _In_ ULONG Flags,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
    _In_opt_ PVOID PortContext,
    _In_reads_bytes_(ConnectionRequest->u1.s1.TotalLength) PPORT_MESSAGE ConnectionRequest,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
    _In_ BOOLEAN AcceptConnection
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCCANCELMESSAGE)(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags,
    _In_ PALPC_CONTEXT_ATTR MessageContext
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCCONNECTPORT)(
    _Out_ PHANDLE PortHandle,
    _In_ PUNICODE_STRING PortName,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
    _In_ ULONG Flags,
    _In_opt_ PSID RequiredServerSid,
    _Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ConnectionMessage,
    _Inout_opt_ PULONG BufferLength,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCCONNECTPORTEX)(
    _Out_ PHANDLE PortHandle,
    _In_ POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ClientPortObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
    _In_ ULONG Flags,
    _In_opt_ PSECURITY_DESCRIPTOR ServerSecurityRequirements,
    _Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ConnectionMessage,
    _Inout_opt_ PSIZE_T BufferLength,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCCREATEPORT)(
    _Out_ PHANDLE PortHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCCREATEPORTSECTION)(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags,
    _In_opt_ HANDLE SectionHandle,
    _In_ SIZE_T SectionSize,
    _Out_ PALPC_HANDLE AlpcSectionHandle,
    _Out_ PSIZE_T ActualSectionSize
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCCREATERESOURCERESERVE)(
    _In_ HANDLE PortHandle,
    _Reserved_ ULONG Flags,
    _In_ SIZE_T MessageSize,
    _Out_ PALPC_HANDLE ResourceId
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCCREATESECTIONVIEW)(
    _In_ HANDLE PortHandle,
    _Reserved_ ULONG Flags,
    _Inout_ PALPC_DATA_VIEW_ATTR ViewAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCCREATESECURITYCONTEXT)(
    _In_ HANDLE PortHandle,
    _Reserved_ ULONG Flags,
    _Inout_ PALPC_SECURITY_ATTR SecurityAttribute
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCDELETEPORTSECTION)(
    _In_ HANDLE PortHandle,
    _Reserved_ ULONG Flags,
    _In_ ALPC_HANDLE SectionHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCDELETERESOURCERESERVE)(
    _In_ HANDLE PortHandle,
    _Reserved_ ULONG Flags,
    _In_ ALPC_HANDLE ResourceId
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCDELETESECTIONVIEW)(
    _In_ HANDLE PortHandle,
    _Reserved_ ULONG Flags,
    _In_ PVOID ViewBase
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCDELETESECURITYCONTEXT)(
    _In_ HANDLE PortHandle,
    _Reserved_ ULONG Flags,
    _In_ ALPC_HANDLE ContextHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCDISCONNECTPORT)(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCIMPERSONATECLIENTCONTAINEROFPORT)(
    _In_ HANDLE PortHandle,
    _In_ PPORT_MESSAGE Message,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCIMPERSONATECLIENTOFPORT)(
    _In_ HANDLE PortHandle,
    _In_ PPORT_MESSAGE Message,
    _In_ PVOID Flags
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCOPENSENDERPROCESS)(
    _Out_ PHANDLE ProcessHandle,
    _In_ HANDLE PortHandle,
    _In_ PPORT_MESSAGE PortMessage,
    _In_ ULONG Flags,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCOPENSENDERTHREAD)(
    _Out_ PHANDLE ThreadHandle,
    _In_ HANDLE PortHandle,
    _In_ PPORT_MESSAGE PortMessage,
    _In_ ULONG Flags,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCQUERYINFORMATION)(
    _In_opt_ HANDLE PortHandle,
    _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    _Inout_updates_bytes_to_(Length, *ReturnLength) PVOID PortInformation,
    _In_ ULONG Length,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCQUERYINFORMATIONMESSAGE)(
    _In_ HANDLE PortHandle,
    _In_ PPORT_MESSAGE PortMessage,
    _In_ ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ReturnLength) PVOID MessageInformation,
    _In_ ULONG Length,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCREVOKESECURITYCONTEXT)(
    _In_ HANDLE PortHandle,
    _Reserved_ ULONG Flags,
    _In_ ALPC_HANDLE ContextHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCSENDWAITRECEIVEPORT)(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags,
    _In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE SendMessage,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
    _Inout_opt_ PSIZE_T BufferLength,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
NTSTATUS(
NTAPI*
ZWALPCSETINFORMATION)(
    _In_ HANDLE PortHandle,
    _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    _In_reads_bytes_opt_(Length) PVOID PortInformation,
    _In_ ULONG Length
    );

typedef
NTSTATUS(
NTAPI*
ZWAREMAPPEDFILESTHESAME)(
    _In_ PVOID File1MappedAsAnImage,
    _In_ PVOID File2MappedAsFile
    );

typedef
NTSTATUS(
NTAPI*
ZWASSIGNPROCESSTOJOBOBJECT)(
    _In_ HANDLE JobHandle,
    _In_ HANDLE ProcessHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWASSOCIATEWAITCOMPLETIONPACKET)(
    _In_ HANDLE WaitCompletionPacketHandle,
    _In_ HANDLE IoCompletionHandle,
    _In_ HANDLE TargetObjectHandle,
    _In_opt_ PVOID KeyContext,
    _In_opt_ PVOID ApcContext,
    _In_ NTSTATUS IoStatus,
    _In_ ULONG_PTR IoStatusInformation,
    _Out_opt_ PBOOLEAN AlreadySignaled
    );

typedef
NTSTATUS(
NTAPI*
ZWCALLBACKRETURN)(
    _In_reads_bytes_opt_(OutputLength) PVOID OutputBuffer,
    _In_ ULONG OutputLength,
    _In_ NTSTATUS Status
    );

typedef
NTSTATUS(
NTAPI*
ZWCALLENCLAVE)(
    _In_ PENCLAVE_ROUTINE Routine,
    _In_ PVOID Parameter,
    _In_ BOOLEAN WaitForThread,
    _Out_opt_ PVOID *ReturnValue
    );

typedef
NTSTATUS(
NTAPI*
ZWCANCELIOFILE)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock
    );

typedef
NTSTATUS(
NTAPI*
ZWCANCELIOFILEEX)(
    _In_ HANDLE FileHandle,
    _In_opt_ PIO_STATUS_BLOCK IoRequestToCancel,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock
    );

typedef
NTSTATUS(
NTAPI*
ZWCANCELSYNCHRONOUSIOFILE)(
    _In_ HANDLE ThreadHandle,
    _In_opt_ PIO_STATUS_BLOCK IoRequestToCancel,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock
    );

typedef
NTSTATUS(
NTAPI*
ZWCANCELTIMER)(
    _In_ HANDLE TimerHandle,
    _Out_opt_ PBOOLEAN CurrentState
    );

typedef
NTSTATUS(
NTAPI*
ZWCANCELTIMER2)(
    _In_ HANDLE TimerHandle,
    _In_ PT2_CANCEL_PARAMETERS Parameters
    );

typedef
NTSTATUS(
NTAPI*
ZWCANCELWAITCOMPLETIONPACKET)(
    _In_ HANDLE WaitCompletionPacketHandle,
    _In_ BOOLEAN RemoveSignaledPacket
    );

typedef
NTSTATUS(
NTAPI*
ZWCHANGEPROCESSSTATE)(
    _In_ HANDLE ProcessStateChangeHandle,
    _In_ HANDLE ProcessHandle,
    _In_ PROCESS_STATE_CHANGE_TYPE StateChangeType,
    _In_opt_ PVOID ExtendedInformation,
    _In_opt_ SIZE_T ExtendedInformationLength,
    _In_opt_ ULONG64 Reserved
    );

typedef
NTSTATUS(
NTAPI*
ZWCHANGETHREADSTATE)(
    _In_ HANDLE ThreadStateChangeHandle,
    _In_ HANDLE ThreadHandle,
    _In_ THREAD_STATE_CHANGE_TYPE StateChangeType,
    _In_opt_ PVOID ExtendedInformation,
    _In_opt_ SIZE_T ExtendedInformationLength,
    _In_opt_ ULONG64 Reserved
    );

typedef
NTSTATUS(
NTAPI*
ZWCLEAREVENT)(
    _In_ HANDLE EventHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWCLOSE)(
    _In_ _Post_ptr_invalid_ HANDLE Handle
    );

typedef
NTSTATUS(
NTAPI*
ZWCLOSEOBJECTAUDITALARM)(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ BOOLEAN GenerateOnClose
    );

typedef
NTSTATUS(
NTAPI*
ZWCOMMITCOMPLETE)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );

typedef
NTSTATUS(
NTAPI*
ZWCOMMITENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );

typedef
NTSTATUS(
NTAPI*
ZWCOMMITTRANSACTION)(
    _In_ HANDLE TransactionHandle,
    _In_ BOOLEAN Wait
    );

typedef
NTSTATUS(
NTAPI*
ZWCOMPACTKEYS)(
    _In_ ULONG Count,
    _In_reads_(Count) HANDLE KeyArray[]
    );

typedef
NTSTATUS(
NTAPI*
ZWCOMPAREOBJECTS)(
    _In_ HANDLE FirstObjectHandle,
    _In_ HANDLE SecondObjectHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWCOMPARESIGNINGLEVELS)(
    _In_ SE_SIGNING_LEVEL FirstSigningLevel,
    _In_ SE_SIGNING_LEVEL SecondSigningLevel
    );

typedef
NTSTATUS(
NTAPI*
ZWCOMPARETOKENS)(
    _In_ HANDLE FirstTokenHandle,
    _In_ HANDLE SecondTokenHandle,
    _Out_ PBOOLEAN Equal
    );

typedef
NTSTATUS(
NTAPI*
ZWCOMPLETECONNECTPORT)(
    _In_ HANDLE PortHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWCOMPRESSKEY)(
    _In_ HANDLE Key
    );

typedef
NTSTATUS(
NTAPI*
ZWCONNECTPORT)(
    _Out_ PHANDLE PortHandle,
    _In_ PUNICODE_STRING PortName,
    _In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    _Inout_opt_ PPORT_VIEW ClientView,
    _Inout_opt_ PREMOTE_PORT_VIEW ServerView,
    _Out_opt_ PULONG MaxMessageLength,
    _Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
    _Inout_opt_ PULONG ConnectionInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWCONTINUE)(
    _In_ PCONTEXT ContextRecord,
    _In_ BOOLEAN TestAlert
    );

typedef
NTSTATUS(
NTAPI*
ZWCONTINUEEX)(
    _In_ PCONTEXT ContextRecord,
    _In_ PVOID ContinueArgument // PKCONTINUE_ARGUMENT and BOOLEAN are valid
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEDEBUGOBJECT)(
    _Out_ PHANDLE DebugObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEDIRECTORYOBJECT)(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEDIRECTORYOBJECTEX)(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ShadowDirectoryHandle,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEENCLAVE)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T Size,
    _In_ SIZE_T InitialCommitment,
    _In_ ULONG EnclaveType,
    _In_reads_bytes_(EnclaveInformationLength) PVOID EnclaveInformation,
    _In_ ULONG EnclaveInformationLength,
    _Out_opt_ PULONG EnclaveError
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEENLISTMENT)(
    _Out_ PHANDLE EnlistmentHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE ResourceManagerHandle,
    _In_ HANDLE TransactionHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ ULONG CreateOptions,
    _In_ NOTIFICATION_MASK NotificationMask,
    _In_opt_ PVOID EnlistmentKey
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEEVENT)(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ EVENT_TYPE EventType,
    _In_ BOOLEAN InitialState
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEEVENTPAIR)(
    _Out_ PHANDLE EventPairHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEFILE)(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEIOCOMPLETION)(
    _Out_ PHANDLE IoCompletionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ ULONG Count
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEIRTIMER)(
    _Out_ PHANDLE TimerHandle,
    _In_ ACCESS_MASK DesiredAccess
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEJOBOBJECT)(
    _Out_ PHANDLE JobHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEJOBSET)(
    _In_ ULONG NumJob,
    _In_reads_(NumJob) PJOB_SET_ARRAY UserJobSet,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEKEY)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Reserved_ ULONG TitleIndex,
    _In_opt_ PUNICODE_STRING Class,
    _In_ ULONG CreateOptions,
    _Out_opt_ PULONG Disposition
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEKEYEDEVENT)(
    _Out_ PHANDLE KeyedEventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEKEYTRANSACTED)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Reserved_ ULONG TitleIndex,
    _In_opt_ PUNICODE_STRING Class,
    _In_ ULONG CreateOptions,
    _In_ HANDLE TransactionHandle,
    _Out_opt_ PULONG Disposition
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATELOWBOXTOKEN)(
    _Out_ PHANDLE TokenHandle,
    _In_ HANDLE ExistingTokenHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PSID PackageSid,
    _In_ ULONG CapabilityCount,
    _In_reads_opt_(CapabilityCount) PSID_AND_ATTRIBUTES Capabilities,
    _In_ ULONG HandleCount,
    _In_reads_opt_(HandleCount) HANDLE *Handles
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEMAILSLOTFILE)(
    _Out_ PHANDLE FileHandle,
    _In_ ULONG DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG CreateOptions,
    _In_ ULONG MailslotQuota,
    _In_ ULONG MaximumMessageSize,
    _In_ PLARGE_INTEGER ReadTimeout
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEMUTANT)(
    _Out_ PHANDLE MutantHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ BOOLEAN InitialOwner
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATENAMEDPIPEFILE)(
    _Out_ PHANDLE FileHandle,
    _In_ ULONG DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_ ULONG NamedPipeType,
    _In_ ULONG ReadMode,
    _In_ ULONG CompletionMode,
    _In_ ULONG MaximumInstances,
    _In_ ULONG InboundQuota,
    _In_ ULONG OutboundQuota,
    _In_opt_ PLARGE_INTEGER DefaultTimeout
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEPAGINGFILE)(
    _In_ PUNICODE_STRING PageFileName,
    _In_ PLARGE_INTEGER MinimumSize,
    _In_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG Priority
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEPARTITION)(
    _In_ HANDLE ParentPartitionHandle,
    _Out_ PHANDLE PartitionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG PreferredNode
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEPORT)(
    _Out_ PHANDLE PortHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG MaxConnectionInfoLength,
    _In_ ULONG MaxMessageLength,
    _In_opt_ ULONG MaxPoolUsage
    );

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
ZWCREATEPRIVATENAMESPACE)(
    _Out_ PHANDLE NamespaceHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor
    );
#endif

typedef
NTSTATUS(
NTAPI*
ZWCREATEPROCESS)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ BOOLEAN InheritObjectTable,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEPROCESSEX)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ ULONG Flags, // PROCESS_CREATE_FLAGS_*
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle,
    _Reserved_ ULONG Reserved // JobMemberLevel
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEPROCESSSTATECHANGE)(
    _Out_ PHANDLE ProcessStateChangeHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_opt_ ULONG64 Reserved
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEPROFILE)(
    _Out_ PHANDLE ProfileHandle,
    _In_opt_ HANDLE Process,
    _In_ PVOID ProfileBase,
    _In_ SIZE_T ProfileSize,
    _In_ ULONG BucketSize,
    _In_reads_bytes_(BufferSize) PULONG Buffer,
    _In_ ULONG BufferSize,
    _In_ KPROFILE_SOURCE ProfileSource,
    _In_ KAFFINITY Affinity
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEPROFILEEX)(
    _Out_ PHANDLE ProfileHandle,
    _In_opt_ HANDLE Process,
    _In_ PVOID ProfileBase,
    _In_ SIZE_T ProfileSize,
    _In_ ULONG BucketSize,
    _In_reads_bytes_(BufferSize) PULONG Buffer,
    _In_ ULONG BufferSize,
    _In_ KPROFILE_SOURCE ProfileSource,
    _In_ USHORT GroupCount,
    _In_reads_(GroupCount) PGROUP_AFFINITY GroupAffinity
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATERESOURCEMANAGER)(
    _Out_ PHANDLE ResourceManagerHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE TmHandle,
    _In_ LPGUID RmGuid,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ ULONG CreateOptions,
    _In_opt_ PUNICODE_STRING Description
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATESECTION)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATESECTIONEX)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATESEMAPHORE)(
    _Out_ PHANDLE SemaphoreHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ LONG InitialCount,
    _In_ LONG MaximumCount
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATESYMBOLICLINKOBJECT)(
    _Out_ PHANDLE LinkHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PUNICODE_STRING LinkTarget
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATETHREAD)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _Out_ PCLIENT_ID ClientId,
    _In_ PCONTEXT ThreadContext,
    _In_ PINITIAL_TEB InitialTeb,
    _In_ BOOLEAN CreateSuspended
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATETHREADEX)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATETHREADSTATECHANGE)(
    _Out_ PHANDLE ThreadStateChangeHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ThreadHandle,
    _In_opt_ ULONG64 Reserved
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATETIMER)(
    _Out_ PHANDLE TimerHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ TIMER_TYPE TimerType
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATETIMER2)(
    _Out_ PHANDLE TimerHandle,
    _In_opt_ PVOID Reserved1,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Attributes,
    _In_ ACCESS_MASK DesiredAccess
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATETOKEN)(
    _Out_ PHANDLE TokenHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ TOKEN_TYPE Type,
    _In_ PLUID AuthenticationId,
    _In_ PLARGE_INTEGER ExpirationTime,
    _In_ PTOKEN_USER User,
    _In_ PTOKEN_GROUPS Groups,
    _In_ PTOKEN_PRIVILEGES Privileges,
    _In_opt_ PTOKEN_OWNER Owner,
    _In_ PTOKEN_PRIMARY_GROUP PrimaryGroup,
    _In_opt_ PTOKEN_DEFAULT_DACL DefaultDacl,
    _In_ PTOKEN_SOURCE Source
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATETOKENEX)(
    _Out_ PHANDLE TokenHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ TOKEN_TYPE Type,
    _In_ PLUID AuthenticationId,
    _In_ PLARGE_INTEGER ExpirationTime,
    _In_ PTOKEN_USER User,
    _In_ PTOKEN_GROUPS Groups,
    _In_ PTOKEN_PRIVILEGES Privileges,
    _In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes,
    _In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes,
    _In_opt_ PTOKEN_GROUPS DeviceGroups,
    _In_opt_ PTOKEN_MANDATORY_POLICY MandatoryPolicy,
    _In_opt_ PTOKEN_OWNER Owner,
    _In_ PTOKEN_PRIMARY_GROUP PrimaryGroup,
    _In_opt_ PTOKEN_DEFAULT_DACL DefaultDacl,
    _In_ PTOKEN_SOURCE Source
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATETRANSACTION)(
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

typedef
NTSTATUS(
NTAPI*
ZWCREATETRANSACTIONMANAGER)(
    _Out_ PHANDLE TmHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PUNICODE_STRING LogFileName,
    _In_opt_ ULONG CreateOptions,
    _In_opt_ ULONG CommitStrength
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEUSERPROCESS)(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
    _In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
    _In_opt_ PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
    _Inout_ PPS_CREATE_INFO CreateInfo,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEWAITABLEPORT)(
    _Out_ PHANDLE PortHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG MaxConnectionInfoLength,
    _In_ ULONG MaxMessageLength,
    _In_opt_ ULONG MaxPoolUsage
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEWAITCOMPLETIONPACKET)(
    _Out_ PHANDLE WaitCompletionPacketHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEWNFSTATENAME)(
    _Out_ PWNF_STATE_NAME StateName,
    _In_ WNF_STATE_NAME_LIFETIME NameLifetime,
    _In_ WNF_DATA_SCOPE DataScope,
    _In_ BOOLEAN PersistData,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_ ULONG MaximumStateSize,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
    );

typedef
NTSTATUS(
NTAPI*
ZWCREATEWORKERFACTORY)(
    _Out_ PHANDLE WorkerFactoryHandleReturn,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE CompletionPortHandle,
    _In_ HANDLE WorkerProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID StartParameter,
    _In_opt_ ULONG MaxThreadCount,
    _In_opt_ SIZE_T StackReserve,
    _In_opt_ SIZE_T StackCommit
    );

typedef
NTSTATUS(
NTAPI*
ZWDEBUGACTIVEPROCESS)(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWDEBUGCONTINUE)(
    _In_ HANDLE DebugObjectHandle,
    _In_ PCLIENT_ID ClientId,
    _In_ NTSTATUS ContinueStatus
    );

typedef
NTSTATUS(
NTAPI*
ZWDELAYEXECUTION)(
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER DelayInterval
    );

typedef
NTSTATUS(
NTAPI*
ZWDELETEATOM)(
    _In_ RTL_ATOM Atom
    );

typedef
NTSTATUS(
NTAPI*
ZWDELETEBOOTENTRY)(
    _In_ ULONG Id
    );

typedef
NTSTATUS(
NTAPI*
ZWDELETEDRIVERENTRY)(
    _In_ ULONG Id
    );

typedef
NTSTATUS(
NTAPI*
ZWDELETEFILE)(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWDELETEKEY)(
    _In_ HANDLE KeyHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWDELETEOBJECTAUDITALARM)(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ BOOLEAN GenerateOnClose
    );

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
ZWDELETEPRIVATENAMESPACE)(
    _In_ HANDLE NamespaceHandle
    );
#endif

typedef
NTSTATUS(
NTAPI*
ZWDELETEVALUEKEY)(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName
    );

typedef
NTSTATUS(
NTAPI*
ZWDELETEWNFSTATEDATA)(
    _In_ PCWNF_STATE_NAME StateName,
    _In_opt_ const VOID *ExplicitScope
    );

typedef
NTSTATUS(
NTAPI*
ZWDELETEWNFSTATENAME)(
    _In_ PCWNF_STATE_NAME StateName
    );

typedef
NTSTATUS(
NTAPI*
ZWDEVICEIOCONTROLFILE)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength
    );

typedef
NTSTATUS(
NTAPI*
ZWDISABLELASTKNOWNGOOD)(
    VOID
    );

typedef
NTSTATUS(
NTAPI*
ZWDISPLAYSTRING)(
    _In_ PUNICODE_STRING String
    );

typedef
NTSTATUS(
NTAPI*
ZWDRAWTEXT)(
    _In_ PUNICODE_STRING Text
    );

typedef
NTSTATUS(
NTAPI*
ZWDUPLICATEOBJECT)(
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _In_opt_ HANDLE TargetProcessHandle,
    _Out_opt_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options
    );

typedef
NTSTATUS(
NTAPI*
ZWDUPLICATETOKEN)(
    _In_ HANDLE ExistingTokenHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ BOOLEAN EffectiveOnly,
    _In_ TOKEN_TYPE Type,
    _Out_ PHANDLE NewTokenHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWENABLELASTKNOWNGOOD)(
    VOID
    );

typedef
NTSTATUS(
NTAPI*
ZWENUMERATEBOOTENTRIES)(
    _Out_writes_bytes_opt_(*BufferLength) PVOID Buffer,
    _Inout_ PULONG BufferLength
    );

typedef
NTSTATUS(
NTAPI*
ZWENUMERATEDRIVERENTRIES)(
    _Out_writes_bytes_opt_(*BufferLength) PVOID Buffer,
    _Inout_ PULONG BufferLength
    );

typedef
NTSTATUS(
NTAPI*
ZWENUMERATEKEY)(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    );

typedef
NTSTATUS(
NTAPI*
ZWENUMERATESYSTEMENVIRONMENTVALUESEX)(
    _In_ ULONG InformationClass,
    _Out_ PVOID Buffer,
    _Inout_ PULONG BufferLength
    );

typedef
NTSTATUS(
NTAPI*
ZWENUMERATETRANSACTIONOBJECT)(
    _In_opt_ HANDLE RootObjectHandle,
    _In_ KTMOBJECT_TYPE QueryType,
    _Inout_updates_bytes_(ObjectCursorLength) PKTMOBJECT_CURSOR ObjectCursor,
    _In_ ULONG ObjectCursorLength,
    _Out_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWENUMERATEVALUEKEY)(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    );

typedef
NTSTATUS(
NTAPI*
ZWEXTENDSECTION)(
    _In_ HANDLE SectionHandle,
    _Inout_ PLARGE_INTEGER NewSectionSize
    );

typedef
NTSTATUS(
NTAPI*
ZWFILTERBOOTOPTION)(
    _In_ FILTER_BOOT_OPTION_OPERATION FilterOperation,
    _In_ ULONG ObjectType,
    _In_ ULONG ElementType,
    _In_reads_bytes_opt_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    );

typedef
NTSTATUS(
NTAPI*
ZWFILTERTOKEN)(
    _In_ HANDLE ExistingTokenHandle,
    _In_ ULONG Flags,
    _In_opt_ PTOKEN_GROUPS SidsToDisable,
    _In_opt_ PTOKEN_PRIVILEGES PrivilegesToDelete,
    _In_opt_ PTOKEN_GROUPS RestrictedSids,
    _Out_ PHANDLE NewTokenHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWFILTERTOKENEX)(
    _In_ HANDLE ExistingTokenHandle,
    _In_ ULONG Flags,
    _In_opt_ PTOKEN_GROUPS SidsToDisable,
    _In_opt_ PTOKEN_PRIVILEGES PrivilegesToDelete,
    _In_opt_ PTOKEN_GROUPS RestrictedSids,
    _In_ ULONG DisableUserClaimsCount,
    _In_opt_ PUNICODE_STRING UserClaimsToDisable,
    _In_ ULONG DisableDeviceClaimsCount,
    _In_opt_ PUNICODE_STRING DeviceClaimsToDisable,
    _In_opt_ PTOKEN_GROUPS DeviceGroupsToDisable,
    _In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes,
    _In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes,
    _In_opt_ PTOKEN_GROUPS RestrictedDeviceGroups,
    _Out_ PHANDLE NewTokenHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWFINDATOM)(
    _In_reads_bytes_opt_(Length) PWSTR AtomName,
    _In_ ULONG Length,
    _Out_opt_ PRTL_ATOM Atom
    );

typedef
NTSTATUS(
NTAPI*
ZWFLUSHBUFFERSFILE)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock
    );

typedef
NTSTATUS(
NTAPI*
ZWFLUSHBUFFERSFILEEX)(
    _In_ HANDLE FileHandle,
    _In_ ULONG Flags,
    _In_reads_bytes_(ParametersSize) PVOID Parameters,
    _In_ ULONG ParametersSize,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock
    );

typedef
NTSTATUS(
NTAPI*
ZWFLUSHINSTALLUILANGUAGE)(
    _In_ LANGID InstallUILanguage,
    _In_ ULONG SetComittedFlag
    );

typedef
NTSTATUS(
NTAPI*
ZWFLUSHINSTRUCTIONCACHE)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ SIZE_T Length
    );

typedef
NTSTATUS(
NTAPI*
ZWFLUSHKEY)(
    _In_ HANDLE KeyHandle
    );

typedef
VOID(
NTAPI*
ZWFLUSHPROCESSWRITEBUFFERS)(
    VOID
    );

typedef
NTSTATUS(
NTAPI*
ZWFLUSHVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _Out_ struct _IO_STATUS_BLOCK* IoStatus
    );

typedef
NTSTATUS(
NTAPI*
ZWFLUSHWRITEBUFFER)(
    VOID
    );

typedef
NTSTATUS(
NTAPI*
ZWFREEUSERPHYSICALPAGES)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PULONG_PTR NumberOfPages,
    _In_reads_(*NumberOfPages) PULONG_PTR UserPfnArray
    );

typedef
NTSTATUS(
NTAPI*
ZWFREEVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
    );

typedef
NTSTATUS(
NTAPI*
ZWFREEZEREGISTRY)(
    _In_ ULONG TimeOutInSeconds
    );

typedef
NTSTATUS(
NTAPI*
ZWFREEZETRANSACTIONS)(
    _In_ PLARGE_INTEGER FreezeTimeout,
    _In_ PLARGE_INTEGER ThawTimeout
    );

typedef
NTSTATUS(
NTAPI*
ZWFSCONTROLFILE)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG FsControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength
    );

typedef
NTSTATUS(
NTAPI*
ZWGETCACHEDSIGNINGLEVEL)(
    _In_ HANDLE File,
    _Out_ PULONG Flags,
    _Out_ PSE_SIGNING_LEVEL SigningLevel,
    _Out_writes_bytes_to_opt_(*ThumbprintSize, *ThumbprintSize) PUCHAR Thumbprint,
    _Inout_opt_ PULONG ThumbprintSize,
    _Out_opt_ PULONG ThumbprintAlgorithm
    );

typedef
NTSTATUS(
NTAPI*
ZWGETCOMPLETEWNFSTATESUBSCRIPTION)(
    _In_opt_ PWNF_STATE_NAME OldDescriptorStateName,
    _In_opt_ ULONG64 *OldSubscriptionId,
    _In_opt_ ULONG OldDescriptorEventMask,
    _In_opt_ ULONG OldDescriptorStatus,
    _Out_writes_bytes_(DescriptorSize) PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
    _In_ ULONG DescriptorSize
    );

typedef
NTSTATUS(
NTAPI*
ZWGETCONTEXTTHREAD)(
    _In_ HANDLE ThreadHandle,
    _Inout_ PCONTEXT ThreadContext
    );

typedef
ULONG(
NTAPI*
ZWGETCURRENTPROCESSORNUMBER)(
    VOID
    );

typedef
ULONG(
NTAPI*
ZWGETCURRENTPROCESSORNUMBEREX)(
    _Out_opt_ PPROCESSOR_NUMBER ProcessorNumber
    );

typedef
NTSTATUS(
NTAPI*
ZWGETDEVICEPOWERSTATE)(
    _In_ HANDLE Device,
    _Out_ PDEVICE_POWER_STATE State
    );

typedef
NTSTATUS(
NTAPI*
ZWGETMUIREGISTRYINFO)(
    _In_ ULONG Flags,
    _Inout_ PULONG DataSize,
    _Out_ PVOID Data
    );

typedef
NTSTATUS(
NTAPI*
ZWGETNEXTPROCESS)(
    _In_opt_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Flags,
    _Out_ PHANDLE NewProcessHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWGETNEXTTHREAD)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Flags,
    _Out_ PHANDLE NewThreadHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWGETNLSSECTIONPTR)(
    _In_ ULONG SectionType,
    _In_ ULONG SectionData,
    _In_ PVOID ContextData,
    _Out_ PVOID *SectionPointer,
    _Out_ PULONG SectionSize
    );

typedef
NTSTATUS(
NTAPI*
ZWGETNOTIFICATIONRESOURCEMANAGER)(
    _In_ HANDLE ResourceManagerHandle,
    _Out_ PTRANSACTION_NOTIFICATION TransactionNotification,
    _In_ ULONG NotificationLength,
    _In_opt_ PLARGE_INTEGER Timeout,
    _Out_opt_ PULONG ReturnLength,
    _In_ ULONG Asynchronous,
    _In_opt_ ULONG_PTR AsynchronousContext
    );

typedef
NTSTATUS(
NTAPI*
ZWGETPLUGPLAYEVENT)(
    _In_ HANDLE EventHandle,
    _In_opt_ PVOID Context,
    _Out_writes_bytes_(EventBufferSize) PPLUGPLAY_EVENT_BLOCK EventBlock,
    _In_ ULONG EventBufferSize
    );

typedef
NTSTATUS(
NTAPI*
ZWGETWRITEWATCH)(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _Out_writes_(*EntriesInUserAddressArray) PVOID *UserAddressArray,
    _Inout_ PULONG_PTR EntriesInUserAddressArray,
    _Out_ PULONG Granularity
    );

typedef
NTSTATUS(
NTAPI*
ZWIMPERSONATEANONYMOUSTOKEN)(
    _In_ HANDLE ThreadHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWIMPERSONATECLIENTOFPORT)(
    _In_ HANDLE PortHandle,
    _In_ PPORT_MESSAGE Message
    );

typedef
NTSTATUS(
NTAPI*
ZWIMPERSONATETHREAD)(
    _In_ HANDLE ServerThreadHandle,
    _In_ HANDLE ClientThreadHandle,
    _In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos
    );

typedef
NTSTATUS(
NTAPI*
ZWINITIALIZEENCLAVE)(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_reads_bytes_(EnclaveInformationLength) PVOID EnclaveInformation,
    _In_ ULONG EnclaveInformationLength,
    _Out_opt_ PULONG EnclaveError
    );

typedef
NTSTATUS(
NTAPI*
ZWINITIALIZENLSFILES)(
    _Out_ PVOID *BaseAddress,
    _Out_ PLCID DefaultLocaleId,
    _Out_ PLARGE_INTEGER DefaultCasingTableSize
    );

typedef
NTSTATUS(
NTAPI*
ZWINITIALIZEREGISTRY)(
    _In_ USHORT BootCondition
    );

typedef
NTSTATUS(
NTAPI*
ZWINITIATEPOWERACTION)(
    _In_ POWER_ACTION SystemAction,
    _In_ SYSTEM_POWER_STATE LightestSystemState,
    _In_ ULONG Flags, // POWER_ACTION_* flags
    _In_ BOOLEAN Asynchronous
    );

typedef
NTSTATUS(
NTAPI*
ZWISPROCESSINJOB)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ HANDLE JobHandle
    );

typedef
BOOLEAN(
NTAPI*
ZWISSYSTEMRESUMEAUTOMATIC)(
    VOID
    );

typedef
NTSTATUS(
NTAPI*
ZWISUILANGUAGECOMITTED)(
    VOID
    );

typedef
NTSTATUS(
NTAPI*
ZWLISTENPORT)(
    _In_ HANDLE PortHandle,
    _Out_ PPORT_MESSAGE ConnectionRequest
    );

typedef
NTSTATUS(
NTAPI*
ZWLOADDRIVER)(
    _In_ PUNICODE_STRING DriverServiceName
    );

typedef
NTSTATUS(
NTAPI*
ZWLOADENCLAVEDATA)(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _In_ ULONG Protect,
    _In_reads_bytes_(PageInformationLength) PVOID PageInformation,
    _In_ ULONG PageInformationLength,
    _Out_opt_ PSIZE_T NumberOfBytesWritten,
    _Out_opt_ PULONG EnclaveError
    );

typedef
NTSTATUS(
NTAPI*
ZWLOADKEY)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ POBJECT_ATTRIBUTES SourceFile
    );

typedef
NTSTATUS(
NTAPI*
ZWLOADKEY2)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ POBJECT_ATTRIBUTES SourceFile,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
ZWLOADKEY3)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ POBJECT_ATTRIBUTES SourceFile,
    _In_ ULONG Flags,
    _In_reads_(LoadEntryCount) PKEY_LOAD_ENTRY LoadEntries,
    _In_ ULONG LoadEntryCount,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE RootHandle,
    _Reserved_ PVOID Reserved
    );

typedef
NTSTATUS(
NTAPI*
ZWLOADKEYEX)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ POBJECT_ATTRIBUTES SourceFile,
    _In_ ULONG Flags,
    _In_opt_ HANDLE TrustClassKey, // this and below were added on Win10
    _In_opt_ HANDLE Event,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE RootHandle,
    _Reserved_ PVOID Reserved // previously PIO_STATUS_BLOCK
    );

typedef
NTSTATUS(
NTAPI*
ZWLOCKFILE)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ PLARGE_INTEGER ByteOffset,
    _In_ PLARGE_INTEGER Length,
    _In_ ULONG Key,
    _In_ BOOLEAN FailImmediately,
    _In_ BOOLEAN ExclusiveLock
    );

typedef
NTSTATUS(
NTAPI*
ZWLOCKPRODUCTACTIVATIONKEYS)(
    _Inout_opt_ ULONG *pPrivateVer,
    _Out_opt_ ULONG *pSafeMode
    );

typedef
NTSTATUS(
NTAPI*
ZWLOCKREGISTRYKEY)(
    _In_ HANDLE KeyHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWLOCKVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG MapType
    );

typedef
NTSTATUS(
NTAPI*
ZWMAKEPERMANENTOBJECT)(
    _In_ HANDLE Handle
    );

typedef
NTSTATUS(
NTAPI*
ZWMAKETEMPORARYOBJECT)(
    _In_ HANDLE Handle
    );

typedef
NTSTATUS(
NTAPI*
ZWMANAGEPARTITION)(
    _In_ HANDLE TargetHandle,
    _In_opt_ HANDLE SourceHandle,
    _In_ PARTITION_INFORMATION_CLASS PartitionInformationClass,
    _Inout_updates_bytes_(PartitionInformationLength) PVOID PartitionInformation,
    _In_ ULONG PartitionInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWMAPCMFMODULE)(
    _In_ ULONG What,
    _In_ ULONG Index,
    _Out_opt_ PULONG CacheIndexOut,
    _Out_opt_ PULONG CacheFlagsOut,
    _Out_opt_ PULONG ViewSizeOut,
    _Out_opt_ PVOID *BaseAddress
    );

typedef
NTSTATUS(
NTAPI*
ZWMAPUSERPHYSICALPAGES)(
    _In_ PVOID VirtualAddress,
    _In_ ULONG_PTR NumberOfPages,
    _In_reads_opt_(NumberOfPages) PULONG_PTR UserPfnArray
    );

typedef
NTSTATUS(
NTAPI*
ZWMAPUSERPHYSICALPAGESSCATTER)(
    _In_reads_(NumberOfPages) PVOID *VirtualAddresses,
    _In_ ULONG_PTR NumberOfPages,
    _In_reads_opt_(NumberOfPages) PULONG_PTR UserPfnArray
    );

typedef
NTSTATUS(
NTAPI*
ZWMAPVIEWOFSECTION)(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
    );

typedef
NTSTATUS(
NTAPI*
ZWMODIFYBOOTENTRY)(
    _In_ PBOOT_ENTRY BootEntry
    );

typedef
NTSTATUS(
NTAPI*
ZWMODIFYDRIVERENTRY)(
    _In_ PEFI_DRIVER_ENTRY DriverEntry
    );

typedef
NTSTATUS(
NTAPI*
ZWNOTIFYCHANGEDIRECTORYFILE)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer, // FILE_NOTIFY_INFORMATION
    _In_ ULONG Length,
    _In_ ULONG CompletionFilter,
    _In_ BOOLEAN WatchTree
    );

typedef
NTSTATUS(
NTAPI*
ZWNOTIFYCHANGEDIRECTORYFILEEX)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ ULONG CompletionFilter,
    _In_ BOOLEAN WatchTree,
    _In_opt_ DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass
    );

typedef
NTSTATUS(
NTAPI*
ZWNOTIFYCHANGEKEY)(
    _In_ HANDLE KeyHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG CompletionFilter,
    _In_ BOOLEAN WatchTree,
    _Out_writes_bytes_opt_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _In_ BOOLEAN Asynchronous
    );

typedef
NTSTATUS(
NTAPI*
ZWNOTIFYCHANGEMULTIPLEKEYS)(
    _In_ HANDLE MasterKeyHandle,
    _In_opt_ ULONG Count,
    _In_reads_opt_(Count) OBJECT_ATTRIBUTES SubordinateObjects[],
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG CompletionFilter,
    _In_ BOOLEAN WatchTree,
    _Out_writes_bytes_opt_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _In_ BOOLEAN Asynchronous
    );

typedef
NTSTATUS(
NTAPI*
ZWNOTIFYCHANGESESSION)(
    _In_ HANDLE SessionHandle,
    _In_ ULONG ChangeSequenceNumber,
    _In_ PLARGE_INTEGER ChangeTimeStamp,
    _In_ IO_SESSION_EVENT Event,
    _In_ IO_SESSION_STATE NewState,
    _In_ IO_SESSION_STATE PreviousState,
    _In_reads_bytes_opt_(PayloadSize) PVOID Payload,
    _In_ ULONG PayloadSize
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENDIRECTORYOBJECT)(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENENLISTMENT)(
    _Out_ PHANDLE EnlistmentHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE ResourceManagerHandle,
    _In_ LPGUID EnlistmentGuid,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENEVENT)(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENEVENTPAIR)(
    _Out_ PHANDLE EventPairHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENFILE)(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG OpenOptions
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENIOCOMPLETION)(
    _Out_ PHANDLE IoCompletionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENJOBOBJECT)(
    _Out_ PHANDLE JobHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENKEY)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENKEYEDEVENT)(
    _Out_ PHANDLE KeyedEventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENKEYEX)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG OpenOptions
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENKEYTRANSACTED)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE TransactionHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENKEYTRANSACTEDEX)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG OpenOptions,
    _In_ HANDLE TransactionHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENMUTANT)(
    _Out_ PHANDLE MutantHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENOBJECTAUDITALARM)(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ PUNICODE_STRING ObjectTypeName,
    _In_ PUNICODE_STRING ObjectName,
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ HANDLE ClientToken,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ACCESS_MASK GrantedAccess,
    _In_opt_ PPRIVILEGE_SET Privileges,
    _In_ BOOLEAN ObjectCreation,
    _In_ BOOLEAN AccessGranted,
    _Out_ PBOOLEAN GenerateOnClose
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENPARTITION)(
    _Out_ PHANDLE PartitionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
ZWOPENPRIVATENAMESPACE)(
    _Out_ PHANDLE NamespaceHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor
    );
#endif

typedef
NTSTATUS(
NTAPI*
ZWOPENPROCESS)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENPROCESSTOKEN)(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE TokenHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENPROCESSTOKENEX)(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _Out_ PHANDLE TokenHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENRESOURCEMANAGER)(
    _Out_ PHANDLE ResourceManagerHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE TmHandle,
    _In_opt_ LPGUID ResourceManagerGuid,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENSECTION)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENSEMAPHORE)(
    _Out_ PHANDLE SemaphoreHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENSESSION)(
    _Out_ PHANDLE SessionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENSYMBOLICLINKOBJECT)(
    _Out_ PHANDLE LinkHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENTHREAD)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENTHREADTOKEN)(
    _In_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN OpenAsSelf,
    _Out_ PHANDLE TokenHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENTHREADTOKENEX)(
    _In_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN OpenAsSelf,
    _In_ ULONG HandleAttributes,
    _Out_ PHANDLE TokenHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENTIMER)(
    _Out_ PHANDLE TimerHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENTRANSACTION)(
    _Out_ PHANDLE TransactionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ LPGUID Uow,
    _In_opt_ HANDLE TmHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWOPENTRANSACTIONMANAGER)(
    _Out_ PHANDLE TmHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PUNICODE_STRING LogFileName,
    _In_opt_ LPGUID TmIdentity,
    _In_opt_ ULONG OpenOptions
    );

typedef
NTSTATUS(
NTAPI*
ZWPLUGPLAYCONTROL)(
    _In_ PLUGPLAY_CONTROL_CLASS PnPControlClass,
    _Inout_updates_bytes_(PnPControlDataLength) PVOID PnPControlData,
    _In_ ULONG PnPControlDataLength
    );

typedef
NTSTATUS(
NTAPI*
ZWPOWERINFORMATION)(
    _In_ POWER_INFORMATION_LEVEL InformationLevel,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength
    );

typedef
NTSTATUS(
NTAPI*
ZWPREPARECOMPLETE)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );

typedef
NTSTATUS(
NTAPI*
ZWPREPAREENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );

typedef
NTSTATUS(
NTAPI*
ZWPREPREPARECOMPLETE)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );

typedef
NTSTATUS(
NTAPI*
ZWPREPREPAREENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );

typedef
NTSTATUS(
NTAPI*
ZWPRIVILEGECHECK)(
    _In_ HANDLE ClientToken,
    _Inout_ PPRIVILEGE_SET RequiredPrivileges,
    _Out_ PBOOLEAN Result
    );

typedef
NTSTATUS(
NTAPI*
ZWPRIVILEGEDSERVICEAUDITALARM)(
    _In_ PUNICODE_STRING SubsystemName,
    _In_ PUNICODE_STRING ServiceName,
    _In_ HANDLE ClientToken,
    _In_ PPRIVILEGE_SET Privileges,
    _In_ BOOLEAN AccessGranted
    );

typedef
NTSTATUS(
NTAPI*
ZWPRIVILEGEOBJECTAUDITALARM)(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ HANDLE ClientToken,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PPRIVILEGE_SET Privileges,
    _In_ BOOLEAN AccessGranted
    );

typedef
NTSTATUS(
NTAPI*
ZWPROPAGATIONCOMPLETE)(
    _In_ HANDLE ResourceManagerHandle,
    _In_ ULONG RequestCookie,
    _In_ ULONG BufferLength,
    _In_ PVOID Buffer
    );

typedef
NTSTATUS(
NTAPI*
ZWPROPAGATIONFAILED)(
    _In_ HANDLE ResourceManagerHandle,
    _In_ ULONG RequestCookie,
    _In_ NTSTATUS PropStatus
    );

typedef
NTSTATUS(
NTAPI*
ZWPROTECTVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
    );

typedef
NTSTATUS(
NTAPI*
ZWPULSEEVENT)(
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYATTRIBUTESFILE)(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PFILE_BASIC_INFORMATION FileInformation
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYBOOTENTRYORDER)(
    _Out_writes_opt_(*Count) PULONG Ids,
    _Inout_ PULONG Count
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYBOOTOPTIONS)(
    _Out_writes_bytes_opt_(*BootOptionsLength) PBOOT_OPTIONS BootOptions,
    _Inout_ PULONG BootOptionsLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYDEBUGFILTERSTATE)(
    _In_ ULONG ComponentId,
    _In_ ULONG Level
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYDEFAULTLOCALE)(
    _In_ BOOLEAN UserProfile,
    _Out_ PLCID DefaultLocaleId
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYDEFAULTUILANGUAGE)(
    _Out_ LANGID *DefaultUILanguageId
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYDIRECTORYFILE)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_opt_ PUNICODE_STRING FileName,
    _In_ BOOLEAN RestartScan
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYDIRECTORYFILEEX)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass,
    _In_ ULONG QueryFlags,
    _In_opt_ PUNICODE_STRING FileName
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYDIRECTORYOBJECT)(
    _In_ HANDLE DirectoryHandle,
    _Out_writes_bytes_opt_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYDRIVERENTRYORDER)(
    _Out_writes_opt_(*Count) PULONG Ids,
    _Inout_ PULONG Count
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYEAFILE)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_reads_bytes_opt_(EaListLength) PVOID EaList,
    _In_ ULONG EaListLength,
    _In_opt_ PULONG EaIndex,
    _In_ BOOLEAN RestartScan
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYEVENT)(
    _In_ HANDLE EventHandle,
    _In_ EVENT_INFORMATION_CLASS EventInformationClass,
    _Out_writes_bytes_(EventInformationLength) PVOID EventInformation,
    _In_ ULONG EventInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYFULLATTRIBUTESFILE)(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PFILE_NETWORK_OPEN_INFORMATION FileInformation
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINFORMATIONATOM)(
    _In_ RTL_ATOM Atom,
    _In_ ATOM_INFORMATION_CLASS AtomInformationClass,
    _Out_writes_bytes_(AtomInformationLength) PVOID AtomInformation,
    _In_ ULONG AtomInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINFORMATIONBYNAME)(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINFORMATIONENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_ ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    _Out_writes_bytes_(EnlistmentInformationLength) PVOID EnlistmentInformation,
    _In_ ULONG EnlistmentInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINFORMATIONFILE)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINFORMATIONJOBOBJECT)(
    _In_opt_ HANDLE JobHandle,
    _In_ JOBOBJECTINFOCLASS JobObjectInformationClass,
    _Out_writes_bytes_(JobObjectInformationLength) PVOID JobObjectInformation,
    _In_ ULONG JobObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINFORMATIONPORT)(
    _In_ HANDLE PortHandle,
    _In_ PORT_INFORMATION_CLASS PortInformationClass,
    _Out_writes_bytes_to_(Length, *ReturnLength) PVOID PortInformation,
    _In_ ULONG Length,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINFORMATIONPROCESS)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINFORMATIONRESOURCEMANAGER)(
    _In_ HANDLE ResourceManagerHandle,
    _In_ RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    _Out_writes_bytes_(ResourceManagerInformationLength) PVOID ResourceManagerInformation,
    _In_ ULONG ResourceManagerInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINFORMATIONTHREAD)(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINFORMATIONTOKEN)(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength) PVOID TokenInformation,
    _In_ ULONG TokenInformationLength,
    _Out_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINFORMATIONTRANSACTION)(
    _In_ HANDLE TransactionHandle,
    _In_ TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    _Out_writes_bytes_(TransactionInformationLength) PVOID TransactionInformation,
    _In_ ULONG TransactionInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINFORMATIONTRANSACTIONMANAGER)(
    _In_ HANDLE TransactionManagerHandle,
    _In_ TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    _Out_writes_bytes_(TransactionManagerInformationLength) PVOID TransactionManagerInformation,
    _In_ ULONG TransactionManagerInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINFORMATIONWORKERFACTORY)(
    _In_ HANDLE WorkerFactoryHandle,
    _In_ WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    _Out_writes_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
    _In_ ULONG WorkerFactoryInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINSTALLUILANGUAGE)(
    _Out_ LANGID *InstallUILanguageId
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYINTERVALPROFILE)(
    _In_ KPROFILE_SOURCE ProfileSource,
    _Out_ PULONG Interval
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYIOCOMPLETION)(
    _In_ HANDLE IoCompletionHandle,
    _In_ IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
    _Out_writes_bytes_(IoCompletionInformationLength) PVOID IoCompletionInformation,
    _In_ ULONG IoCompletionInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYKEY)(
    _In_ HANDLE KeyHandle,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYLICENSEVALUE)(
    _In_ PUNICODE_STRING ValueName,
    _Out_opt_ PULONG Type,
    _Out_writes_bytes_to_opt_(DataSize, *ResultDataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PULONG ResultDataSize
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYMULTIPLEVALUEKEY)(
    _In_ HANDLE KeyHandle,
    _Inout_updates_(EntryCount) PKEY_VALUE_ENTRY ValueEntries,
    _In_ ULONG EntryCount,
    _Out_writes_bytes_(*BufferLength) PVOID ValueBuffer,
    _Inout_ PULONG BufferLength,
    _Out_opt_ PULONG RequiredBufferLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYMUTANT)(
    _In_ HANDLE MutantHandle,
    _In_ MUTANT_INFORMATION_CLASS MutantInformationClass,
    _Out_writes_bytes_(MutantInformationLength) PVOID MutantInformation,
    _In_ ULONG MutantInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYOBJECT)(
    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYOPENSUBKEYS)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _Out_ PULONG HandleCount
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYOPENSUBKEYSEX)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_opt_(BufferLength) PVOID Buffer,
    _Out_ PULONG RequiredSize
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYPERFORMANCECOUNTER)(
    _Out_ PLARGE_INTEGER PerformanceCounter,
    _Out_opt_ PLARGE_INTEGER PerformanceFrequency
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYQUOTAINFORMATIONFILE)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_reads_bytes_opt_(SidListLength) PVOID SidList,
    _In_ ULONG SidListLength,
    _In_opt_ PSID StartSid,
    _In_ BOOLEAN RestartScan
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYSECTION)(
    _In_ HANDLE SectionHandle,
    _In_ SECTION_INFORMATION_CLASS SectionInformationClass,
    _Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation,
    _In_ SIZE_T SectionInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYSECURITYATTRIBUTESTOKEN)(
    _In_ HANDLE TokenHandle,
    _In_reads_opt_(NumberOfAttributes) PUNICODE_STRING Attributes,
    _In_ ULONG NumberOfAttributes,
    _Out_writes_bytes_(Length) PVOID Buffer, // PTOKEN_SECURITY_ATTRIBUTES_INFORMATION
    _In_ ULONG Length,
    _Out_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYSECURITYOBJECT)(
    _In_ HANDLE Handle,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _Out_writes_bytes_opt_(Length) PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG Length,
    _Out_ PULONG LengthNeeded
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYSEMAPHORE)(
    _In_ HANDLE SemaphoreHandle,
    _In_ SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
    _Out_writes_bytes_(SemaphoreInformationLength) PVOID SemaphoreInformation,
    _In_ ULONG SemaphoreInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYSYMBOLICLINKOBJECT)(
    _In_ HANDLE LinkHandle,
    _Inout_ PUNICODE_STRING LinkTarget,
    _Out_opt_ PULONG ReturnedLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYSYSTEMENVIRONMENTVALUE)(
    _In_ PUNICODE_STRING VariableName,
    _Out_writes_bytes_(ValueLength) PWSTR VariableValue,
    _In_ USHORT ValueLength,
    _Out_opt_ PUSHORT ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYSYSTEMENVIRONMENTVALUEEX)(
    _In_ PUNICODE_STRING VariableName,
    _In_ LPGUID VendorGuid,
    _Out_writes_bytes_opt_(*ValueLength) PVOID Value,
    _Inout_ PULONG ValueLength,
    _Out_opt_ PULONG Attributes // EFI_VARIABLE_*
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYSYSTEMINFORMATION)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYSYSTEMINFORMATIONEX)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYSYSTEMTIME)(
    _Out_ PLARGE_INTEGER SystemTime
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYTIMER)(
    _In_ HANDLE TimerHandle,
    _In_ TIMER_INFORMATION_CLASS TimerInformationClass,
    _Out_writes_bytes_(TimerInformationLength) PVOID TimerInformation,
    _In_ ULONG TimerInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYTIMERRESOLUTION)(
    _Out_ PULONG MaximumTime,
    _Out_ PULONG MinimumTime,
    _Out_ PULONG CurrentTime
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYVALUEKEY)(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYVOLUMEINFORMATIONFILE)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FsInformation,
    _In_ ULONG Length,
    _In_ FSINFOCLASS FsInformationClass
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYWNFSTATEDATA)(
    _In_ PCWNF_STATE_NAME StateName,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ const VOID *ExplicitScope,
    _Out_ PWNF_CHANGE_STAMP ChangeStamp,
    _Out_writes_bytes_to_opt_(*BufferSize, *BufferSize) PVOID Buffer,
    _Inout_ PULONG BufferSize
    );

typedef
NTSTATUS(
NTAPI*
ZWQUERYWNFSTATENAMEINFORMATION)(
    _In_ PCWNF_STATE_NAME StateName,
    _In_ WNF_STATE_NAME_INFORMATION NameInfoClass,
    _In_opt_ const VOID *ExplicitScope,
    _Out_writes_bytes_(InfoBufferSize) PVOID InfoBuffer,
    _In_ ULONG InfoBufferSize
    );

typedef
NTSTATUS(
NTAPI*
ZWQUEUEAPCTHREAD)(
    _In_ HANDLE ThreadHandle,
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );

typedef
NTSTATUS(
NTAPI*
ZWQUEUEAPCTHREADEX)(
    _In_ HANDLE ThreadHandle,
    _In_opt_ HANDLE ReserveHandle, // NtAllocateReserveObject
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );

#if (PHNT_VERSION >= PHNT_WIN11)
typedef
NTSTATUS(
NTAPI*
ZWQUEUEAPCTHREADEX2)(
    _In_ HANDLE ThreadHandle,
    _In_opt_ HANDLE ReserveHandle, // NtAllocateReserveObject
    _In_ QUEUE_USER_APC_FLAGS ApcFlags,
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );
#endif

typedef
NTSTATUS(
NTAPI*
ZWRAISEEXCEPTION)(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord,
    _In_ BOOLEAN FirstChance
    );

typedef
NTSTATUS(
NTAPI*
ZWRAISEHARDERROR)(
    _In_ NTSTATUS ErrorStatus,
    _In_ ULONG NumberOfParameters,
    _In_ ULONG UnicodeStringParameterMask,
    _In_reads_(NumberOfParameters) PULONG_PTR Parameters,
    _In_ ULONG ValidResponseOptions,
    _Out_ PULONG Response
    );

typedef
NTSTATUS(
NTAPI*
ZWREADFILE)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
    );

typedef
NTSTATUS(
NTAPI*
ZWREADFILESCATTER)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ PFILE_SEGMENT_ELEMENT SegmentArray,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
    );

typedef
NTSTATUS(
NTAPI*
ZWREADONLYENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );

typedef
NTSTATUS(
NTAPI*
ZWREADREQUESTDATA)(
    _In_ HANDLE PortHandle,
    _In_ PPORT_MESSAGE Message,
    _In_ ULONG DataEntryIndex,
    _Out_writes_bytes_to_(BufferSize, *NumberOfBytesRead) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead
    );

typedef
NTSTATUS(
NTAPI*
ZWREADVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead
    );

typedef
NTSTATUS(
NTAPI*
ZWRECOVERENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PVOID EnlistmentKey
    );

typedef
NTSTATUS(
NTAPI*
ZWRECOVERRESOURCEMANAGER)(
    _In_ HANDLE ResourceManagerHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWRECOVERTRANSACTIONMANAGER)(
    _In_ HANDLE TransactionManagerHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWREGISTERPROTOCOLADDRESSINFORMATION)(
    _In_ HANDLE ResourceManager,
    _In_ PCRM_PROTOCOL_ID ProtocolId,
    _In_ ULONG ProtocolInformationSize,
    _In_ PVOID ProtocolInformation,
    _In_opt_ ULONG CreateOptions
    );

typedef
NTSTATUS(
NTAPI*
ZWREGISTERTHREADTERMINATEPORT)(
    _In_ HANDLE PortHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWRELEASECMFVIEWOWNERSHIP)(
    VOID
    );

typedef
NTSTATUS(
NTAPI*
ZWRELEASEKEYEDEVENT)(
    _In_ HANDLE KeyedEventHandle,
    _In_ PVOID KeyValue,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
NTSTATUS(
NTAPI*
ZWRELEASEMUTANT)(
    _In_ HANDLE MutantHandle,
    _Out_opt_ PLONG PreviousCount
    );

typedef
NTSTATUS(
NTAPI*
ZWRELEASESEMAPHORE)(
    _In_ HANDLE SemaphoreHandle,
    _In_ LONG ReleaseCount,
    _Out_opt_ PLONG PreviousCount
    );

typedef
NTSTATUS(
NTAPI*
ZWRELEASEWORKERFACTORYWORKER)(
    _In_ HANDLE WorkerFactoryHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWREMOVEIOCOMPLETION)(
    _In_ HANDLE IoCompletionHandle,
    _Out_ PVOID *KeyContext,
    _Out_ PVOID *ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
NTSTATUS(
NTAPI*
ZWREMOVEIOCOMPLETIONEX)(
    _In_ HANDLE IoCompletionHandle,
    _Out_writes_to_(Count, *NumEntriesRemoved) PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
    _In_ ULONG Count,
    _Out_ PULONG NumEntriesRemoved,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_ BOOLEAN Alertable
    );

typedef
NTSTATUS(
NTAPI*
ZWREMOVEPROCESSDEBUG)(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWRENAMEKEY)(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING NewName
    );

typedef
NTSTATUS(
NTAPI*
ZWRENAMETRANSACTIONMANAGER)(
    _In_ PUNICODE_STRING LogFileName,
    _In_ LPGUID ExistingTransactionManagerGuid
    );

typedef
NTSTATUS(
NTAPI*
ZWREPLACEKEY)(
    _In_ POBJECT_ATTRIBUTES NewFile,
    _In_ HANDLE TargetHandle,
    _In_ POBJECT_ATTRIBUTES OldFile
    );

typedef
NTSTATUS(
NTAPI*
ZWREPLACEPARTITIONUNIT)(
    _In_ PUNICODE_STRING TargetInstancePath,
    _In_ PUNICODE_STRING SpareInstancePath,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
ZWREPLYPORT)(
    _In_ HANDLE PortHandle,
    _In_reads_bytes_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE ReplyMessage
    );

typedef
NTSTATUS(
NTAPI*
ZWREPLYWAITRECEIVEPORT)(
    _In_ HANDLE PortHandle,
    _Out_opt_ PVOID *PortContext,
    _In_reads_bytes_opt_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE ReplyMessage,
    _Out_ PPORT_MESSAGE ReceiveMessage
    );

typedef
NTSTATUS(
NTAPI*
ZWREPLYWAITRECEIVEPORTEX)(
    _In_ HANDLE PortHandle,
    _Out_opt_ PVOID *PortContext,
    _In_reads_bytes_opt_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE ReplyMessage,
    _Out_ PPORT_MESSAGE ReceiveMessage,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
NTSTATUS(
NTAPI*
ZWREPLYWAITREPLYPORT)(
    _In_ HANDLE PortHandle,
    _Inout_ PPORT_MESSAGE ReplyMessage
    );

typedef
NTSTATUS(
NTAPI*
ZWREQUESTPORT)(
    _In_ HANDLE PortHandle,
    _In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE RequestMessage
    );

typedef
NTSTATUS(
NTAPI*
ZWREQUESTWAITREPLYPORT)(
    _In_ HANDLE PortHandle,
    _In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE RequestMessage,
    _Out_ PPORT_MESSAGE ReplyMessage
    );

typedef
NTSTATUS(
NTAPI*
ZWREQUESTWAKEUPLATENCY)(
    _In_ LATENCY_TIME latency
    );

typedef
NTSTATUS(
NTAPI*
ZWRESETEVENT)(
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState
    );

typedef
NTSTATUS(
NTAPI*
ZWRESETWRITEWATCH)(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize
    );

typedef
NTSTATUS(
NTAPI*
ZWRESTOREKEY)(
    _In_ HANDLE KeyHandle,
    _In_ HANDLE FileHandle,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
ZWRESUMEPROCESS)(
    _In_ HANDLE ProcessHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWRESUMETHREAD)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );

typedef
NTSTATUS(
NTAPI*
ZWREVERTCONTAINERIMPERSONATION)(
    VOID
    );

typedef
NTSTATUS(
NTAPI*
ZWROLLBACKCOMPLETE)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );

typedef
NTSTATUS(
NTAPI*
ZWROLLBACKENLISTMENT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );

typedef
NTSTATUS(
NTAPI*
ZWROLLBACKTRANSACTION)(
    _In_ HANDLE TransactionHandle,
    _In_ BOOLEAN Wait
    );

typedef
NTSTATUS(
NTAPI*
ZWROLLFORWARDTRANSACTIONMANAGER)(
    _In_ HANDLE TransactionManagerHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );

typedef
NTSTATUS(
NTAPI*
ZWSAVEKEY)(
    _In_ HANDLE KeyHandle,
    _In_ HANDLE FileHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWSAVEKEYEX)(
    _In_ HANDLE KeyHandle,
    _In_ HANDLE FileHandle,
    _In_ ULONG Format
    );

typedef
NTSTATUS(
NTAPI*
ZWSAVEMERGEDKEYS)(
    _In_ HANDLE HighPrecedenceKeyHandle,
    _In_ HANDLE LowPrecedenceKeyHandle,
    _In_ HANDLE FileHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWSECURECONNECTPORT)(
    _Out_ PHANDLE PortHandle,
    _In_ PUNICODE_STRING PortName,
    _In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    _Inout_opt_ PPORT_VIEW ClientView,
    _In_opt_ PSID RequiredServerSid,
    _Inout_opt_ PREMOTE_PORT_VIEW ServerView,
    _Out_opt_ PULONG MaxMessageLength,
    _Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
    _Inout_opt_ PULONG ConnectionInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSERIALIZEBOOT)(
    VOID
    );

typedef
NTSTATUS(
NTAPI*
ZWSETBOOTENTRYORDER)(
    _In_reads_(Count) PULONG Ids,
    _In_ ULONG Count
    );

typedef
NTSTATUS(
NTAPI*
ZWSETBOOTOPTIONS)(
    _In_ PBOOT_OPTIONS BootOptions,
    _In_ ULONG FieldsToChange
    );

typedef
NTSTATUS(
NTAPI*
ZWSETCACHEDSIGNINGLEVEL)(
    _In_ ULONG Flags,
    _In_ SE_SIGNING_LEVEL InputSigningLevel,
    _In_reads_(SourceFileCount) PHANDLE SourceFiles,
    _In_ ULONG SourceFileCount,
    _In_opt_ HANDLE TargetFile
    );

typedef
NTSTATUS(
NTAPI*
ZWSETCONTEXTTHREAD)(
    _In_ HANDLE ThreadHandle,
    _In_ PCONTEXT ThreadContext
    );

typedef
NTSTATUS(
NTAPI*
ZWSETDEBUGFILTERSTATE)(
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_ BOOLEAN State
    );

typedef
NTSTATUS(
NTAPI*
ZWSETDEFAULTHARDERRORPORT)(
    _In_ HANDLE DefaultHardErrorPort
    );

typedef
NTSTATUS(
NTAPI*
ZWSETDEFAULTLOCALE)(
    _In_ BOOLEAN UserProfile,
    _In_ LCID DefaultLocaleId
    );

typedef
NTSTATUS(
NTAPI*
ZWSETDEFAULTUILANGUAGE)(
    _In_ LANGID DefaultUILanguageId
    );

typedef
NTSTATUS(
NTAPI*
ZWSETDRIVERENTRYORDER)(
    _In_reads_(Count) PULONG Ids,
    _In_ ULONG Count
    );

typedef
NTSTATUS(
NTAPI*
ZWSETEAFILE)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
    );

typedef
NTSTATUS(
NTAPI*
ZWSETEVENT)(
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState
    );

typedef
NTSTATUS(
NTAPI*
ZWSETEVENTBOOSTPRIORITY)(
    _In_ HANDLE EventHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWSETHIGHEVENTPAIR)(
    _In_ HANDLE EventPairHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWSETHIGHWAITLOWEVENTPAIR)(
    _In_ HANDLE EventPairHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONDEBUGOBJECT)(
    _In_ HANDLE DebugObjectHandle,
    _In_ DEBUGOBJECTINFOCLASS DebugObjectInformationClass,
    _In_ PVOID DebugInformation,
    _In_ ULONG DebugInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONENLISTMENT)(
    _In_opt_ HANDLE EnlistmentHandle,
    _In_ ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    _In_reads_bytes_(EnlistmentInformationLength) PVOID EnlistmentInformation,
    _In_ ULONG EnlistmentInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONFILE)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONJOBOBJECT)(
    _In_ HANDLE JobHandle,
    _In_ JOBOBJECTINFOCLASS JobObjectInformationClass,
    _In_reads_bytes_(JobObjectInformationLength) PVOID JobObjectInformation,
    _In_ ULONG JobObjectInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONKEY)(
    _In_ HANDLE KeyHandle,
    _In_ KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    _In_reads_bytes_(KeySetInformationLength) PVOID KeySetInformation,
    _In_ ULONG KeySetInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONOBJECT)(
    _In_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _In_reads_bytes_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONPROCESS)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONRESOURCEMANAGER)(
    _In_ HANDLE ResourceManagerHandle,
    _In_ RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    _In_reads_bytes_(ResourceManagerInformationLength) PVOID ResourceManagerInformation,
    _In_ ULONG ResourceManagerInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONSYMBOLICLINK)(
    _In_ HANDLE LinkHandle,
    _In_ SYMBOLIC_LINK_INFO_CLASS SymbolicLinkInformationClass,
    _In_reads_bytes_(SymbolicLinkInformationLength) PVOID SymbolicLinkInformation,
    _In_ ULONG SymbolicLinkInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONTHREAD)(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONTOKEN)(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _In_reads_bytes_(TokenInformationLength) PVOID TokenInformation,
    _In_ ULONG TokenInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONTRANSACTION)(
    _In_ HANDLE TransactionHandle,
    _In_ TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    _In_reads_bytes_(TransactionInformationLength) PVOID TransactionInformation,
    _In_ ULONG TransactionInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONTRANSACTIONMANAGER)(
    _In_opt_ HANDLE TmHandle,
    _In_ TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    _In_reads_bytes_(TransactionManagerInformationLength) PVOID TransactionManagerInformation,
    _In_ ULONG TransactionManagerInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _In_ VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
    _In_ ULONG_PTR NumberOfEntries,
    _In_reads_ (NumberOfEntries) PMEMORY_RANGE_ENTRY VirtualAddresses,
    _In_reads_bytes_ (VmInformationLength) PVOID VmInformation,
    _In_ ULONG VmInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINFORMATIONWORKERFACTORY)(
    _In_ HANDLE WorkerFactoryHandle,
    _In_ WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    _In_reads_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
    _In_ ULONG WorkerFactoryInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETINTERVALPROFILE)(
    _In_ ULONG Interval,
    _In_ KPROFILE_SOURCE Source
    );

typedef
NTSTATUS(
NTAPI*
ZWSETIOCOMPLETION)(
    _In_ HANDLE IoCompletionHandle,
    _In_opt_ PVOID KeyContext,
    _In_opt_ PVOID ApcContext,
    _In_ NTSTATUS IoStatus,
    _In_ ULONG_PTR IoStatusInformation
    );

typedef
NTSTATUS(
NTAPI*
ZWSETIOCOMPLETIONEX)(
    _In_ HANDLE IoCompletionHandle,
    _In_ HANDLE IoCompletionPacketHandle,
    _In_opt_ PVOID KeyContext,
    _In_opt_ PVOID ApcContext,
    _In_ NTSTATUS IoStatus,
    _In_ ULONG_PTR IoStatusInformation
    );

typedef
NTSTATUS(
NTAPI*
ZWSETIRTIMER)(
    _In_ HANDLE TimerHandle,
    _In_opt_ PLARGE_INTEGER DueTime
    );

typedef
NTSTATUS(
NTAPI*
ZWSETLDTENTRIES)(
    _In_ ULONG Selector0,
    _In_ ULONG Entry0Low,
    _In_ ULONG Entry0Hi,
    _In_ ULONG Selector1,
    _In_ ULONG Entry1Low,
    _In_ ULONG Entry1Hi
    );

typedef
NTSTATUS(
NTAPI*
ZWSETLOWEVENTPAIR)(
    _In_ HANDLE EventPairHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWSETLOWWAITHIGHEVENTPAIR)(
    _In_ HANDLE EventPairHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWSETQUOTAINFORMATIONFILE)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
    );

typedef
NTSTATUS(
NTAPI*
ZWSETSECURITYOBJECT)(
    _In_ HANDLE Handle,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
    );

typedef
NTSTATUS(
NTAPI*
ZWSETSYSTEMENVIRONMENTVALUE)(
    _In_ PUNICODE_STRING VariableName,
    _In_ PUNICODE_STRING VariableValue
    );

typedef
NTSTATUS(
NTAPI*
ZWSETSYSTEMENVIRONMENTVALUEEX)(
    _In_ PUNICODE_STRING VariableName,
    _In_ LPGUID VendorGuid,
    _In_reads_bytes_opt_(ValueLength) PVOID Value,
    _In_ ULONG ValueLength, // 0 = delete variable
    _In_ ULONG Attributes // EFI_VARIABLE_*
    );

typedef
NTSTATUS(
NTAPI*
ZWSETSYSTEMINFORMATION)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _In_reads_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETSYSTEMPOWERSTATE)(
    _In_ POWER_ACTION SystemAction,
    _In_ SYSTEM_POWER_STATE LightestSystemState,
    _In_ ULONG Flags // POWER_ACTION_* flags
    );

typedef
NTSTATUS(
NTAPI*
ZWSETSYSTEMTIME)(
    _In_opt_ PLARGE_INTEGER SystemTime,
    _Out_opt_ PLARGE_INTEGER PreviousTime
    );

typedef
NTSTATUS(
NTAPI*
ZWSETTHREADEXECUTIONSTATE)(
    _In_ EXECUTION_STATE NewFlags, // ES_* flags
    _Out_ EXECUTION_STATE *PreviousFlags
    );

typedef
NTSTATUS(
NTAPI*
ZWSETTIMER)(
    _In_ HANDLE TimerHandle,
    _In_ PLARGE_INTEGER DueTime,
    _In_opt_ PTIMER_APC_ROUTINE TimerApcRoutine,
    _In_opt_ PVOID TimerContext,
    _In_ BOOLEAN ResumeTimer,
    _In_opt_ LONG Period,
    _Out_opt_ PBOOLEAN PreviousState
    );

typedef
NTSTATUS(
NTAPI*
ZWSETTIMER2)(
    _In_ HANDLE TimerHandle,
    _In_ PLARGE_INTEGER DueTime,
    _In_opt_ PLARGE_INTEGER Period,
    _In_ PT2_SET_PARAMETERS Parameters
    );

typedef
NTSTATUS(
NTAPI*
ZWSETTIMEREX)(
    _In_ HANDLE TimerHandle,
    _In_ TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
    _Inout_updates_bytes_opt_(TimerSetInformationLength) PVOID TimerSetInformation,
    _In_ ULONG TimerSetInformationLength
    );

typedef
NTSTATUS(
NTAPI*
ZWSETTIMERRESOLUTION)(
    _In_ ULONG DesiredTime,
    _In_ BOOLEAN SetResolution,
    _Out_ PULONG ActualTime
    );

typedef
NTSTATUS(
NTAPI*
ZWSETUUIDSEED)(
    _In_ PCHAR Seed
    );

typedef
NTSTATUS(
NTAPI*
ZWSETVALUEKEY)(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_opt_ ULONG TitleIndex,
    _In_ ULONG Type,
    _In_reads_bytes_opt_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    );

typedef
NTSTATUS(
NTAPI*
ZWSETVOLUMEINFORMATIONFILE)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID FsInformation,
    _In_ ULONG Length,
    _In_ FSINFOCLASS FsInformationClass
    );

typedef
NTSTATUS(
NTAPI*
ZWSETWNFPROCESSNOTIFICATIONEVENT)(
    _In_ HANDLE NotificationEvent
    );

typedef
NTSTATUS(
NTAPI*
ZWSHUTDOWNSYSTEM)(
    _In_ SHUTDOWN_ACTION Action
    );

typedef
NTSTATUS(
NTAPI*
ZWSHUTDOWNWORKERFACTORY)(
    _In_ HANDLE WorkerFactoryHandle,
    _Inout_ volatile LONG *PendingWorkerCount
    );

typedef
NTSTATUS(
NTAPI*
ZWSIGNALANDWAITFORSINGLEOBJECT)(
    _In_ HANDLE SignalHandle,
    _In_ HANDLE WaitHandle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
NTSTATUS(
NTAPI*
ZWSINGLEPHASEREJECT)(
    _In_ HANDLE EnlistmentHandle,
    _In_opt_ PLARGE_INTEGER TmVirtualClock
    );

typedef
NTSTATUS(
NTAPI*
ZWSTARTPROFILE)(
    _In_ HANDLE ProfileHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWSTOPPROFILE)(
    _In_ HANDLE ProfileHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWSUBSCRIBEWNFSTATECHANGE)(
    _In_ PCWNF_STATE_NAME StateName,
    _In_opt_ WNF_CHANGE_STAMP ChangeStamp,
    _In_ ULONG EventMask,
    _Out_opt_ PULONG64 SubscriptionId
    );

typedef
NTSTATUS(
NTAPI*
ZWSUSPENDPROCESS)(
    _In_ HANDLE ProcessHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWSUSPENDTHREAD)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );

typedef
NTSTATUS(
NTAPI*
ZWSYSTEMDEBUGCONTROL)(
    _In_ SYSDBG_COMMAND Command,
    _Inout_updates_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWTERMINATEENCLAVE)(
    _In_ PVOID BaseAddress,
    _In_ BOOLEAN WaitForThread
    );

typedef
NTSTATUS(
NTAPI*
ZWTERMINATEJOBOBJECT)(
    _In_ HANDLE JobHandle,
    _In_ NTSTATUS ExitStatus
    );

typedef
NTSTATUS(
NTAPI*
ZWTERMINATEPROCESS)(
    _In_opt_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus
    );

typedef
NTSTATUS(
NTAPI*
ZWTERMINATETHREAD)(
    _In_opt_ HANDLE ThreadHandle,
    _In_ NTSTATUS ExitStatus
    );

typedef
NTSTATUS(
NTAPI*
ZWTESTALERT)(
    VOID
    );

typedef
NTSTATUS(
NTAPI*
ZWTHAWREGISTRY)(
    VOID
    );

typedef
NTSTATUS(
NTAPI*
ZWTHAWTRANSACTIONS)(
    VOID
    );

typedef
NTSTATUS(
NTAPI*
ZWTRACECONTROL)(
    _In_ TRACE_CONTROL_INFORMATION_CLASS TraceInformationClass,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(TraceInformationLength) PVOID TraceInformation,
    _In_ ULONG TraceInformationLength,
    _Out_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
ZWTRACEEVENT)(
    _In_ HANDLE TraceHandle,
    _In_ ULONG Flags,
    _In_ ULONG FieldSize,
    _In_ PVOID Fields
    );

typedef
NTSTATUS(
NTAPI*
ZWTRANSLATEFILEPATH)(
    _In_ PFILE_PATH InputFilePath,
    _In_ ULONG OutputType,
    _Out_writes_bytes_opt_(*OutputFilePathLength) PFILE_PATH OutputFilePath,
    _Inout_opt_ PULONG OutputFilePathLength
    );

typedef
NTSTATUS(
NTAPI*
ZWUMSTHREADYIELD)(
    _In_ PVOID SchedulerParam
    );

typedef
NTSTATUS(
NTAPI*
ZWUNLOADDRIVER)(
    _In_ PUNICODE_STRING DriverServiceName
    );

typedef
NTSTATUS(
NTAPI*
ZWUNLOADKEY)(
    _In_ POBJECT_ATTRIBUTES TargetKey
    );

typedef
NTSTATUS(
NTAPI*
ZWUNLOADKEY2)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
ZWUNLOADKEYEX)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_opt_ HANDLE Event
    );

typedef
NTSTATUS(
NTAPI*
ZWUNLOCKFILE)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ PLARGE_INTEGER ByteOffset,
    _In_ PLARGE_INTEGER Length,
    _In_ ULONG Key
    );

typedef
NTSTATUS(
NTAPI*
ZWUNLOCKVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG MapType
    );

typedef
NTSTATUS(
NTAPI*
ZWUNMAPVIEWOFSECTION)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
    );

typedef
NTSTATUS(
NTAPI*
ZWUNMAPVIEWOFSECTIONEX)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
ZWUNSUBSCRIBEWNFSTATECHANGE)(
    _In_ PCWNF_STATE_NAME StateName
    );

typedef
NTSTATUS(
NTAPI*
ZWUPDATEWNFSTATEDATA)(
    _In_ PCWNF_STATE_NAME StateName,
    _In_reads_bytes_opt_(Length) const VOID *Buffer,
    _In_opt_ ULONG Length,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ const VOID *ExplicitScope,
    _In_ WNF_CHANGE_STAMP MatchingChangeStamp,
    _In_ LOGICAL CheckStamp
    );

typedef
NTSTATUS(
NTAPI*
ZWVDMCONTROL)(
    _In_ VDMSERVICECLASS Service,
    _Inout_ PVOID ServiceData
    );

typedef
NTSTATUS(
NTAPI*
ZWWAITFORALERTBYTHREADID)(
    _In_ PVOID Address,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
NTSTATUS(
NTAPI*
ZWWAITFORDEBUGEVENT)(
    _In_ HANDLE DebugObjectHandle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout,
    _Out_ PDBGUI_WAIT_STATE_CHANGE WaitStateChange
    );

typedef
NTSTATUS(
NTAPI*
ZWWAITFORKEYEDEVENT)(
    _In_ HANDLE KeyedEventHandle,
    _In_ PVOID KeyValue,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
NTSTATUS(
NTAPI*
ZWWAITFORMULTIPLEOBJECTS)(
    _In_ ULONG Count,
    _In_reads_(Count) HANDLE Handles[],
    _In_ WAIT_TYPE WaitType,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
NTSTATUS(
NTAPI*
ZWWAITFORMULTIPLEOBJECTS32)(
    _In_ ULONG Count,
    _In_reads_(Count) LONG Handles[],
    _In_ WAIT_TYPE WaitType,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
NTSTATUS(
NTAPI*
ZWWAITFORSINGLEOBJECT)(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
NTSTATUS(
NTAPI*
ZWWAITFORWORKVIAWORKERFACTORY)(
    _In_ HANDLE WorkerFactoryHandle,
    _Out_ struct _FILE_IO_COMPLETION_INFORMATION *MiniPacket
    );

typedef
NTSTATUS(
NTAPI*
ZWWAITHIGHEVENTPAIR)(
    _In_ HANDLE EventPairHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWWAITLOWEVENTPAIR)(
    _In_ HANDLE EventPairHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWWORKERFACTORYWORKERREADY)(
    _In_ HANDLE WorkerFactoryHandle
    );

typedef
NTSTATUS(
NTAPI*
ZWWRITEFILE)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
    );

typedef
NTSTATUS(
NTAPI*
ZWWRITEFILEGATHER)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ PFILE_SEGMENT_ELEMENT SegmentArray,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
    );

typedef
NTSTATUS(
NTAPI*
ZWWRITEREQUESTDATA)(
    _In_ HANDLE PortHandle,
    _In_ PPORT_MESSAGE Message,
    _In_ ULONG DataEntryIndex,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
    );

typedef
NTSTATUS(
NTAPI*
ZWWRITEVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
    );

typedef
NTSTATUS(
NTAPI*
ZWYIELDEXECUTION)(
    VOID
    );

#endif
