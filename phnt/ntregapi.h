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

#ifndef _NTREGAPI_H
#define _NTREGAPI_H

// Boot condition flags (NtInitializeRegistry)

#define REG_INIT_BOOT_SM 0x0000
#define REG_INIT_BOOT_SETUP 0x0001
#define REG_INIT_BOOT_ACCEPTED_BASE 0x0002
#define REG_INIT_BOOT_ACCEPTED_MAX REG_INIT_BOOT_ACCEPTED_BASE + 999

#define REG_MAX_KEY_VALUE_NAME_LENGTH 32767
#define REG_MAX_KEY_NAME_LENGTH 512

typedef enum _KEY_INFORMATION_CLASS
{
    KeyBasicInformation, // KEY_BASIC_INFORMATION
    KeyNodeInformation, // KEY_NODE_INFORMATION
    KeyFullInformation, // KEY_FULL_INFORMATION
    KeyNameInformation, // KEY_NAME_INFORMATION
    KeyCachedInformation, // KEY_CACHED_INFORMATION
    KeyFlagsInformation, // KEY_FLAGS_INFORMATION
    KeyVirtualizationInformation, // KEY_VIRTUALIZATION_INFORMATION
    KeyHandleTagsInformation, // KEY_HANDLE_TAGS_INFORMATION
    KeyTrustInformation, // KEY_TRUST_INFORMATION
    KeyLayerInformation, // KEY_LAYER_INFORMATION
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _KEY_NODE_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG NameLength;
    WCHAR Name[1];
    // ...
    // WCHAR Class[1];
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

typedef struct _KEY_FULL_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG MaxClassLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    WCHAR Class[1];
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef struct _KEY_NAME_INFORMATION
{
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _KEY_CACHED_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_CACHED_INFORMATION, *PKEY_CACHED_INFORMATION;

// rev
#define REG_FLAG_VOLATILE 0x0001
#define REG_FLAG_LINK 0x0002

// msdn
#define REG_KEY_DONT_VIRTUALIZE 0x0002
#define REG_KEY_DONT_SILENT_FAIL 0x0004
#define REG_KEY_RECURSE_FLAG 0x0008

// private
typedef struct _KEY_FLAGS_INFORMATION
{
    ULONG Wow64Flags;
    ULONG KeyFlags; // REG_FLAG_*
    ULONG ControlFlags; // REG_KEY_*
} KEY_FLAGS_INFORMATION, *PKEY_FLAGS_INFORMATION;

typedef struct _KEY_VIRTUALIZATION_INFORMATION
{
    ULONG VirtualizationCandidate : 1; // Tells whether the key is part of the virtualization namespace scope (only HKLM\Software for now).
    ULONG VirtualizationEnabled : 1; // Tells whether virtualization is enabled on this key. Can be 1 only if above flag is 1.
    ULONG VirtualTarget : 1; // Tells if the key is a virtual key. Can be 1 only if above 2 are 0. Valid only on the virtual store key handles.
    ULONG VirtualStore : 1; // Tells if the key is a part of the virtual store path. Valid only on the virtual store key handles.
    ULONG VirtualSource : 1; // Tells if the key has ever been virtualized, can be 1 only if VirtualizationCandidate is 1.
    ULONG Reserved : 27;
} KEY_VIRTUALIZATION_INFORMATION, *PKEY_VIRTUALIZATION_INFORMATION;

// private
typedef struct _KEY_TRUST_INFORMATION
{
    ULONG TrustedKey : 1;
    ULONG Reserved : 31;
} KEY_TRUST_INFORMATION, *PKEY_TRUST_INFORMATION;

// private
typedef struct _KEY_LAYER_INFORMATION
{
    ULONG IsTombstone : 1;
    ULONG IsSupersedeLocal : 1;
    ULONG IsSupersedeTree : 1;
    ULONG ClassIsInherited : 1;
    ULONG Reserved : 28;
} KEY_LAYER_INFORMATION, *PKEY_LAYER_INFORMATION;

typedef enum _KEY_SET_INFORMATION_CLASS
{
    KeyWriteTimeInformation, // KEY_WRITE_TIME_INFORMATION
    KeyWow64FlagsInformation, // KEY_WOW64_FLAGS_INFORMATION
    KeyControlFlagsInformation, // KEY_CONTROL_FLAGS_INFORMATION
    KeySetVirtualizationInformation, // KEY_SET_VIRTUALIZATION_INFORMATION
    KeySetDebugInformation,
    KeySetHandleTagsInformation, // KEY_HANDLE_TAGS_INFORMATION
    KeySetLayerInformation, // KEY_SET_LAYER_INFORMATION
    MaxKeySetInfoClass
} KEY_SET_INFORMATION_CLASS;

typedef struct _KEY_WRITE_TIME_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
} KEY_WRITE_TIME_INFORMATION, *PKEY_WRITE_TIME_INFORMATION;

typedef struct _KEY_WOW64_FLAGS_INFORMATION
{
    ULONG UserFlags;
} KEY_WOW64_FLAGS_INFORMATION, *PKEY_WOW64_FLAGS_INFORMATION;

typedef struct _KEY_HANDLE_TAGS_INFORMATION
{
    ULONG HandleTags;
} KEY_HANDLE_TAGS_INFORMATION, *PKEY_HANDLE_TAGS_INFORMATION;

typedef struct _KEY_SET_LAYER_INFORMATION
{
    ULONG IsTombstone : 1;
    ULONG IsSupersedeLocal : 1;
    ULONG IsSupersedeTree : 1;
    ULONG ClassIsInherited : 1;
    ULONG Reserved : 28;
} KEY_SET_LAYER_INFORMATION, *PKEY_SET_LAYER_INFORMATION;

typedef struct _KEY_CONTROL_FLAGS_INFORMATION
{
    ULONG ControlFlags;
} KEY_CONTROL_FLAGS_INFORMATION, *PKEY_CONTROL_FLAGS_INFORMATION;

typedef struct _KEY_SET_VIRTUALIZATION_INFORMATION
{
    ULONG VirtualTarget : 1;
    ULONG VirtualStore : 1;
    ULONG VirtualSource : 1; // true if key has been virtualized at least once
    ULONG Reserved : 29;
} KEY_SET_VIRTUALIZATION_INFORMATION, *PKEY_SET_VIRTUALIZATION_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS
{
    KeyValueBasicInformation, // KEY_VALUE_BASIC_INFORMATION
    KeyValueFullInformation, // KEY_VALUE_FULL_INFORMATION
    KeyValuePartialInformation, // KEY_VALUE_PARTIAL_INFORMATION
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,  // KEY_VALUE_PARTIAL_INFORMATION_ALIGN64
    KeyValueLayerInformation, // KEY_VALUE_LAYER_INFORMATION
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_BASIC_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
    // ...
    // UCHAR Data[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION_ALIGN64
{
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, *PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64;

// private
typedef struct _KEY_VALUE_LAYER_INFORMATION
{
    ULONG IsTombstone : 1;
    ULONG Reserved : 31;
} KEY_VALUE_LAYER_INFORMATION, *PKEY_VALUE_LAYER_INFORMATION;

// rev
typedef enum _KEY_LOAD_ENTRY_TYPE
{
    KeyLoadTrustClassKey = 1,
    KeyLoadEvent,
    KeyLoadToken
} KEY_LOAD_ENTRY_TYPE;

// rev
typedef struct _KEY_LOAD_ENTRY
{
    KEY_LOAD_ENTRY_TYPE EntryType;
    union
    {
        HANDLE Handle;
        ULONG_PTR Value;
    };
} KEY_LOAD_ENTRY, *PKEY_LOAD_ENTRY;

typedef struct _KEY_VALUE_ENTRY
{
    PUNICODE_STRING ValueName;
    ULONG DataLength;
    ULONG DataOffset;
    ULONG Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef enum _REG_ACTION
{
    KeyAdded,
    KeyRemoved,
    KeyModified
} REG_ACTION;

typedef struct _REG_NOTIFY_INFORMATION
{
    ULONG NextEntryOffset;
    REG_ACTION Action;
    ULONG KeyLength;
    WCHAR Key[1];
} REG_NOTIFY_INFORMATION, *PREG_NOTIFY_INFORMATION;

typedef struct _KEY_PID_ARRAY
{
    HANDLE ProcessId;
    UNICODE_STRING KeyName;
} KEY_PID_ARRAY, *PKEY_PID_ARRAY;

typedef struct _KEY_OPEN_SUBKEYS_INFORMATION
{
    ULONG Count;
    KEY_PID_ARRAY KeyArray[1];
} KEY_OPEN_SUBKEYS_INFORMATION, *PKEY_OPEN_SUBKEYS_INFORMATION;

// System calls

typedef
NTSTATUS(
NTAPI*
NTCREATEKEY)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Reserved_ ULONG TitleIndex,
    _In_opt_ PUNICODE_STRING Class,
    _In_ ULONG CreateOptions,
    _Out_opt_ PULONG Disposition
    );

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTCREATEKEYTRANSACTED)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Reserved_ ULONG TitleIndex,
    _In_opt_ PUNICODE_STRING Class,
    _In_ ULONG CreateOptions,
    _In_ HANDLE TransactionHandle,
    _Out_opt_ PULONG Disposition
    );
#endif

typedef
NTSTATUS(
NTAPI*
NTOPENKEY)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
NTOPENKEYTRANSACTED)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE TransactionHandle
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN7)
typedef
NTSTATUS(
NTAPI*
NTOPENKEYEX)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG OpenOptions
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN7)
typedef
NTSTATUS(
NTAPI*
NTOPENKEYTRANSACTEDEX)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG OpenOptions,
    _In_ HANDLE TransactionHandle
    );
#endif

typedef
NTSTATUS(
NTAPI*
NTDELETEKEY)(
    _In_ HANDLE KeyHandle
    );

typedef
NTSTATUS(
NTAPI*
NTRENAMEKEY)(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING NewName
    );

typedef
NTSTATUS(
NTAPI*
NTDELETEVALUEKEY)(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName
    );

typedef
NTSTATUS(
NTAPI*
NTQUERYKEY)(
    _In_ HANDLE KeyHandle,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    );

typedef
NTSTATUS(
NTAPI*
NTSETINFORMATIONKEY)(
    _In_ HANDLE KeyHandle,
    _In_ KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    _In_reads_bytes_(KeySetInformationLength) PVOID KeySetInformation,
    _In_ ULONG KeySetInformationLength
    );

typedef
NTSTATUS(
NTAPI*
NTQUERYVALUEKEY)(
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
NTSETVALUEKEY)(
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
NTQUERYMULTIPLEVALUEKEY)(
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
NTENUMERATEKEY)(
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
NTENUMERATEVALUEKEY)(
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
NTFLUSHKEY)(
    _In_ HANDLE KeyHandle
    );

typedef
NTSTATUS(
NTAPI*
NTCOMPACTKEYS)(
    _In_ ULONG Count,
    _In_reads_(Count) HANDLE KeyArray[]
    );

typedef
NTSTATUS(
NTAPI*
NTCOMPRESSKEY)(
    _In_ HANDLE Key
    );

typedef
NTSTATUS(
NTAPI*
NTLOADKEY)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ POBJECT_ATTRIBUTES SourceFile
    );

typedef
NTSTATUS(
NTAPI*
NTLOADKEY2)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ POBJECT_ATTRIBUTES SourceFile,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
NTLOADKEYEX)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ POBJECT_ATTRIBUTES SourceFile,
    _In_ ULONG Flags,
    _In_opt_ HANDLE TrustClassKey, // this and below were added on Win10
    _In_opt_ HANDLE Event,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE RootHandle,
    _Reserved_ PVOID Reserved // previously PIO_STATUS_BLOCK
    );
       
// rev by tyranid
#if (PHNT_VERSION >= PHNT_20H1)
typedef
NTSTATUS(
NTAPI*
NTLOADKEY3)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ POBJECT_ATTRIBUTES SourceFile,
    _In_ ULONG Flags,
    _In_reads_(LoadEntryCount) PKEY_LOAD_ENTRY LoadEntries,
    _In_ ULONG LoadEntryCount,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE RootHandle,
    _Reserved_ PVOID Reserved
    );
#endif

typedef
NTSTATUS(
NTAPI*
NTREPLACEKEY)(
    _In_ POBJECT_ATTRIBUTES NewFile,
    _In_ HANDLE TargetHandle,
    _In_ POBJECT_ATTRIBUTES OldFile
    );

typedef
NTSTATUS(
NTAPI*
NTSAVEKEY)(
    _In_ HANDLE KeyHandle,
    _In_ HANDLE FileHandle
    );

typedef
NTSTATUS(
NTAPI*
NTSAVEKEYEX)(
    _In_ HANDLE KeyHandle,
    _In_ HANDLE FileHandle,
    _In_ ULONG Format
    );

typedef
NTSTATUS(
NTAPI*
NTSAVEMERGEDKEYS)(
    _In_ HANDLE HighPrecedenceKeyHandle,
    _In_ HANDLE LowPrecedenceKeyHandle,
    _In_ HANDLE FileHandle
    );

typedef
NTSTATUS(
NTAPI*
NTRESTOREKEY)(
    _In_ HANDLE KeyHandle,
    _In_ HANDLE FileHandle,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
NTUNLOADKEY)(
    _In_ POBJECT_ATTRIBUTES TargetKey
    );

//
// NtUnloadKey2 Flags (from winnt.h)
//
//#define REG_FORCE_UNLOAD            1
//#define REG_UNLOAD_LEGAL_FLAGS      (REG_FORCE_UNLOAD)

typedef
NTSTATUS(
NTAPI*
NTUNLOADKEY2)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
NTUNLOADKEYEX)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_opt_ HANDLE Event
    );

typedef
NTSTATUS(
NTAPI*
NTNOTIFYCHANGEKEY)(
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
NTNOTIFYCHANGEMULTIPLEKEYS)(
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
NTQUERYOPENSUBKEYS)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _Out_ PULONG HandleCount
    );

typedef
NTSTATUS(
NTAPI*
NTQUERYOPENSUBKEYSEX)(
    _In_ POBJECT_ATTRIBUTES TargetKey,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_opt_(BufferLength) PVOID Buffer,
    _Out_ PULONG RequiredSize
    );

typedef
NTSTATUS(
NTAPI*
NTINITIALIZEREGISTRY)(
    _In_ USHORT BootCondition
    );

typedef
NTSTATUS(
NTAPI*
NTLOCKREGISTRYKEY)(
    _In_ HANDLE KeyHandle
    );

typedef
NTSTATUS(
NTAPI*
NTLOCKPRODUCTACTIVATIONKEYS)(
    _Inout_opt_ ULONG *pPrivateVer,
    _Out_opt_ ULONG *pSafeMode
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
NTFREEZEREGISTRY)(
    _In_ ULONG TimeOutInSeconds
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
NTTHAWREGISTRY)(
    VOID
    );
#endif

#if (PHNT_VERSION >= PHNT_REDSTONE)
NTSTATUS NtCreateRegistryTransaction(
    _Out_ HANDLE *RegistryTransactionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjAttributes,
    _Reserved_ ULONG CreateOptions
    );     
#endif

#if (PHNT_VERSION >= PHNT_REDSTONE)
NTSTATUS NtOpenRegistryTransaction(
    _Out_ HANDLE *RegistryTransactionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjAttributes
    );
#endif

#if (PHNT_VERSION >= PHNT_REDSTONE)
NTSTATUS NtCommitRegistryTransaction(
    _In_ HANDLE RegistryTransactionHandle,
    _Reserved_ ULONG Flags
    );
#endif

#if (PHNT_VERSION >= PHNT_REDSTONE)
NTSTATUS NtRollbackRegistryTransaction(
    _In_ HANDLE RegistryTransactionHandle,
    _Reserved_ ULONG Flags
    );
#endif

#endif
