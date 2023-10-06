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

#ifndef _NTRTL_H
#define _NTRTL_H

#define RtlOffsetToPointer(Base, Offset) ((PCHAR)(((PCHAR)(Base)) + ((ULONG_PTR)(Offset))))
#define RtlPointerToOffset(Base, Pointer) ((ULONG)(((PCHAR)(Pointer)) - ((PCHAR)(Base))))

// Linked lists

FORCEINLINE VOID InitializeListHead(
    _Out_ PLIST_ENTRY ListHead
    )
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

_Check_return_ FORCEINLINE BOOLEAN IsListEmpty(
    _In_ PLIST_ENTRY ListHead
    )
{
    return ListHead->Flink == ListHead;
}

FORCEINLINE BOOLEAN RemoveEntryList(
    _In_ PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Flink;

    Flink = Entry->Flink;
    Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;

    return Flink == Blink;
}

FORCEINLINE PLIST_ENTRY RemoveHeadList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;

    return Entry;
}

FORCEINLINE PLIST_ENTRY RemoveTailList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Blink;
    Blink = Entry->Blink;
    ListHead->Blink = Blink;
    Blink->Flink = ListHead;

    return Entry;
}

FORCEINLINE VOID InsertTailList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Blink;

    Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}

FORCEINLINE VOID InsertHeadList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Flink;

    Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
}

FORCEINLINE VOID AppendTailList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY ListToAppend
    )
{
    PLIST_ENTRY ListEnd = ListHead->Blink;

    ListHead->Blink->Flink = ListToAppend;
    ListHead->Blink = ListToAppend->Blink;
    ListToAppend->Blink->Flink = ListHead;
    ListToAppend->Blink = ListEnd;
}

FORCEINLINE PSINGLE_LIST_ENTRY PopEntryList(
    _Inout_ PSINGLE_LIST_ENTRY ListHead
    )
{
    PSINGLE_LIST_ENTRY FirstEntry;

    FirstEntry = ListHead->Next;

    if (FirstEntry)
        ListHead->Next = FirstEntry->Next;

    return FirstEntry;
}

FORCEINLINE VOID PushEntryList(
    _Inout_ PSINGLE_LIST_ENTRY ListHead,
    _Inout_ PSINGLE_LIST_ENTRY Entry
    )
{
    Entry->Next = ListHead->Next;
    ListHead->Next = Entry;
}

// AVL and splay trees

typedef enum _TABLE_SEARCH_RESULT
{
    TableEmptyTree,
    TableFoundNode,
    TableInsertAsLeft,
    TableInsertAsRight
} TABLE_SEARCH_RESULT;

typedef enum _RTL_GENERIC_COMPARE_RESULTS
{
    GenericLessThan,
    GenericGreaterThan,
    GenericEqual
} RTL_GENERIC_COMPARE_RESULTS;

typedef RTL_GENERIC_COMPARE_RESULTS (NTAPI *PRTL_AVL_COMPARE_ROUTINE)(
    _In_ struct _RTL_AVL_TABLE *Table,
    _In_ PVOID FirstStruct,
    _In_ PVOID SecondStruct
    );

typedef PVOID (NTAPI *PRTL_AVL_ALLOCATE_ROUTINE)(
    _In_ struct _RTL_AVL_TABLE *Table,
    _In_ CLONG ByteSize
    );

typedef VOID (NTAPI *PRTL_AVL_FREE_ROUTINE)(
    _In_ struct _RTL_AVL_TABLE *Table,
    _In_ _Post_invalid_ PVOID Buffer
    );

typedef NTSTATUS (NTAPI *PRTL_AVL_MATCH_FUNCTION)(
    _In_ struct _RTL_AVL_TABLE *Table,
    _In_ PVOID UserData,
    _In_ PVOID MatchData
    );

typedef struct _RTL_BALANCED_LINKS
{
    struct _RTL_BALANCED_LINKS *Parent;
    struct _RTL_BALANCED_LINKS *LeftChild;
    struct _RTL_BALANCED_LINKS *RightChild;
    CHAR Balance;
    UCHAR Reserved[3];
} RTL_BALANCED_LINKS, *PRTL_BALANCED_LINKS;

typedef struct _RTL_AVL_TABLE
{
    RTL_BALANCED_LINKS BalancedRoot;
    PVOID OrderedPointer;
    ULONG WhichOrderedElement;
    ULONG NumberGenericTableElements;
    ULONG DepthOfTree;
    PRTL_BALANCED_LINKS RestartKey;
    ULONG DeleteCount;
    PRTL_AVL_COMPARE_ROUTINE CompareRoutine;
    PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine;
    PRTL_AVL_FREE_ROUTINE FreeRoutine;
    PVOID TableContext;
} RTL_AVL_TABLE, *PRTL_AVL_TABLE;

typedef
VOID(
NTAPI*
RTLINITIALIZEGENERICTABLEAVL)(
    _Out_ PRTL_AVL_TABLE Table,
    _In_ PRTL_AVL_COMPARE_ROUTINE CompareRoutine,
    _In_ PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine,
    _In_ PRTL_AVL_FREE_ROUTINE FreeRoutine,
    _In_opt_ PVOID TableContext
    );

typedef
PVOID(
NTAPI*
RTLINSERTELEMENTGENERICTABLEAVL)(
    _In_ PRTL_AVL_TABLE Table,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ CLONG BufferSize,
    _Out_opt_ PBOOLEAN NewElement
    );

typedef
PVOID(
NTAPI*
RTLINSERTELEMENTGENERICTABLEFULLAVL)(
    _In_ PRTL_AVL_TABLE Table,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ CLONG BufferSize,
    _Out_opt_ PBOOLEAN NewElement,
    _In_ PVOID NodeOrParent,
    _In_ TABLE_SEARCH_RESULT SearchResult
    );

typedef
BOOLEAN(
NTAPI*
RTLDELETEELEMENTGENERICTABLEAVL)(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer
    );

_Check_return_
typedef
PVOID(
NTAPI*
RTLLOOKUPELEMENTGENERICTABLEAVL)(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer
    );

typedef
PVOID(
NTAPI*
RTLLOOKUPELEMENTGENERICTABLEFULLAVL)(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer,
    _Out_ PVOID *NodeOrParent,
    _Out_ TABLE_SEARCH_RESULT *SearchResult
    );

_Check_return_
typedef
PVOID(
NTAPI*
RTLENUMERATEGENERICTABLEAVL)(
    _In_ PRTL_AVL_TABLE Table,
    _In_ BOOLEAN Restart
    );

_Check_return_
typedef
PVOID(
NTAPI*
RTLENUMERATEGENERICTABLEWITHOUTSPLAYINGAVL)(
    _In_ PRTL_AVL_TABLE Table,
    _Inout_ PVOID *RestartKey
    );

_Check_return_
typedef
PVOID(
NTAPI*
RTLLOOKUPFIRSTMATCHINGELEMENTGENERICTABLEAVL)(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer,
    _Out_ PVOID *RestartKey
    );

_Check_return_
typedef
PVOID(
NTAPI*
RTLENUMERATEGENERICTABLELIKEADIRECTORY)(
    _In_ PRTL_AVL_TABLE Table,
    _In_opt_ PRTL_AVL_MATCH_FUNCTION MatchFunction,
    _In_opt_ PVOID MatchData,
    _In_ ULONG NextFlag,
    _Inout_ PVOID *RestartKey,
    _Inout_ PULONG DeleteCount,
    _In_ PVOID Buffer
    );

_Check_return_
typedef
PVOID(
NTAPI*
RTLGETELEMENTGENERICTABLEAVL)(
    _In_ PRTL_AVL_TABLE Table,
    _In_ ULONG I
    );

typedef
ULONG(
NTAPI*
RTLNUMBERGENERICTABLEELEMENTSAVL)(
    _In_ PRTL_AVL_TABLE Table
    );

_Check_return_
typedef
BOOLEAN(
NTAPI*
RTLISGENERICTABLEEMPTYAVL)(
    _In_ PRTL_AVL_TABLE Table
    );

typedef struct _RTL_SPLAY_LINKS
{
    struct _RTL_SPLAY_LINKS *Parent;
    struct _RTL_SPLAY_LINKS *LeftChild;
    struct _RTL_SPLAY_LINKS *RightChild;
} RTL_SPLAY_LINKS, *PRTL_SPLAY_LINKS;

#define RtlInitializeSplayLinks(Links) \
{ \
    PRTL_SPLAY_LINKS _SplayLinks; \
    _SplayLinks = (PRTL_SPLAY_LINKS)(Links); \
    _SplayLinks->Parent = _SplayLinks; \
    _SplayLinks->LeftChild = NULL; \
    _SplayLinks->RightChild = NULL; \
}

#define RtlParent(Links) ((PRTL_SPLAY_LINKS)(Links)->Parent)
#define RtlLeftChild(Links) ((PRTL_SPLAY_LINKS)(Links)->LeftChild)
#define RtlRightChild(Links) ((PRTL_SPLAY_LINKS)(Links)->RightChild)
#define RtlIsRoot(Links) ((RtlParent(Links) == (PRTL_SPLAY_LINKS)(Links)))
#define RtlIsLeftChild(Links) ((RtlLeftChild(RtlParent(Links)) == (PRTL_SPLAY_LINKS)(Links)))
#define RtlIsRightChild(Links) ((RtlRightChild(RtlParent(Links)) == (PRTL_SPLAY_LINKS)(Links)))

#define RtlInsertAsLeftChild(ParentLinks, ChildLinks) \
{ \
    PRTL_SPLAY_LINKS _SplayParent; \
    PRTL_SPLAY_LINKS _SplayChild; \
    _SplayParent = (PRTL_SPLAY_LINKS)(ParentLinks); \
    _SplayChild = (PRTL_SPLAY_LINKS)(ChildLinks); \
    _SplayParent->LeftChild = _SplayChild; \
    _SplayChild->Parent = _SplayParent; \
}

#define RtlInsertAsRightChild(ParentLinks, ChildLinks) \
{ \
    PRTL_SPLAY_LINKS _SplayParent; \
    PRTL_SPLAY_LINKS _SplayChild; \
    _SplayParent = (PRTL_SPLAY_LINKS)(ParentLinks); \
    _SplayChild = (PRTL_SPLAY_LINKS)(ChildLinks); \
    _SplayParent->RightChild = _SplayChild; \
    _SplayChild->Parent = _SplayParent; \
}

typedef
PRTL_SPLAY_LINKS(
NTAPI*
RTLSPLAY)(
    _Inout_ PRTL_SPLAY_LINKS Links
    );

typedef
PRTL_SPLAY_LINKS(
NTAPI*
RTLDELETE)(
    _In_ PRTL_SPLAY_LINKS Links
    );

typedef
VOID(
NTAPI*
RTLDELETENOSPLAY)(
    _In_ PRTL_SPLAY_LINKS Links,
    _Inout_ PRTL_SPLAY_LINKS *Root
    );

_Check_return_
typedef
PRTL_SPLAY_LINKS(
NTAPI*
RTLSUBTREESUCCESSOR)(
    _In_ PRTL_SPLAY_LINKS Links
    );

_Check_return_
typedef
PRTL_SPLAY_LINKS(
NTAPI*
RTLSUBTREEPREDECESSOR)(
    _In_ PRTL_SPLAY_LINKS Links
    );

_Check_return_
typedef
PRTL_SPLAY_LINKS(
NTAPI*
RTLREALSUCCESSOR)(
    _In_ PRTL_SPLAY_LINKS Links
    );

_Check_return_
typedef
PRTL_SPLAY_LINKS(
NTAPI*
RTLREALPREDECESSOR)(
    _In_ PRTL_SPLAY_LINKS Links
    );

struct _RTL_GENERIC_TABLE;

typedef RTL_GENERIC_COMPARE_RESULTS (NTAPI *PRTL_GENERIC_COMPARE_ROUTINE)(
    _In_ struct _RTL_GENERIC_TABLE *Table,
    _In_ PVOID FirstStruct,
    _In_ PVOID SecondStruct
    );

typedef PVOID (NTAPI *PRTL_GENERIC_ALLOCATE_ROUTINE)(
    _In_ struct _RTL_GENERIC_TABLE *Table,
    _In_ CLONG ByteSize
    );

typedef VOID (NTAPI *PRTL_GENERIC_FREE_ROUTINE)(
    _In_ struct _RTL_GENERIC_TABLE *Table,
    _In_ _Post_invalid_ PVOID Buffer
    );

typedef struct _RTL_GENERIC_TABLE
{
    PRTL_SPLAY_LINKS TableRoot;
    LIST_ENTRY InsertOrderList;
    PLIST_ENTRY OrderedPointer;
    ULONG WhichOrderedElement;
    ULONG NumberGenericTableElements;
    PRTL_GENERIC_COMPARE_ROUTINE CompareRoutine;
    PRTL_GENERIC_ALLOCATE_ROUTINE AllocateRoutine;
    PRTL_GENERIC_FREE_ROUTINE FreeRoutine;
    PVOID TableContext;
} RTL_GENERIC_TABLE, *PRTL_GENERIC_TABLE;

typedef
VOID(
NTAPI*
RTLINITIALIZEGENERICTABLE)(
    _Out_ PRTL_GENERIC_TABLE Table,
    _In_ PRTL_GENERIC_COMPARE_ROUTINE CompareRoutine,
    _In_ PRTL_GENERIC_ALLOCATE_ROUTINE AllocateRoutine,
    _In_ PRTL_GENERIC_FREE_ROUTINE FreeRoutine,
    _In_opt_ PVOID TableContext
    );

typedef
PVOID(
NTAPI*
RTLINSERTELEMENTGENERICTABLE)(
    _In_ PRTL_GENERIC_TABLE Table,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ CLONG BufferSize,
    _Out_opt_ PBOOLEAN NewElement
    );

typedef
PVOID(
NTAPI*
RTLINSERTELEMENTGENERICTABLEFULL)(
    _In_ PRTL_GENERIC_TABLE Table,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ CLONG BufferSize,
    _Out_opt_ PBOOLEAN NewElement,
    _In_ PVOID NodeOrParent,
    _In_ TABLE_SEARCH_RESULT SearchResult
    );

typedef
BOOLEAN(
NTAPI*
RTLDELETEELEMENTGENERICTABLE)(
    _In_ PRTL_GENERIC_TABLE Table,
    _In_ PVOID Buffer
    );

_Check_return_
typedef
PVOID(
NTAPI*
RTLLOOKUPELEMENTGENERICTABLE)(
    _In_ PRTL_GENERIC_TABLE Table,
    _In_ PVOID Buffer
    );

typedef
PVOID(
NTAPI*
RTLLOOKUPELEMENTGENERICTABLEFULL)(
    _In_ PRTL_GENERIC_TABLE Table,
    _In_ PVOID Buffer,
    _Out_ PVOID *NodeOrParent,
    _Out_ TABLE_SEARCH_RESULT *SearchResult
    );

_Check_return_
typedef
PVOID(
NTAPI*
RTLENUMERATEGENERICTABLE)(
    _In_ PRTL_GENERIC_TABLE Table,
    _In_ BOOLEAN Restart
    );

_Check_return_
typedef
PVOID(
NTAPI*
RTLENUMERATEGENERICTABLEWITHOUTSPLAYING)(
    _In_ PRTL_GENERIC_TABLE Table,
    _Inout_ PVOID *RestartKey
    );

_Check_return_
typedef
PVOID(
NTAPI*
RTLGETELEMENTGENERICTABLE)(
    _In_ PRTL_GENERIC_TABLE Table,
    _In_ ULONG I
    );

typedef
ULONG(
NTAPI*
RTLNUMBERGENERICTABLEELEMENTS)(
    _In_ PRTL_GENERIC_TABLE Table
    );

_Check_return_
typedef
BOOLEAN(
NTAPI*
RTLISGENERICTABLEEMPTY)(
    _In_ PRTL_GENERIC_TABLE Table
    );

// RB trees

typedef struct _RTL_RB_TREE
{
    PRTL_BALANCED_NODE Root;
    PRTL_BALANCED_NODE Min;
} RTL_RB_TREE, *PRTL_RB_TREE;

#if (PHNT_VERSION >= PHNT_WIN8)

// rev
typedef
VOID(
NTAPI*
RTLRBINSERTNODEEX)(
    _In_ PRTL_RB_TREE Tree,
    _In_opt_ PRTL_BALANCED_NODE Parent,
    _In_ BOOLEAN Right,
    _Out_ PRTL_BALANCED_NODE Node
    );

// rev
typedef
VOID(
NTAPI*
RTLRBREMOVENODE)(
    _In_ PRTL_RB_TREE Tree,
    _In_ PRTL_BALANCED_NODE Node
    );

#endif

// Hash tables

// begin_ntddk

#define RTL_HASH_ALLOCATED_HEADER 0x00000001
#define RTL_HASH_RESERVED_SIGNATURE 0

typedef struct _RTL_DYNAMIC_HASH_TABLE_ENTRY
{
    LIST_ENTRY Linkage;
    ULONG_PTR Signature;
} RTL_DYNAMIC_HASH_TABLE_ENTRY, *PRTL_DYNAMIC_HASH_TABLE_ENTRY;

#define HASH_ENTRY_KEY(x) ((x)->Signature)

typedef struct _RTL_DYNAMIC_HASH_TABLE_CONTEXT
{
    PLIST_ENTRY ChainHead;
    PLIST_ENTRY PrevLinkage;
    ULONG_PTR Signature;
} RTL_DYNAMIC_HASH_TABLE_CONTEXT, *PRTL_DYNAMIC_HASH_TABLE_CONTEXT;

typedef struct _RTL_DYNAMIC_HASH_TABLE_ENUMERATOR
{
    RTL_DYNAMIC_HASH_TABLE_ENTRY HashEntry;
    PLIST_ENTRY ChainHead;
    ULONG BucketIndex;
} RTL_DYNAMIC_HASH_TABLE_ENUMERATOR, *PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR;

typedef struct _RTL_DYNAMIC_HASH_TABLE
{
    // Entries initialized at creation.
    ULONG Flags;
    ULONG Shift;

    // Entries used in bucket computation.
    ULONG TableSize;
    ULONG Pivot;
    ULONG DivisorMask;

    // Counters.
    ULONG NumEntries;
    ULONG NonEmptyBuckets;
    ULONG NumEnumerators;

    // The directory. This field is for internal use only.
    PVOID Directory;
} RTL_DYNAMIC_HASH_TABLE, *PRTL_DYNAMIC_HASH_TABLE;

#if (PHNT_VERSION >= PHNT_WIN7)

FORCEINLINE
VOID
RtlInitHashTableContext(
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context
    )
{
    Context->ChainHead = NULL;
    Context->PrevLinkage = NULL;
}

FORCEINLINE
VOID
RtlInitHashTableContextFromEnumerator(
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context,
    _In_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator
    )
{
    Context->ChainHead = Enumerator->ChainHead;
    Context->PrevLinkage = Enumerator->HashEntry.Linkage.Blink;
}

FORCEINLINE
VOID
RtlReleaseHashTableContext(
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context
    )
{
    UNREFERENCED_PARAMETER(Context);
    return;
}

FORCEINLINE
ULONG
RtlTotalBucketsHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable
    )
{
    return HashTable->TableSize;
}

FORCEINLINE
ULONG
RtlNonEmptyBucketsHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable
    )
{
    return HashTable->NonEmptyBuckets;
}

FORCEINLINE
ULONG
RtlEmptyBucketsHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable
    )
{
    return HashTable->TableSize - HashTable->NonEmptyBuckets;
}

FORCEINLINE
ULONG
RtlTotalEntriesHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable
    )
{
    return HashTable->NumEntries;
}

FORCEINLINE
ULONG
RtlActiveEnumeratorsHashTable(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable
    )
{
    return HashTable->NumEnumerators;
}

_Must_inspect_result_
typedef
BOOLEAN(
NTAPI*
RTLCREATEHASHTABLE)(
    _Inout_ _When_(*HashTable == NULL, __drv_allocatesMem(Mem)) PRTL_DYNAMIC_HASH_TABLE *HashTable,
    _In_ ULONG Shift,
    _In_ _Reserved_ ULONG Flags
    );

typedef
VOID(
NTAPI*
RTLDELETEHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable
    );

typedef
BOOLEAN(
NTAPI*
RTLINSERTENTRYHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _In_ PRTL_DYNAMIC_HASH_TABLE_ENTRY Entry,
    _In_ ULONG_PTR Signature,
    _Inout_opt_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context
    );

typedef
BOOLEAN(
NTAPI*
RTLREMOVEENTRYHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _In_ PRTL_DYNAMIC_HASH_TABLE_ENTRY Entry,
    _Inout_opt_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context
    );

_Must_inspect_result_
typedef
PRTL_DYNAMIC_HASH_TABLE_ENTRY(
NTAPI*
RTLLOOKUPENTRYHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _In_ ULONG_PTR Signature,
    _Out_opt_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context
    );

_Must_inspect_result_
typedef
PRTL_DYNAMIC_HASH_TABLE_ENTRY(
NTAPI*
RTLGETNEXTENTRYHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _In_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context
    );

typedef
BOOLEAN(
NTAPI*
RTLINITENUMERATIONHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Out_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator
    );

_Must_inspect_result_
typedef
PRTL_DYNAMIC_HASH_TABLE_ENTRY(
NTAPI*
RTLENUMERATEENTRYHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator
    );

typedef
VOID(
NTAPI*
RTLENDENUMERATIONHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator
    );

typedef
BOOLEAN(
NTAPI*
RTLINITWEAKENUMERATIONHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Out_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator
    );

_Must_inspect_result_
typedef
PRTL_DYNAMIC_HASH_TABLE_ENTRY(
NTAPI*
RTLWEAKLYENUMERATEENTRYHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator
    );

typedef
VOID(
NTAPI*
RTLENDWEAKENUMERATIONHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator
    );

typedef
BOOLEAN(
NTAPI*
RTLEXPANDHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable
    );

typedef
BOOLEAN(
NTAPI*
RTLCONTRACTHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable
    );

#endif

#if (PHNT_VERSION >= PHNT_THRESHOLD)

typedef
BOOLEAN(
NTAPI*
RTLINITSTRONGENUMERATIONHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Out_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator
    );

_Must_inspect_result_
typedef
PRTL_DYNAMIC_HASH_TABLE_ENTRY(
NTAPI*
RTLSTRONGLYENUMERATEENTRYHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator
    );

typedef
VOID(
NTAPI*
RTLENDSTRONGENUMERATIONHASHTABLE)(
    _In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
    _Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator
    );

#endif

// end_ntddk

// Critical sections

typedef
NTSTATUS(
NTAPI*
RTLINITIALIZECRITICALSECTION)(
    _Out_ PRTL_CRITICAL_SECTION CriticalSection
    );

typedef
NTSTATUS(
NTAPI*
RTLINITIALIZECRITICALSECTIONANDSPINCOUNT)(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection,
    _In_ ULONG SpinCount
    );

typedef
NTSTATUS(
NTAPI*
RTLDELETECRITICALSECTION)(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
    );

typedef
NTSTATUS(
NTAPI*
RTLENTERCRITICALSECTION)(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
    );

typedef
NTSTATUS(
NTAPI*
RTLLEAVECRITICALSECTION)(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
    );

typedef
LOGICAL(
NTAPI*
RTLTRYENTERCRITICALSECTION)(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
    );

typedef
LOGICAL(
NTAPI*
RTLISCRITICALSECTIONLOCKED)(
    _In_ PRTL_CRITICAL_SECTION CriticalSection
    );

typedef
LOGICAL(
NTAPI*
RTLISCRITICALSECTIONLOCKEDBYTHREAD)(
    _In_ PRTL_CRITICAL_SECTION CriticalSection
    );

typedef
ULONG(
NTAPI*
RTLGETCRITICALSECTIONRECURSIONCOUNT)(
    _In_ PRTL_CRITICAL_SECTION CriticalSection
    );

typedef
ULONG(
NTAPI*
RTLSETCRITICALSECTIONSPINCOUNT)(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection,
    _In_ ULONG SpinCount
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
HANDLE(
NTAPI*
RTLQUERYCRITICALSECTIONOWNER)(
    _In_ HANDLE EventHandle
    );
#endif

typedef
VOID(
NTAPI*
RTLCHECKFORORPHANEDCRITICALSECTIONS)(
    _In_ HANDLE ThreadHandle
    );

// Resources

typedef struct _RTL_RESOURCE
{
    RTL_CRITICAL_SECTION CriticalSection;

    HANDLE SharedSemaphore;
    volatile ULONG NumberOfWaitingShared;
    HANDLE ExclusiveSemaphore;
    volatile ULONG NumberOfWaitingExclusive;

    volatile LONG NumberOfActive; // negative: exclusive acquire; zero: not acquired; positive: shared acquire(s)
    HANDLE ExclusiveOwnerThread;

    ULONG Flags; // RTL_RESOURCE_FLAG_*

    PRTL_RESOURCE_DEBUG DebugInfo;
} RTL_RESOURCE, *PRTL_RESOURCE;

#define RTL_RESOURCE_FLAG_LONG_TERM ((ULONG)0x00000001)

typedef
VOID(
NTAPI*
RTLINITIALIZERESOURCE)(
    _Out_ PRTL_RESOURCE Resource
    );

typedef
VOID(
NTAPI*
RTLDELETERESOURCE)(
    _Inout_ PRTL_RESOURCE Resource
    );

typedef
BOOLEAN(
NTAPI*
RTLACQUIRERESOURCESHARED)(
    _Inout_ PRTL_RESOURCE Resource,
    _In_ BOOLEAN Wait
    );

typedef
BOOLEAN(
NTAPI*
RTLACQUIRERESOURCEEXCLUSIVE)(
    _Inout_ PRTL_RESOURCE Resource,
    _In_ BOOLEAN Wait
    );

typedef
VOID(
NTAPI*
RTLRELEASERESOURCE)(
    _Inout_ PRTL_RESOURCE Resource
    );

typedef
VOID(
NTAPI*
RTLCONVERTSHAREDTOEXCLUSIVE)(
    _Inout_ PRTL_RESOURCE Resource
    );

typedef
VOID(
NTAPI*
RTLCONVERTEXCLUSIVETOSHARED)(
    _Inout_ PRTL_RESOURCE Resource
    );

// Slim reader-writer locks, condition variables, and barriers

#if (PHNT_VERSION >= PHNT_VISTA)

// winbase:InitializeSRWLock
typedef
VOID(
NTAPI*
RTLINITIALIZESRWLOCK)(
    _Out_ PRTL_SRWLOCK SRWLock
    );

// winbase:AcquireSRWLockExclusive
typedef
VOID(
NTAPI*
RTLACQUIRESRWLOCKEXCLUSIVE)(
    _Inout_ PRTL_SRWLOCK SRWLock
    );

// winbase:AcquireSRWLockShared
typedef
VOID(
NTAPI*
RTLACQUIRESRWLOCKSHARED)(
    _Inout_ PRTL_SRWLOCK SRWLock
    );

// winbase:ReleaseSRWLockExclusive
typedef
VOID(
NTAPI*
RTLRELEASESRWLOCKEXCLUSIVE)(
    _Inout_ PRTL_SRWLOCK SRWLock
    );

// winbase:ReleaseSRWLockShared
typedef
VOID(
NTAPI*
RTLRELEASESRWLOCKSHARED)(
    _Inout_ PRTL_SRWLOCK SRWLock
    );

// winbase:TryAcquireSRWLockExclusive
typedef
BOOLEAN(
NTAPI*
RTLTRYACQUIRESRWLOCKEXCLUSIVE)(
    _Inout_ PRTL_SRWLOCK SRWLock
    );

// winbase:TryAcquireSRWLockShared
typedef
BOOLEAN(
NTAPI*
RTLTRYACQUIRESRWLOCKSHARED)(
    _Inout_ PRTL_SRWLOCK SRWLock
    );

#if (PHNT_VERSION >= PHNT_WIN7)
// rev
typedef
VOID(
NTAPI*
RTLACQUIRERELEASESRWLOCKEXCLUSIVE)(
    _Inout_ PRTL_SRWLOCK SRWLock
    );
#endif

#endif

#if (PHNT_VERSION >= PHNT_VISTA)

// winbase:InitializeConditionVariable
typedef
VOID(
NTAPI*
RTLINITIALIZECONDITIONVARIABLE)(
    _Out_ PRTL_CONDITION_VARIABLE ConditionVariable
    );

// private
typedef
NTSTATUS(
NTAPI*
RTLSLEEPCONDITIONVARIABLECS)(
    _Inout_ PRTL_CONDITION_VARIABLE ConditionVariable,
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection,
    _In_opt_ PLARGE_INTEGER Timeout
    );

// private
typedef
NTSTATUS(
NTAPI*
RTLSLEEPCONDITIONVARIABLESRW)(
    _Inout_ PRTL_CONDITION_VARIABLE ConditionVariable,
    _Inout_ PRTL_SRWLOCK SRWLock,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_ ULONG Flags
    );

// winbase:WakeConditionVariable
typedef
VOID(
NTAPI*
RTLWAKECONDITIONVARIABLE)(
    _Inout_ PRTL_CONDITION_VARIABLE ConditionVariable
    );

// winbase:WakeAllConditionVariable
typedef
VOID(
NTAPI*
RTLWAKEALLCONDITIONVARIABLE)(
    _Inout_ PRTL_CONDITION_VARIABLE ConditionVariable
    );

#endif

// begin_rev
#define RTL_BARRIER_FLAGS_SPIN_ONLY 0x00000001 // never block on event - always spin
#define RTL_BARRIER_FLAGS_BLOCK_ONLY 0x00000002 // always block on event - never spin
#define RTL_BARRIER_FLAGS_NO_DELETE 0x00000004 // use if barrier will never be deleted
// end_rev

// begin_private

#if (PHNT_VERSION >= PHNT_VISTA)

typedef
NTSTATUS(
NTAPI*
RTLINITBARRIER)(
    _Out_ PRTL_BARRIER Barrier,
    _In_ ULONG TotalThreads,
    _In_ ULONG SpinCount
    );

typedef
NTSTATUS(
NTAPI*
RTLDELETEBARRIER)(
    _In_ PRTL_BARRIER Barrier
    );

typedef
BOOLEAN(
NTAPI*
RTLBARRIER)(
    _Inout_ PRTL_BARRIER Barrier,
    _In_ ULONG Flags
    );

typedef
BOOLEAN(
NTAPI*
RTLBARRIERFORDELETE)(
    _Inout_ PRTL_BARRIER Barrier,
    _In_ ULONG Flags
    );

#endif

// end_private

// Wait on address

// begin_rev

#if (PHNT_VERSION >= PHNT_WIN8)

typedef
NTSTATUS(
NTAPI*
RTLWAITONADDRESS)(
    _In_ volatile VOID *Address,
    _In_ PVOID CompareAddress,
    _In_ SIZE_T AddressSize,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef
VOID(
NTAPI*
RTLWAKEADDRESSALL)(
    _In_ PVOID Address
    );

typedef
VOID(
NTAPI*
RTLWAKEADDRESSSINGLE)(
    _In_ PVOID Address
    );

#endif

// end_rev

// Strings

FORCEINLINE
VOID
NTAPI
RtlInitEmptyAnsiString(
    _Out_ PANSI_STRING AnsiString,
    _Pre_maybenull_ _Pre_readable_size_(MaximumLength) PCHAR Buffer,
    _In_ USHORT MaximumLength
    )
{
    memset(AnsiString, 0, sizeof(ANSI_STRING));
    AnsiString->MaximumLength = MaximumLength;
    AnsiString->Buffer = Buffer;
}

#ifndef PHNT_NO_INLINE_INIT_STRING
FORCEINLINE VOID RtlInitString(
    _Out_ PSTRING DestinationString,
    _In_opt_ PCSTR SourceString
    )
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)strlen(SourceString)) + sizeof(ANSI_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PCHAR)SourceString;
}
#else
typedef
VOID(
NTAPI*
RTLINITSTRING)(
    _Out_ PSTRING DestinationString,
    _In_opt_ PCSTR SourceString
    );
#endif

#if (PHNT_VERSION >= PHNT_THRESHOLD)
typedef
NTSTATUS(
NTAPI*
RTLINITSTRINGEX)(
    _Out_ PSTRING DestinationString,
    _In_opt_z_ PCSZ SourceString
    );
#endif

#ifndef PHNT_NO_INLINE_INIT_STRING
FORCEINLINE VOID RtlInitAnsiString(
    _Out_ PANSI_STRING DestinationString,
    _In_opt_ PCSTR SourceString
    )
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)strlen(SourceString)) + sizeof(ANSI_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PCHAR)SourceString;
}
#else
typedef
VOID(
NTAPI*
RTLINITANSISTRING)(
    _Out_ PANSI_STRING DestinationString,
    _In_opt_ PCSTR SourceString
    );
#endif

#if (PHNT_VERSION >= PHNT_WS03)
typedef
NTSTATUS(
NTAPI*
RTLINITANSISTRINGEX)(
    _Out_ PANSI_STRING DestinationString,
    _In_opt_z_ PCSZ SourceString
    );
#endif

typedef
VOID(
NTAPI*
RTLFREEANSISTRING)(
    _Inout_ _At_(AnsiString->Buffer, _Frees_ptr_opt_) PANSI_STRING AnsiString
    );

#if (PHNT_VERSION >= PHNT_20H1)
typedef
VOID(
NTAPI*
RTLINITUTF8STRING)(
    _Out_ PUTF8_STRING DestinationString,
    _In_opt_z_ PCSZ SourceString
    );

typedef
NTSTATUS(
NTAPI*
RTLINITUTF8STRINGEX)(
    _Out_ PUTF8_STRING DestinationString,
    _In_opt_z_ PCSZ SourceString
    );

typedef
VOID(
NTAPI*
RTLFREEUTF8STRING)(
    _Inout_ _At_(utf8String->Buffer, _Frees_ptr_opt_) PUTF8_STRING Utf8String
    );
#endif

typedef
VOID(
NTAPI*
RTLFREEOEMSTRING)(
    _Inout_ POEM_STRING OemString
    );

typedef
VOID(
NTAPI*
RTLCOPYSTRING)(
    _In_ PSTRING DestinationString,
    _In_opt_ PSTRING SourceString
    );

typedef
CHAR(
NTAPI*
RTLUPPERCHAR)(
    _In_ CHAR Character
    );

_Must_inspect_result_
typedef
LONG(
NTAPI*
RTLCOMPARESTRING)(
    _In_ PSTRING String1,
    _In_ PSTRING String2,
    _In_ BOOLEAN CaseInSensitive
    );

_Must_inspect_result_
typedef
BOOLEAN(
NTAPI*
RTLEQUALSTRING)(
    _In_ PSTRING String1,
    _In_ PSTRING String2,
    _In_ BOOLEAN CaseInSensitive
    );

_Must_inspect_result_
typedef
BOOLEAN(
NTAPI*
RTLPREFIXSTRING)(
    _In_ PSTRING String1,
    _In_ PSTRING String2,
    _In_ BOOLEAN CaseInSensitive
    );

typedef
NTSTATUS(
NTAPI*
RTLAPPENDSTRINGTOSTRING)(
    _Inout_ PSTRING Destination,
    _In_ PSTRING Source
    );

typedef
NTSTATUS(
NTAPI*
RTLAPPENDASCIIZTOSTRING)(
    _In_ PSTRING Destination,
    _In_opt_ PCSTR Source
    );

typedef
VOID(
NTAPI*
RTLUPPERSTRING)(
    _Inout_ PSTRING DestinationString,
    _In_ const STRING* SourceString
    );

FORCEINLINE
BOOLEAN
RtlIsNullOrEmptyUnicodeString(
    _In_opt_ PUNICODE_STRING String
    )
{
    return !String || String->Length == 0;
}

FORCEINLINE
VOID
NTAPI
RtlInitEmptyUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _Writable_bytes_(MaximumLength) _When_(MaximumLength != 0, _Notnull_) PWCHAR Buffer,
    _In_ USHORT MaximumLength
    )
{
    memset(DestinationString, 0, sizeof(UNICODE_STRING));
    DestinationString->MaximumLength = MaximumLength;
    DestinationString->Buffer = Buffer;
}

#ifndef PHNT_NO_INLINE_INIT_STRING
FORCEINLINE VOID RtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_ PCWSTR SourceString
    )
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PWCH)SourceString;
}
#else
typedef
VOID(
NTAPI*
RTLINITUNICODESTRING)(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_z_ PCWSTR SourceString
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLINITUNICODESTRINGEX)(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_z_ PCWSTR SourceString
    );

_Success_(return != 0)
_Must_inspect_result_
typedef
BOOLEAN(
NTAPI*
RTLCREATEUNICODESTRING)(
    _Out_ PUNICODE_STRING DestinationString,
    _In_z_ PCWSTR SourceString
    );

typedef
BOOLEAN(
NTAPI*
RTLCREATEUNICODESTRINGFROMASCIIZ)(
    _Out_ PUNICODE_STRING DestinationString,
    _In_ PCSTR SourceString
    );

typedef
VOID(
NTAPI*
RTLFREEUNICODESTRING)(
    _Inout_ _At_(UnicodeString->Buffer, _Frees_ptr_opt_) PUNICODE_STRING UnicodeString
    );

#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE (0x00000001)
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING (0x00000002)

typedef
NTSTATUS(
NTAPI*
RTLDUPLICATEUNICODESTRING)(
    _In_ ULONG Flags,
    _In_ PUNICODE_STRING StringIn,
    _Out_ PUNICODE_STRING StringOut
    );

typedef
VOID(
NTAPI*
RTLCOPYUNICODESTRING)(
    _In_ PUNICODE_STRING DestinationString,
    _In_opt_ PCUNICODE_STRING SourceString
    );

typedef
WCHAR(
NTAPI*
RTLUPCASEUNICODECHAR)(
    _In_ WCHAR SourceCharacter
    );

typedef
WCHAR(
NTAPI*
RTLDOWNCASEUNICODECHAR)(
    _In_ WCHAR SourceCharacter
    );

_Must_inspect_result_
typedef
LONG(
NTAPI*
RTLCOMPAREUNICODESTRING)(
    _In_ PUNICODE_STRING String1,
    _In_ PUNICODE_STRING String2,
    _In_ BOOLEAN CaseInSensitive
    );

#if (PHNT_VERSION >= PHNT_VISTA)
_Must_inspect_result_
typedef
LONG(
NTAPI*
RTLCOMPAREUNICODESTRINGS)(
    _In_reads_(String1Length) PCWCH String1,
    _In_ SIZE_T String1Length,
    _In_reads_(String2Length) PCWCH String2,
    _In_ SIZE_T String2Length,
    _In_ BOOLEAN CaseInSensitive
    );
#endif

_Must_inspect_result_
typedef
BOOLEAN(
NTAPI*
RTLEQUALUNICODESTRING)(
    _In_ PUNICODE_STRING String1,
    _In_ PUNICODE_STRING String2,
    _In_ BOOLEAN CaseInSensitive
    );

#define HASH_STRING_ALGORITHM_DEFAULT 0
#define HASH_STRING_ALGORITHM_X65599 1
#define HASH_STRING_ALGORITHM_INVALID 0xffffffff

typedef
NTSTATUS(
NTAPI*
RTLHASHUNICODESTRING)(
    _In_ PUNICODE_STRING String,
    _In_ BOOLEAN CaseInSensitive,
    _In_ ULONG HashAlgorithm,
    _Out_ PULONG HashValue
    );

typedef
NTSTATUS(
NTAPI*
RTLVALIDATEUNICODESTRING)(
    _In_ ULONG Flags,
    _In_ PUNICODE_STRING String
    );

_Must_inspect_result_
typedef
BOOLEAN(
NTAPI*
RTLPREFIXUNICODESTRING)(
    _In_ PUNICODE_STRING String1,
    _In_ PUNICODE_STRING String2,
    _In_ BOOLEAN CaseInSensitive
    );

#if (PHNT_MODE == PHNT_MODE_KERNEL && PHNT_VERSION >= PHNT_THRESHOLD)
_Must_inspect_result_
typedef
BOOLEAN(
NTAPI*
RTLSUFFIXUNICODESTRING)(
    _In_ PUNICODE_STRING String1,
    _In_ PUNICODE_STRING String2,
    _In_ BOOLEAN CaseInSensitive
    );
#endif

#if (PHNT_VERSION >= PHNT_THRESHOLD)
_Must_inspect_result_
typedef
PWCHAR(
NTAPI*
RTLFINDUNICODESUBSTRING)(
    _In_ PUNICODE_STRING FullString,
    _In_ PUNICODE_STRING SearchString,
    _In_ BOOLEAN CaseInSensitive
    );
#endif

#define RTL_FIND_CHAR_IN_UNICODE_STRING_START_AT_END 0x00000001
#define RTL_FIND_CHAR_IN_UNICODE_STRING_COMPLEMENT_CHAR_SET 0x00000002
#define RTL_FIND_CHAR_IN_UNICODE_STRING_CASE_INSENSITIVE 0x00000004

typedef
NTSTATUS(
NTAPI*
RTLFINDCHARINUNICODESTRING)(
    _In_ ULONG Flags,
    _In_ PUNICODE_STRING StringToSearch,
    _In_ PUNICODE_STRING CharSet,
    _Out_ PUSHORT NonInclusivePrefixLength
    );

typedef
NTSTATUS(
NTAPI*
RTLAPPENDUNICODESTRINGTOSTRING)(
    _In_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    );

typedef
NTSTATUS(
NTAPI*
RTLAPPENDUNICODETOSTRING)(
    _In_ PUNICODE_STRING Destination,
    _In_opt_ PCWSTR Source
    );

typedef
NTSTATUS(
NTAPI*
RTLUPCASEUNICODESTRING)(
    _Inout_ PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );

typedef
NTSTATUS(
NTAPI*
RTLDOWNCASEUNICODESTRING)(
    _Inout_ PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );

typedef
VOID(
NTAPI*
RTLERASEUNICODESTRING)(
    _Inout_ PUNICODE_STRING String
    );

typedef
NTSTATUS(
NTAPI*
RTLANSISTRINGTOUNICODESTRING)(
    _Inout_ PUNICODE_STRING DestinationString,
    _In_ PANSI_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );

typedef
NTSTATUS(
NTAPI*
RTLUNICODESTRINGTOANSISTRING)(
    _Inout_ PANSI_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );

#if (PHNT_VERSION >= PHNT_20H1)
typedef
NTSTATUS(
NTAPI*
RTLUNICODESTRINGTOUTF8STRING)(
    _Inout_ PUTF8_STRING DestinationString,
    _In_ PCUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );

typedef
NTSTATUS(
NTAPI*
RTLUTF8STRINGTOUNICODESTRING)(
    _Inout_ PUNICODE_STRING DestinationString,
    _In_ PUTF8_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );
#endif

typedef
WCHAR(
NTAPI*
RTLANSICHARTOUNICODECHAR)(
    _Inout_ PUCHAR *SourceCharacter
    );

typedef
NTSTATUS(
NTAPI*
RTLUPCASEUNICODESTRINGTOANSISTRING)(
    _Inout_ PANSI_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );

typedef
NTSTATUS(
NTAPI*
RTLOEMSTRINGTOUNICODESTRING)(
    _Inout_ PUNICODE_STRING DestinationString,
    _In_ POEM_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );

typedef
NTSTATUS(
NTAPI*
RTLUNICODESTRINGTOOEMSTRING)(
    _Inout_ POEM_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );

typedef
NTSTATUS(
NTAPI*
RTLUPCASEUNICODESTRINGTOOEMSTRING)(
    _Inout_ POEM_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );

typedef
NTSTATUS(
NTAPI*
RTLOEMSTRINGTOCOUNTEDUNICODESTRING)(
    _Inout_ PUNICODE_STRING DestinationString,
    _In_ PCOEM_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );

typedef
NTSTATUS(
NTAPI*
RTLUNICODESTRINGTOCOUNTEDOEMSTRING)(
    _Inout_ POEM_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );

typedef
NTSTATUS(
NTAPI*
RTLUPCASEUNICODESTRINGTOCOUNTEDOEMSTRING)(
    _Inout_ POEM_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );

typedef
NTSTATUS(
NTAPI*
RTLMULTIBYTETOUNICODEN)(
    _Out_writes_bytes_to_(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
    _In_ ULONG MaxBytesInUnicodeString,
    _Out_opt_ PULONG BytesInUnicodeString,
    _In_reads_bytes_(BytesInMultiByteString) PCSTR MultiByteString,
    _In_ ULONG BytesInMultiByteString
    );

typedef
NTSTATUS(
NTAPI*
RTLMULTIBYTETOUNICODESIZE)(
    _Out_ PULONG BytesInUnicodeString,
    _In_reads_bytes_(BytesInMultiByteString) PCSTR MultiByteString,
    _In_ ULONG BytesInMultiByteString
    );

typedef
NTSTATUS(
NTAPI*
RTLUNICODETOMULTIBYTEN)(
    _Out_writes_bytes_to_(MaxBytesInMultiByteString, *BytesInMultiByteString) PCHAR MultiByteString,
    _In_ ULONG MaxBytesInMultiByteString,
    _Out_opt_ PULONG BytesInMultiByteString,
    _In_reads_bytes_(BytesInUnicodeString) PCWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
    );

typedef
NTSTATUS(
NTAPI*
RTLUNICODETOMULTIBYTESIZE)(
    _Out_ PULONG BytesInMultiByteString,
    _In_reads_bytes_(BytesInUnicodeString) PCWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
    );

typedef
NTSTATUS(
NTAPI*
RTLUPCASEUNICODETOMULTIBYTEN)(
    _Out_writes_bytes_to_(MaxBytesInMultiByteString, *BytesInMultiByteString) PCHAR MultiByteString,
    _In_ ULONG MaxBytesInMultiByteString,
    _Out_opt_ PULONG BytesInMultiByteString,
    _In_reads_bytes_(BytesInUnicodeString) PCWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
    );

typedef
NTSTATUS(
NTAPI*
RTLOEMTOUNICODEN)(
    _Out_writes_bytes_to_(MaxBytesInUnicodeString, *BytesInUnicodeString) PWSTR UnicodeString,
    _In_ ULONG MaxBytesInUnicodeString,
    _Out_opt_ PULONG BytesInUnicodeString,
    _In_reads_bytes_(BytesInOemString) PCCH OemString,
    _In_ ULONG BytesInOemString
    );

typedef
NTSTATUS(
NTAPI*
RTLUNICODETOOEMN)(
    _Out_writes_bytes_to_(MaxBytesInOemString, *BytesInOemString) PCHAR OemString,
    _In_ ULONG MaxBytesInOemString,
    _Out_opt_ PULONG BytesInOemString,
    _In_reads_bytes_(BytesInUnicodeString) PCWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
    );

typedef
NTSTATUS(
NTAPI*
RTLUPCASEUNICODETOOEMN)(
    _Out_writes_bytes_to_(MaxBytesInOemString, *BytesInOemString) PCHAR OemString,
    _In_ ULONG MaxBytesInOemString,
    _Out_opt_ PULONG BytesInOemString,
    _In_reads_bytes_(BytesInUnicodeString) PCWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
    );

typedef
NTSTATUS(
NTAPI*
RTLCONSOLEMULTIBYTETOUNICODEN)(
    _Out_writes_bytes_to_(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
    _In_ ULONG MaxBytesInUnicodeString,
    _Out_opt_ PULONG BytesInUnicodeString,
    _In_reads_bytes_(BytesInMultiByteString) PCCH MultiByteString,
    _In_ ULONG BytesInMultiByteString,
    _Out_ PULONG pdwSpecialChar
    );

#if (PHNT_VERSION >= PHNT_WIN7)
typedef
NTSTATUS(
NTAPI*
RTLUTF8TOUNICODEN)(
    _Out_writes_bytes_to_(UnicodeStringMaxByteCount, *UnicodeStringActualByteCount) PWSTR UnicodeStringDestination,
    _In_ ULONG UnicodeStringMaxByteCount,
    _Out_ PULONG UnicodeStringActualByteCount,
    _In_reads_bytes_(UTF8StringByteCount) PCCH UTF8StringSource,
    _In_ ULONG UTF8StringByteCount
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN7)
typedef
NTSTATUS(
NTAPI*
RTLUNICODETOUTF8N)(
    _Out_writes_bytes_to_(UTF8StringMaxByteCount, *UTF8StringActualByteCount) PCHAR UTF8StringDestination,
    _In_ ULONG UTF8StringMaxByteCount,
    _Out_ PULONG UTF8StringActualByteCount,
    _In_reads_bytes_(UnicodeStringByteCount) PCWCH UnicodeStringSource,
    _In_ ULONG UnicodeStringByteCount
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLCUSTOMCPTOUNICODEN)(
    _In_ PCPTABLEINFO CustomCP,
    _Out_writes_bytes_to_(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
    _In_ ULONG MaxBytesInUnicodeString,
    _Out_opt_ PULONG BytesInUnicodeString,
    _In_reads_bytes_(BytesInCustomCPString) PCH CustomCPString,
    _In_ ULONG BytesInCustomCPString
    );

typedef
NTSTATUS(
NTAPI*
RTLUNICODETOCUSTOMCPN)(
    _In_ PCPTABLEINFO CustomCP,
    _Out_writes_bytes_to_(MaxBytesInCustomCPString, *BytesInCustomCPString) PCH CustomCPString,
    _In_ ULONG MaxBytesInCustomCPString,
    _Out_opt_ PULONG BytesInCustomCPString,
    _In_reads_bytes_(BytesInUnicodeString) PWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
    );

typedef
NTSTATUS(
NTAPI*
RTLUPCASEUNICODETOCUSTOMCPN)(
    _In_ PCPTABLEINFO CustomCP,
    _Out_writes_bytes_to_(MaxBytesInCustomCPString, *BytesInCustomCPString) PCH CustomCPString,
    _In_ ULONG MaxBytesInCustomCPString,
    _Out_opt_ PULONG BytesInCustomCPString,
    _In_reads_bytes_(BytesInUnicodeString) PWCH UnicodeString,
    _In_ ULONG BytesInUnicodeString
    );

typedef
VOID(
NTAPI*
RTLINITCODEPAGETABLE)(
    _In_reads_z_(2) PUSHORT TableBase,
    _Inout_ PCPTABLEINFO CodePageTable
    );

typedef
VOID(
NTAPI*
RTLINITNLSTABLES)(
    _In_ PUSHORT AnsiNlsBase,
    _In_ PUSHORT OemNlsBase,
    _In_ PUSHORT LanguageNlsBase,
    _Out_ PNLSTABLEINFO TableInfo // PCPTABLEINFO?
    );

typedef
VOID(
NTAPI*
RTLRESETRTLTRANSLATIONS)(
    _In_ PNLSTABLEINFO TableInfo
    );

typedef
BOOLEAN(
NTAPI*
RTLISTEXTUNICODE)(
    _In_ PVOID Buffer,
    _In_ ULONG Size,
    _Inout_opt_ PULONG Result
    );

typedef enum _RTL_NORM_FORM
{
    NormOther = 0x0,
    NormC = 0x1,
    NormD = 0x2,
    NormKC = 0x5,
    NormKD = 0x6,
    NormIdna = 0xd,
    DisallowUnassigned = 0x100,
    NormCDisallowUnassigned = 0x101,
    NormDDisallowUnassigned = 0x102,
    NormKCDisallowUnassigned = 0x105,
    NormKDDisallowUnassigned = 0x106,
    NormIdnaDisallowUnassigned = 0x10d
} RTL_NORM_FORM;

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
RTLNORMALIZESTRING)(
    _In_ ULONG NormForm, // RTL_NORM_FORM
    _In_ PCWSTR SourceString,
    _In_ LONG SourceStringLength,
    _Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
    _Inout_ PLONG DestinationStringLength
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
NTSTATUS(
NTAPI*
RTLISNORMALIZEDSTRING)(
    _In_ ULONG NormForm, // RTL_NORM_FORM
    _In_ PCWSTR SourceString,
    _In_ LONG SourceStringLength,
    _Out_ PBOOLEAN Normalized
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN7)
// ntifs:FsRtlIsNameInExpression
typedef
BOOLEAN(
NTAPI*
RTLISNAMEINEXPRESSION)(
    _In_ PUNICODE_STRING Expression,
    _In_ PUNICODE_STRING Name,
    _In_ BOOLEAN IgnoreCase,
    _In_opt_ PWCH UpcaseTable
    );
#endif

#if (PHNT_VERSION >= PHNT_REDSTONE4)
// rev
typedef
BOOLEAN(
NTAPI*
RTLISNAMEINUNUPCASEDEXPRESSION)(
    _In_ PUNICODE_STRING Expression,
    _In_ PUNICODE_STRING Name,
    _In_ BOOLEAN IgnoreCase,
    _In_opt_ PWCH UpcaseTable
    );
#endif

#if (PHNT_VERSION >= PHNT_19H1)
typedef
BOOLEAN(
NTAPI*
RTLDOESNAMECONTAINWILDCARDS)(
    _In_ PUNICODE_STRING Expression
    );
#endif

typedef
BOOLEAN(
NTAPI*
RTLEQUALDOMAINNAME)(
    _In_ PUNICODE_STRING String1,
    _In_ PUNICODE_STRING String2
    );

typedef
BOOLEAN(
NTAPI*
RTLEQUALCOMPUTERNAME)(
    _In_ PUNICODE_STRING String1,
    _In_ PUNICODE_STRING String2
    );

typedef
NTSTATUS(
NTAPI*
RTLDNSHOSTNAMETOCOMPUTERNAME)(
    _Out_ PUNICODE_STRING ComputerNameString,
    _In_ PUNICODE_STRING DnsHostNameString,
    _In_ BOOLEAN AllocateComputerNameString
    );

typedef
NTSTATUS(
NTAPI*
RTLSTRINGFROMGUID)(
    _In_ PGUID Guid,
    _Out_ PUNICODE_STRING GuidString
    );

#if (PHNT_VERSION >= PHNT_WINBLUE)

// rev
typedef
NTSTATUS(
NTAPI*
RTLSTRINGFROMGUIDEX)(
    _In_ PGUID Guid,
    _Inout_ PUNICODE_STRING GuidString,
    _In_ BOOLEAN AllocateGuidString
    );

#endif

typedef
NTSTATUS(
NTAPI*
RTLGUIDFROMSTRING)(
    _In_ PUNICODE_STRING GuidString,
    _Out_ PGUID Guid
    );

#if (PHNT_VERSION >= PHNT_VISTA)

typedef
LONG(
NTAPI*
RTLCOMPAREALTITUDES)(
    _In_ PUNICODE_STRING Altitude1,
    _In_ PUNICODE_STRING Altitude2
    );

typedef
NTSTATUS(
NTAPI*
RTLIDNTOASCII)(
    _In_ ULONG Flags,
    _In_ PCWSTR SourceString,
    _In_ LONG SourceStringLength,
    _Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
    _Inout_ PLONG DestinationStringLength
    );

typedef
NTSTATUS(
NTAPI*
RTLIDNTOUNICODE)(
    _In_ ULONG Flags,
    _In_ PCWSTR SourceString,
    _In_ LONG SourceStringLength,
    _Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
    _Inout_ PLONG DestinationStringLength
    );

typedef
NTSTATUS(
NTAPI*
RTLIDNTONAMEPREPUNICODE)(
    _In_ ULONG Flags,
    _In_ PCWSTR SourceString,
    _In_ LONG SourceStringLength,
    _Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
    _Inout_ PLONG DestinationStringLength
    );

#endif

// Prefix

typedef struct _PREFIX_TABLE_ENTRY
{
    CSHORT NodeTypeCode;
    CSHORT NameLength;
    struct _PREFIX_TABLE_ENTRY *NextPrefixTree;
    RTL_SPLAY_LINKS Links;
    PSTRING Prefix;
} PREFIX_TABLE_ENTRY, *PPREFIX_TABLE_ENTRY;

typedef struct _PREFIX_TABLE
{
    CSHORT NodeTypeCode;
    CSHORT NameLength;
    PPREFIX_TABLE_ENTRY NextPrefixTree;
} PREFIX_TABLE, *PPREFIX_TABLE;

typedef
VOID(
NTAPI*
PFXINITIALIZE)(
    _Out_ PPREFIX_TABLE PrefixTable
    );

typedef
BOOLEAN(
NTAPI*
PFXINSERTPREFIX)(
    _In_ PPREFIX_TABLE PrefixTable,
    _In_ PSTRING Prefix,
    _Out_ PPREFIX_TABLE_ENTRY PrefixTableEntry
    );

typedef
VOID(
NTAPI*
PFXREMOVEPREFIX)(
    _In_ PPREFIX_TABLE PrefixTable,
    _In_ PPREFIX_TABLE_ENTRY PrefixTableEntry
    );

typedef
PPREFIX_TABLE_ENTRY(
NTAPI*
PFXFINDPREFIX)(
    _In_ PPREFIX_TABLE PrefixTable,
    _In_ PSTRING FullName
    );

typedef struct _UNICODE_PREFIX_TABLE_ENTRY
{
    CSHORT NodeTypeCode;
    CSHORT NameLength;
    struct _UNICODE_PREFIX_TABLE_ENTRY *NextPrefixTree;
    struct _UNICODE_PREFIX_TABLE_ENTRY *CaseMatch;
    RTL_SPLAY_LINKS Links;
    PUNICODE_STRING Prefix;
} UNICODE_PREFIX_TABLE_ENTRY, *PUNICODE_PREFIX_TABLE_ENTRY;

typedef struct _UNICODE_PREFIX_TABLE
{
    CSHORT NodeTypeCode;
    CSHORT NameLength;
    PUNICODE_PREFIX_TABLE_ENTRY NextPrefixTree;
    PUNICODE_PREFIX_TABLE_ENTRY LastNextEntry;
} UNICODE_PREFIX_TABLE, *PUNICODE_PREFIX_TABLE;

typedef
VOID(
NTAPI*
RTLINITIALIZEUNICODEPREFIX)(
    _Out_ PUNICODE_PREFIX_TABLE PrefixTable
    );

typedef
BOOLEAN(
NTAPI*
RTLINSERTUNICODEPREFIX)(
    _In_ PUNICODE_PREFIX_TABLE PrefixTable,
    _In_ PUNICODE_STRING Prefix,
    _Out_ PUNICODE_PREFIX_TABLE_ENTRY PrefixTableEntry
    );

typedef
VOID(
NTAPI*
RTLREMOVEUNICODEPREFIX)(
    _In_ PUNICODE_PREFIX_TABLE PrefixTable,
    _In_ PUNICODE_PREFIX_TABLE_ENTRY PrefixTableEntry
    );

typedef
PUNICODE_PREFIX_TABLE_ENTRY(
NTAPI*
RTLFINDUNICODEPREFIX)(
    _In_ PUNICODE_PREFIX_TABLE PrefixTable,
    _In_ PUNICODE_STRING FullName,
    _In_ ULONG CaseInsensitiveIndex
    );

typedef
PUNICODE_PREFIX_TABLE_ENTRY(
NTAPI*
RTLNEXTUNICODEPREFIX)(
    _In_ PUNICODE_PREFIX_TABLE PrefixTable,
    _In_ BOOLEAN Restart
    );

// Compression

typedef struct _COMPRESSED_DATA_INFO
{
    USHORT CompressionFormatAndEngine; // COMPRESSION_FORMAT_* and COMPRESSION_ENGINE_*

    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved;

    USHORT NumberOfChunks;

    ULONG CompressedChunkSizes[1];
} COMPRESSED_DATA_INFO, *PCOMPRESSED_DATA_INFO;

typedef
NTSTATUS(
NTAPI*
RTLGETCOMPRESSIONWORKSPACESIZE)(
    _In_ USHORT CompressionFormatAndEngine,
    _Out_ PULONG CompressBufferWorkSpaceSize,
    _Out_ PULONG CompressFragmentWorkSpaceSize
    );

typedef
NTSTATUS(
NTAPI*
RTLCOMPRESSBUFFER)(
    _In_ USHORT CompressionFormatAndEngine,
    _In_reads_bytes_(UncompressedBufferSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _Out_writes_bytes_to_(CompressedBufferSize, *FinalCompressedSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _In_ ULONG UncompressedChunkSize,
    _Out_ PULONG FinalCompressedSize,
    _In_ PVOID WorkSpace
    );

typedef
NTSTATUS(
NTAPI*
RTLDECOMPRESSBUFFER)(
    _In_ USHORT CompressionFormat,
    _Out_writes_bytes_to_(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _Out_ PULONG FinalUncompressedSize
    );

#if (PHNT_VERSION >= PHNT_WIN8)
typedef
NTSTATUS(
NTAPI*
RTLDECOMPRESSBUFFEREX)(
    _In_ USHORT CompressionFormat,
    _Out_writes_bytes_to_(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _Out_ PULONG FinalUncompressedSize,
    _In_opt_ PVOID WorkSpace
    );
#endif

#if (PHNT_VERSION >= PHNT_WINBLUE)
typedef
NTSTATUS(
NTAPI*
RTLDECOMPRESSBUFFEREX2)(
    _In_ USHORT CompressionFormat,
    _Out_writes_bytes_to_(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _In_ ULONG UncompressedChunkSize,
    _Out_ PULONG FinalUncompressedSize,
    _In_opt_ PVOID WorkSpace
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLDECOMPRESSFRAGMENT)(
    _In_ USHORT CompressionFormat,
    _Out_writes_bytes_to_(UncompressedFragmentSize, *FinalUncompressedSize) PUCHAR UncompressedFragment,
    _In_ ULONG UncompressedFragmentSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _In_range_(<, CompressedBufferSize) ULONG FragmentOffset,
    _Out_ PULONG FinalUncompressedSize,
    _In_ PVOID WorkSpace
    );

#if (PHNT_VERSION >= PHNT_WINBLUE)
typedef
NTSTATUS(
NTAPI*
RTLDECOMPRESSFRAGMENTEX)(
    _In_ USHORT CompressionFormat,
    _Out_writes_bytes_to_(UncompressedFragmentSize, *FinalUncompressedSize) PUCHAR UncompressedFragment,
    _In_ ULONG UncompressedFragmentSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _In_range_(<, CompressedBufferSize) ULONG FragmentOffset,
    _In_ ULONG UncompressedChunkSize,
    _Out_ PULONG FinalUncompressedSize,
    _In_ PVOID WorkSpace
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLDESCRIBECHUNK)(
    _In_ USHORT CompressionFormat,
    _Inout_ PUCHAR *CompressedBuffer,
    _In_ PUCHAR EndOfCompressedBufferPlus1,
    _Out_ PUCHAR *ChunkBuffer,
    _Out_ PULONG ChunkSize
    );

typedef
NTSTATUS(
NTAPI*
RTLRESERVECHUNK)(
    _In_ USHORT CompressionFormat,
    _Inout_ PUCHAR *CompressedBuffer,
    _In_ PUCHAR EndOfCompressedBufferPlus1,
    _Out_ PUCHAR *ChunkBuffer,
    _In_ ULONG ChunkSize
    );

typedef
NTSTATUS(
NTAPI*
RTLDECOMPRESSCHUNKS)(
    _Out_writes_bytes_(UncompressedBufferSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _In_reads_bytes_(CompressedTailSize) PUCHAR CompressedTail,
    _In_ ULONG CompressedTailSize,
    _In_ PCOMPRESSED_DATA_INFO CompressedDataInfo
    );

typedef
NTSTATUS(
NTAPI*
RTLCOMPRESSCHUNKS)(
    _In_reads_bytes_(UncompressedBufferSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _Out_writes_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_range_(>=, (UncompressedBufferSize - (UncompressedBufferSize / 16))) ULONG CompressedBufferSize,
    _Inout_updates_bytes_(CompressedDataInfoLength) PCOMPRESSED_DATA_INFO CompressedDataInfo,
    _In_range_(>, sizeof(COMPRESSED_DATA_INFO)) ULONG CompressedDataInfoLength,
    _In_ PVOID WorkSpace
    );

// Locale

#if (PHNT_VERSION >= PHNT_VISTA)

// private
typedef
NTSTATUS(
NTAPI*
RTLCONVERTLCIDTOSTRING)(
    _In_ LCID LcidValue,
    _In_ ULONG Base,
    _In_ ULONG Padding, // string is padded to this width
    _Out_writes_(Size) PWSTR pResultBuf,
    _In_ ULONG Size
    );

// private
typedef
BOOLEAN(
NTAPI*
RTLISVALIDLOCALENAME)(
    _In_ PCWSTR LocaleName,
    _In_ ULONG Flags
    );

// private
typedef
NTSTATUS(
NTAPI*
RTLGETPARENTLOCALENAME)(
    _In_ PCWSTR LocaleName,
    _Inout_ PUNICODE_STRING ParentLocaleName,
    _In_ ULONG Flags,
    _In_ BOOLEAN AllocateDestinationString
    );

// private
typedef
NTSTATUS(
NTAPI*
RTLLCIDTOLOCALENAME)(
    _In_ LCID lcid, // sic
    _Inout_ PUNICODE_STRING LocaleName,
    _In_ ULONG Flags,
    _In_ BOOLEAN AllocateDestinationString
    );

// private
typedef
NTSTATUS(
NTAPI*
RTLLOCALENAMETOLCID)(
    _In_ PCWSTR LocaleName,
    _Out_ PLCID lcid,
    _In_ ULONG Flags
    );

// private
typedef
BOOLEAN(
NTAPI*
RTLLCIDTOCULTURENAME)(
    _In_ LCID Lcid,
    _Inout_ PUNICODE_STRING String
    );

// private
typedef
BOOLEAN(
NTAPI*
RTLCULTURENAMETOLCID)(
    _In_ PUNICODE_STRING String,
    _Out_ PLCID Lcid
    );

// private
typedef
VOID(
NTAPI*
RTLCLEANUPTEBLANGLISTS)(
    VOID
    );

#endif

#if (PHNT_VERSION >= PHNT_WIN7)

// rev
typedef
NTSTATUS(
NTAPI*
RTLGETLOCALEFILEMAPPINGADDRESS)(
    _Out_ PVOID *BaseAddress,
    _Out_ PLCID DefaultLocaleId,
    _Out_ PLARGE_INTEGER DefaultCasingTableSize
    );

#endif

// PEB

typedef
PPEB(
NTAPI*
RTLGETCURRENTPEB)(
    VOID
    );

typedef
VOID(
NTAPI*
RTLACQUIREPEBLOCK)(
    VOID
    );

typedef
VOID(
NTAPI*
RTLRELEASEPEBLOCK)(
    VOID
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
LOGICAL(
NTAPI*
RTLTRYACQUIREPEBLOCK)(
    VOID
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLALLOCATEFROMPEB)(
    _In_ ULONG Size,
    _Out_ PVOID *Block
    );

typedef
NTSTATUS(
NTAPI*
RTLFREETOPEB)(
    _In_ PVOID Block,
    _In_ ULONG Size
    );

// Processes

#define DOS_MAX_COMPONENT_LENGTH 255
#define DOS_MAX_PATH_LENGTH (DOS_MAX_COMPONENT_LENGTH + 5)

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

#define RTL_USER_PROC_CURDIR_CLOSE 0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;

    UNICODE_STRING RedirectionDllName; // REDSTONE4
    UNICODE_STRING HeapPartitionName; // 19H1
    ULONG_PTR DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#define RTL_USER_PROC_PROFILE_USER 0x00000002
#define RTL_USER_PROC_PROFILE_KERNEL 0x00000004
#define RTL_USER_PROC_PROFILE_SERVER 0x00000008
#define RTL_USER_PROC_RESERVE_1MB 0x00000020
#define RTL_USER_PROC_RESERVE_16MB 0x00000040
#define RTL_USER_PROC_CASE_SENSITIVE 0x00000080
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT 0x00000100
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL 0x00001000
#define RTL_USER_PROC_APP_MANIFEST_PRESENT 0x00002000
#define RTL_USER_PROC_IMAGE_KEY_MISSING 0x00004000
#define RTL_USER_PROC_OPTIN_PROCESS 0x00020000

typedef
NTSTATUS(
NTAPI*
RTLCREATEPROCESSPARAMETERS)(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
RTLCREATEPROCESSPARAMETERSEX)(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLDESTROYPROCESSPARAMETERS)(
    _In_ _Post_invalid_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );

typedef
PRTL_USER_PROCESS_PARAMETERS(
NTAPI*
RTLNORMALIZEPROCESSPARAMS)(
    _Inout_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );

typedef
PRTL_USER_PROCESS_PARAMETERS(
NTAPI*
RTLDENORMALIZEPROCESSPARAMS)(
    _Inout_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );

typedef struct _RTL_USER_PROCESS_INFORMATION
{
    ULONG Length;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

// private
typedef
NTSTATUS(
NTAPI*
RTLCREATEUSERPROCESS)(
    _In_ PUNICODE_STRING NtImagePathName,
    _In_ ULONG AttributesDeprecated,
    _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    _In_opt_ PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_opt_ HANDLE ParentProcess,
    _In_ BOOLEAN InheritHandles,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle, // used to be ExceptionPort
    _Out_ PRTL_USER_PROCESS_INFORMATION ProcessInformation
    );

#if (PHNT_VERSION >= PHNT_REDSTONE2)

#define RTL_USER_PROCESS_EXTENDED_PARAMETERS_VERSION 1

// private
typedef struct _RTL_USER_PROCESS_EXTENDED_PARAMETERS
{
    USHORT Version;
    USHORT NodeNumber;
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor;
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor;
    HANDLE ParentProcess;
    HANDLE DebugPort;
    HANDLE TokenHandle;
    HANDLE JobHandle;
} RTL_USER_PROCESS_EXTENDED_PARAMETERS, *PRTL_USER_PROCESS_EXTENDED_PARAMETERS;

typedef
NTSTATUS(
NTAPI*
RTLCREATEUSERPROCESSEX)(
    _In_ PUNICODE_STRING NtImagePathName,
    _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    _In_ BOOLEAN InheritHandles,
    _In_opt_ PRTL_USER_PROCESS_EXTENDED_PARAMETERS ProcessExtendedParameters,
    _Out_ PRTL_USER_PROCESS_INFORMATION ProcessInformation
    );

#endif

#if (PHNT_VERSION >= PHNT_VISTA)
DECLSPEC_NORETURN
typedef
VOID(
NTAPI*
RTLEXITUSERPROCESS)(
    _In_ NTSTATUS ExitStatus
    );
#else

#define RtlExitUserProcess RtlExitUserProcess_R

DECLSPEC_NORETURN
FORCEINLINE VOID RtlExitUserProcess_R(
    _In_ NTSTATUS ExitStatus
    )
{
    ExitProcess(ExitStatus);
}

#endif

#if (PHNT_VERSION >= PHNT_VISTA)

// begin_rev
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004 // don't update synchronization objects
// end_rev

// private
typedef
NTSTATUS(
NTAPI*
RTLCLONEUSERPROCESS)(
    _In_ ULONG ProcessFlags,
    _In_opt_ PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_opt_ HANDLE DebugPort,
    _Out_ PRTL_USER_PROCESS_INFORMATION ProcessInformation
    );

// private
typedef
VOID(
NTAPI*
RTLUPDATECLONEDCRITICALSECTION)(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
    );

// private
typedef
VOID(
NTAPI*
RTLUPDATECLONEDSRWLOCK)(
    _Inout_ PRTL_SRWLOCK SRWLock,
    _In_ LOGICAL Shared // TRUE to set to shared acquire
    );

// rev
#define RTL_PROCESS_REFLECTION_FLAGS_INHERIT_HANDLES 0x2
#define RTL_PROCESS_REFLECTION_FLAGS_NO_SUSPEND 0x4
#define RTL_PROCESS_REFLECTION_FLAGS_NO_SYNCHRONIZE 0x8
#define RTL_PROCESS_REFLECTION_FLAGS_NO_CLOSE_EVENT 0x10

// private
typedef struct _RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION
{
    HANDLE ReflectionProcessHandle;
    HANDLE ReflectionThreadHandle;
    CLIENT_ID ReflectionClientId;
} RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION, *PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;

#if (PHNT_VERSION >= PHNT_WIN7)
// rev
typedef
NTSTATUS(
NTAPI*
RTLCREATEPROCESSREFLECTION)(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG Flags, // RTL_PROCESS_REFLECTION_FLAGS_*
    _In_opt_ PVOID StartRoutine,
    _In_opt_ PVOID StartContext,
    _In_opt_ HANDLE EventHandle,
    _Out_opt_ PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION ReflectionInformation
    );
#endif

#endif

typedef
NTSTATUS(
STDAPIVCALLTYPE*
RTLSETPROCESSISCRITICAL)(
    _In_ BOOLEAN NewValue,
    _Out_opt_ PBOOLEAN OldValue,
    _In_ BOOLEAN CheckFlag
    );

typedef
NTSTATUS(
STDAPIVCALLTYPE*
RTLSETTHREADISCRITICAL)(
    _In_ BOOLEAN NewValue,
    _Out_opt_ PBOOLEAN OldValue,
    _In_ BOOLEAN CheckFlag
    );

// rev
typedef
BOOLEAN(
NTAPI*
RTLVALIDPROCESSPROTECTION)(
    _In_ PS_PROTECTION ProcessProtection
    );

// rev
typedef
BOOLEAN(
NTAPI*
RTLTESTPROTECTEDACCESS)(
    _In_ PS_PROTECTION Source,
    _In_ PS_PROTECTION Target
    );

#if (PHNT_VERSION >= PHNT_REDSTONE3)
// rev
typedef
BOOLEAN(
NTAPI*
RTLISCURRENTPROCESS)( // NtCompareObjects(NtCurrentProcess(), ProcessHandle)
    _In_ HANDLE ProcessHandle
    );

// rev
typedef
BOOLEAN(
NTAPI*
RTLISCURRENTTHREAD)( // NtCompareObjects(NtCurrentThread(), ThreadHandle)
    _In_ HANDLE ThreadHandle
    );
#endif

// Threads

typedef NTSTATUS (NTAPI *PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
    );

typedef
NTSTATUS(
NTAPI*
RTLCREATEUSERTHREAD)(
    _In_ HANDLE Process,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_ BOOLEAN CreateSuspended,
    _In_opt_ ULONG ZeroBits,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ SIZE_T CommittedStackSize,
    _In_ PUSER_THREAD_START_ROUTINE StartAddress,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PHANDLE Thread,
    _Out_opt_ PCLIENT_ID ClientId
    );

#if (PHNT_VERSION >= PHNT_VISTA) // should be PHNT_WINXP, but is PHNT_VISTA for consistency with RtlExitUserProcess
DECLSPEC_NORETURN
typedef
VOID(
NTAPI*
RTLEXITUSERTHREAD)(
    _In_ NTSTATUS ExitStatus
    );
#else

#define RtlExitUserThread RtlExitUserThread_R

DECLSPEC_NORETURN
FORCEINLINE VOID RtlExitUserThread_R(
    _In_ NTSTATUS ExitStatus
    )
{
    ExitThread(ExitStatus);
}

#endif

#if (PHNT_VERSION >= PHNT_VISTA)

// rev
typedef
BOOLEAN(
NTAPI*
RTLISCURRENTTHREADATTACHEXEMPT)(
    VOID
    );

#endif

#if (PHNT_VERSION >= PHNT_VISTA)

// private
typedef
NTSTATUS(
NTAPI*
RTLCREATEUSERSTACK)(
    _In_opt_ SIZE_T CommittedStackSize,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ ULONG_PTR ZeroBits,
    _In_ SIZE_T PageSize,
    _In_ ULONG_PTR ReserveAlignment,
    _Out_ PINITIAL_TEB InitialTeb
    );

// private
typedef
NTSTATUS(
NTAPI*
RTLFREEUSERSTACK)(
    _In_ PVOID AllocationBase
    );

#endif

// Extended thread context

typedef struct _CONTEXT_CHUNK 
{
    LONG Offset; // Offset may be negative.
    ULONG Length;
} CONTEXT_CHUNK, *PCONTEXT_CHUNK;

typedef struct _CONTEXT_EX 
{
    CONTEXT_CHUNK All;
    CONTEXT_CHUNK Legacy;
    CONTEXT_CHUNK XState;
} CONTEXT_EX, *PCONTEXT_EX;

#define CONTEXT_EX_LENGTH ALIGN_UP_BY(sizeof(CONTEXT_EX), PAGE_SIZE)
#define RTL_CONTEXT_EX_OFFSET(ContextEx, Chunk) ((ContextEx)->Chunk.Offset)
#define RTL_CONTEXT_EX_LENGTH(ContextEx, Chunk) ((ContextEx)->Chunk.Length)
#define RTL_CONTEXT_EX_CHUNK(Base, Layout, Chunk) ((PVOID)((PCHAR)(Base) + RTL_CONTEXT_EX_OFFSET(Layout, Chunk)))
#define RTL_CONTEXT_OFFSET(Context, Chunk) RTL_CONTEXT_EX_OFFSET((PCONTEXT_EX)(Context + 1), Chunk)
#define RTL_CONTEXT_LENGTH(Context, Chunk) RTL_CONTEXT_EX_LENGTH((PCONTEXT_EX)(Context + 1), Chunk)
#define RTL_CONTEXT_CHUNK(Context, Chunk) RTL_CONTEXT_EX_CHUNK((PCONTEXT_EX)(Context + 1), (PCONTEXT_EX)(Context + 1), Chunk)

typedef
VOID(
NTAPI*
RTLINITIALIZECONTEXT)(
    _In_ HANDLE Process,
    _Out_ PCONTEXT Context,
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID InitialPc,
    _In_opt_ PVOID InitialSp
    );

typedef
ULONG(
NTAPI*
RTLINITIALIZEEXTENDEDCONTEXT)(
    _Out_ PCONTEXT Context,
    _In_ ULONG ContextFlags,
    _Out_ PCONTEXT_EX* ContextEx
    );

typedef
NTSTATUS(
NTAPI*
RTLCOPYCONTEXT)(
    _Inout_ PCONTEXT Context,
    _In_ ULONG ContextFlags,
    _Out_ PCONTEXT Source
    );

typedef
ULONG(
NTAPI*
RTLCOPYEXTENDEDCONTEXT)(
    _Out_ PCONTEXT_EX Destination,
    _In_ ULONG ContextFlags,
    _In_ PCONTEXT_EX Source
    );

typedef
ULONG(
NTAPI*
RTLGETEXTENDEDCONTEXTLENGTH)(
    _In_ ULONG ContextFlags,
    _Out_ PULONG ContextLength
    );

typedef
ULONG64(
NTAPI*
RTLGETEXTENDEDFEATURESMASK)(
    _In_ PCONTEXT_EX ContextEx
    );

typedef
PVOID(
NTAPI*
RTLLOCATEEXTENDEDFEATURE)(
    _In_ PCONTEXT_EX ContextEx,
    _In_ ULONG FeatureId,
    _Out_opt_ PULONG Length
    );

typedef
PCONTEXT(
NTAPI*
RTLLOCATELEGACYCONTEXT)(
    _In_ PCONTEXT_EX ContextEx,
    _Out_opt_ PULONG Length
    );

typedef
VOID(
NTAPI*
RTLSETEXTENDEDFEATURESMASK)(
    _In_ PCONTEXT_EX ContextEx,
    _In_ ULONG64 FeatureMask
    );

#ifdef _WIN64
// rev
typedef
NTSTATUS(
NTAPI*
RTLWOW64GETTHREADCONTEXT)(
    _In_ HANDLE ThreadHandle,
    _Inout_ PWOW64_CONTEXT ThreadContext
    );
#endif

#ifdef _WIN64
// rev
typedef
NTSTATUS(
NTAPI*
RTLWOW64SETTHREADCONTEXT)(
    _In_ HANDLE ThreadHandle,
    _In_ PWOW64_CONTEXT ThreadContext
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLREMOTECALL)(
    _In_ HANDLE Process,
    _In_ HANDLE Thread,
    _In_ PVOID CallSite,
    _In_ ULONG ArgumentCount,
    _In_opt_ PULONG_PTR Arguments,
    _In_ BOOLEAN PassContext,
    _In_ BOOLEAN AlreadySuspended
    );

// Vectored Exception Handlers

typedef
PVOID(
NTAPI*
RTLADDVECTOREDEXCEPTIONHANDLER)(
    _In_ ULONG First,
    _In_ PVECTORED_EXCEPTION_HANDLER Handler
    );

typedef
ULONG(
NTAPI*
RTLREMOVEVECTOREDEXCEPTIONHANDLER)(
    _In_ PVOID Handle
    );

typedef
PVOID(
NTAPI*
RTLADDVECTOREDCONTINUEHANDLER)(
    _In_ ULONG First,
    _In_ PVECTORED_EXCEPTION_HANDLER Handler
    );

typedef
ULONG(
NTAPI*
RTLREMOVEVECTOREDCONTINUEHANDLER)(
    _In_ PVOID Handle
    );

// Runtime exception handling

typedef ULONG (NTAPI *PRTLP_UNHANDLED_EXCEPTION_FILTER)(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
    );

typedef
VOID(
NTAPI*
RTLSETUNHANDLEDEXCEPTIONFILTER)(
    _In_ PRTLP_UNHANDLED_EXCEPTION_FILTER UnhandledExceptionFilter
    );

// rev
typedef
LONG(
NTAPI*
RTLUNHANDLEDEXCEPTIONFILTER)(
    _In_ PEXCEPTION_POINTERS ExceptionPointers
    );

// rev
typedef
LONG(
NTAPI*
RTLUNHANDLEDEXCEPTIONFILTER2)(
    _In_ PEXCEPTION_POINTERS ExceptionPointers,
    _In_ ULONG Flags
    );

// rev
typedef
LONG(
NTAPI*
RTLKNOWNEXCEPTIONFILTER)(
    _In_ PEXCEPTION_POINTERS ExceptionPointers
    );

#ifdef _WIN64

// private
typedef enum _FUNCTION_TABLE_TYPE
{
    RF_SORTED,
    RF_UNSORTED,
    RF_CALLBACK,
    RF_KERNEL_DYNAMIC
} FUNCTION_TABLE_TYPE;

// private
typedef struct _DYNAMIC_FUNCTION_TABLE
{
    LIST_ENTRY ListEntry;
    PRUNTIME_FUNCTION FunctionTable;
    LARGE_INTEGER TimeStamp;
    ULONG64 MinimumAddress;
    ULONG64 MaximumAddress;
    ULONG64 BaseAddress;
    PGET_RUNTIME_FUNCTION_CALLBACK Callback;
    PVOID Context;
    PWSTR OutOfProcessCallbackDll;
    FUNCTION_TABLE_TYPE Type;
    ULONG EntryCount;
    RTL_BALANCED_NODE TreeNodeMin;
    RTL_BALANCED_NODE TreeNodeMax;
} DYNAMIC_FUNCTION_TABLE, *PDYNAMIC_FUNCTION_TABLE;

// rev
typedef
PLIST_ENTRY(
NTAPI*
RTLGETFUNCTIONTABLELISTHEAD)(
    VOID
    );

#endif

// Activation Contexts

// rev
typedef
NTSTATUS(
NTAPI*
RTLGETACTIVEACTIVATIONCONTEXT)(
    _Out_ HANDLE ActCtx
    );

// rev
typedef
VOID(
NTAPI*
RTLADDREFACTIVATIONCONTEXT)(
    _In_ HANDLE ActCtx
    );

// rev
typedef
VOID(
NTAPI*
RTLRELEASEACTIVATIONCONTEXT)(
    _In_ HANDLE ActCtx
    );

// Images

typedef
PIMAGE_NT_HEADERS(
NTAPI*
RTLIMAGENTHEADER)(
    _In_ PVOID BaseOfImage
    );

#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK 0x00000001

typedef
NTSTATUS(
NTAPI*
RTLIMAGENTHEADEREX)(
    _In_ ULONG Flags,
    _In_ PVOID BaseOfImage,
    _In_ ULONG64 Size,
    _Out_ PIMAGE_NT_HEADERS *OutHeaders
    );

typedef
PVOID(
NTAPI*
RTLADDRESSINSECTIONTABLE)(
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ PVOID BaseOfImage,
    _In_ ULONG VirtualAddress
    );

typedef
PIMAGE_SECTION_HEADER(
NTAPI*
RTLSECTIONTABLEFROMVIRTUALADDRESS)(
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ PVOID BaseOfImage,
    _In_ ULONG VirtualAddress
    );

typedef
PVOID(
NTAPI*
RTLIMAGEDIRECTORYENTRYTODATA)(
    _In_ PVOID BaseOfImage,
    _In_ BOOLEAN MappedAsImage,
    _In_ USHORT DirectoryEntry,
    _Out_ PULONG Size
    );

typedef
PIMAGE_SECTION_HEADER(
NTAPI*
RTLIMAGERVATOSECTION)(
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ PVOID BaseOfImage,
    _In_ ULONG Rva
    );

typedef
PVOID(
NTAPI*
RTLIMAGERVATOVA)(
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ PVOID BaseOfImage,
    _In_ ULONG Rva,
    _Out_opt_ PIMAGE_SECTION_HEADER *LastRvaSection
    );

#if (PHNT_VERSION >= PHNT_REDSTONE)

// rev
typedef
PVOID(
NTAPI*
RTLFINDEXPORTEDROUTINEBYNAME)(
    _In_ PVOID BaseOfImage,
    _In_ PCSTR RoutineName
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLGUARDCHECKLONGJUMPTARGET)(
    _In_ PVOID PcValue, 
    _In_ BOOL IsFastFail, 
    _Out_ PBOOL IsLongJumpTarget
    );

#endif

// Memory

_Must_inspect_result_
typedef
SIZE_T(
NTAPI*
RTLCOMPAREMEMORYULONG)(
    _In_reads_bytes_(Length) PVOID Source,
    _In_ SIZE_T Length,
    _In_ ULONG Pattern
    );

#if defined(_M_AMD64)
FORCEINLINE
VOID
RtlFillMemoryUlong(
    _Out_writes_bytes_all_(Length) PVOID Destination,
    _In_ SIZE_T Length,
    _In_ ULONG Pattern
    )
{
    PULONG Address = (PULONG)Destination;

    //
    // If the number of DWORDs is not zero, then fill the specified buffer
    // with the specified pattern.
    //

    if ((Length /= 4) != 0) {

        //
        // If the destination is not quadword aligned (ignoring low bits),
        // then align the destination by storing one DWORD.
        //

        if (((ULONG64)Address & 4) != 0) {
            *Address = Pattern;
            if ((Length -= 1) == 0) {
                return;
            }

            Address += 1;
        }

        //
        // If the number of QWORDs is not zero, then fill the destination
        // buffer a QWORD at a time.
        //

         __stosq((PULONG64)(Address),
                 Pattern | ((ULONG64)Pattern << 32),
                 Length / 2);

        if ((Length & 1) != 0) {
            Address[Length - 1] = Pattern;
        }
    }

    return;
}
#else
typedef
VOID(
NTAPI*
RTLFILLMEMORYULONG)(
    _Out_writes_bytes_all_(Length) PVOID Destination,
    _In_ SIZE_T Length,
    _In_ ULONG Pattern
    );
#endif

#if defined(_M_AMD64)

#define RtlFillMemoryUlonglong(Destination, Length, Pattern) \
    __stosq((PULONG64)(Destination), Pattern, (Length) / 8)

#else
typedef
VOID(
NTAPI*
RTLFILLMEMORYULONGLONG)(
    _Out_writes_bytes_all_(Length) PVOID Destination,
    _In_ SIZE_T Length,
    _In_ ULONGLONG Pattern
    );
#endif
// Environment

typedef
NTSTATUS(
NTAPI*
RTLCREATEENVIRONMENT)(
    _In_ BOOLEAN CloneCurrentEnvironment,
    _Out_ PVOID *Environment
    );

// begin_rev
#define RTL_CREATE_ENVIRONMENT_TRANSLATE 0x1 // translate from multi-byte to Unicode
#define RTL_CREATE_ENVIRONMENT_TRANSLATE_FROM_OEM 0x2 // translate from OEM to Unicode (Translate flag must also be set)
#define RTL_CREATE_ENVIRONMENT_EMPTY 0x4 // create empty environment block
// end_rev

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
RTLCREATEENVIRONMENTEX)(
    _In_ PVOID SourceEnv,
    _Out_ PVOID *Environment,
    _In_ ULONG Flags
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLDESTROYENVIRONMENT)(
    _In_ PVOID Environment
    );

typedef
NTSTATUS(
NTAPI*
RTLSETCURRENTENVIRONMENT)(
    _In_ PVOID Environment,
    _Out_opt_ PVOID *PreviousEnvironment
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
RTLSETENVIRONMENTVAR)(
    _Inout_opt_ PVOID *Environment,
    _In_reads_(NameLength) PCWSTR Name,
    _In_ SIZE_T NameLength,
    _In_reads_(ValueLength) PCWSTR Value,
    _In_ SIZE_T ValueLength
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLSETENVIRONMENTVARIABLE)(
    _Inout_opt_ PVOID *Environment,
    _In_ PUNICODE_STRING Name,
    _In_opt_ PUNICODE_STRING Value
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
RTLQUERYENVIRONMENTVARIABLE)(
    _In_opt_ PVOID Environment,
    _In_reads_(NameLength) PCWSTR Name,
    _In_ SIZE_T NameLength,
    _Out_writes_(ValueLength) PWSTR Value,
    _In_ SIZE_T ValueLength,
    _Out_ PSIZE_T ReturnLength
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLQUERYENVIRONMENTVARIABLE_U)(
    _In_opt_ PVOID Environment,
    _In_ PUNICODE_STRING Name,
    _Inout_ PUNICODE_STRING Value
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
RTLEXPANDENVIRONMENTSTRINGS)(
    _In_opt_ PVOID Environment,
    _In_reads_(SrcLength) PCWSTR Src,
    _In_ SIZE_T SrcLength,
    _Out_writes_(DstLength) PWSTR Dst,
    _In_ SIZE_T DstLength,
    _Out_opt_ PSIZE_T ReturnLength
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLEXPANDENVIRONMENTSTRINGS_U)(
    _In_opt_ PVOID Environment,
    _In_ PUNICODE_STRING Source,
    _Inout_ PUNICODE_STRING Destination,
    _Out_opt_ PULONG ReturnedLength
    );

typedef
NTSTATUS(
NTAPI*
RTLSETENVIRONMENTSTRINGS)(
    _In_ PCWCHAR NewEnvironment,
    _In_ SIZE_T NewEnvironmentSize
    );

// Directory and path support

typedef struct _RTLP_CURDIR_REF
{
    LONG ReferenceCount;
    HANDLE DirectoryHandle;
} RTLP_CURDIR_REF, *PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U
{
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

typedef enum _RTL_PATH_TYPE
{
    RtlPathTypeUnknown,
    RtlPathTypeUncAbsolute,
    RtlPathTypeDriveAbsolute,
    RtlPathTypeDriveRelative,
    RtlPathTypeRooted,
    RtlPathTypeRelative,
    RtlPathTypeLocalDevice,
    RtlPathTypeRootLocalDevice
} RTL_PATH_TYPE;

// Data exports (ntdll.lib/ntdllp.lib)

NTSYSAPI PWSTR RtlNtdllName;
NTSYSAPI UNICODE_STRING RtlDosPathSeperatorsString;
NTSYSAPI UNICODE_STRING RtlAlternateDosPathSeperatorString;
NTSYSAPI UNICODE_STRING RtlNtPathSeperatorString;

#ifndef PHNT_INLINE_SEPERATOR_STRINGS
#define RtlNtdllName L"ntdll.dll"
#define RtlDosPathSeperatorsString ((UNICODE_STRING)RTL_CONSTANT_STRING(L"\\/"))
#define RtlAlternateDosPathSeperatorString ((UNICODE_STRING)RTL_CONSTANT_STRING(L"/"))
#define RtlNtPathSeperatorString ((UNICODE_STRING)RTL_CONSTANT_STRING(L"\\"))
#endif

// Path functions

typedef
RTL_PATH_TYPE(
NTAPI*
RTLDETERMINEDOSPATHNAMETYPE_U)(
    _In_ PCWSTR DosFileName
    );

typedef
RTL_PATH_TYPE(
NTAPI*
RTLDETERMINEDOSPATHNAMETYPE_USTR)(
    _In_ PCUNICODE_STRING DosFileName
    );

typedef
ULONG(
NTAPI*
RTLISDOSDEVICENAME_U)(
    _In_ PCWSTR DosFileName
    );

typedef
ULONG(
NTAPI*
RTLISDOSDEVICENAME_USTR)(
    _In_ PUNICODE_STRING DosFileName
    );

typedef
ULONG(
NTAPI*
RTLGETFULLPATHNAME_U)(
    _In_ PCWSTR FileName,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_(BufferLength) PWSTR Buffer,
    _Out_opt_ PWSTR *FilePart
    );

#if (PHNT_VERSION >= PHNT_WIN7)
// rev
typedef
NTSTATUS(
NTAPI*
RTLGETFULLPATHNAME_UEX)(
    _In_ PCWSTR FileName,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_(BufferLength) PWSTR Buffer,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ ULONG *BytesRequired
    );
#endif

#if (PHNT_VERSION >= PHNT_WS03)
typedef
NTSTATUS(
NTAPI*
RTLGETFULLPATHNAME_USTREX)(
    _In_ PUNICODE_STRING FileName,
    _Inout_ PUNICODE_STRING StaticString,
    _Out_opt_ PUNICODE_STRING DynamicString,
    _Out_opt_ PUNICODE_STRING *StringUsed,
    _Out_opt_ SIZE_T *FilePartPrefixCch,
    _Out_opt_ PBOOLEAN NameInvalid,
    _Out_ RTL_PATH_TYPE *InputPathType,
    _Out_opt_ SIZE_T *BytesRequired
    );
#endif

typedef
ULONG(
NTAPI*
RTLGETCURRENTDIRECTORY_U)(
    _In_ ULONG BufferLength,
    _Out_writes_bytes_(BufferLength) PWSTR Buffer
    );

typedef
NTSTATUS(
NTAPI*
RTLSETCURRENTDIRECTORY_U)(
    _In_ PUNICODE_STRING PathName
    );

typedef
ULONG(
NTAPI*
RTLGETLONGESTNTPATHLENGTH)(
    VOID
    );

typedef
BOOLEAN(
NTAPI*
RTLDOSPATHNAMETONTPATHNAME_U)(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
    );

#if (PHNT_VERSION >= PHNT_WS03)
typedef
NTSTATUS(
NTAPI*
RTLDOSPATHNAMETONTPATHNAME_U_WITHSTATUS)(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
    );
#endif

#if (PHNT_VERSION >= PHNT_REDSTONE3)
// rev
typedef
NTSTATUS(
NTAPI*
RTLDOSLONGPATHNAMETONTPATHNAME_U_WITHSTATUS)(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
    );
#endif

#if (PHNT_VERSION >= PHNT_WS03)
typedef
BOOLEAN(
NTAPI*
RTLDOSPATHNAMETORELATIVENTPATHNAME_U)(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
    );
#endif

#if (PHNT_VERSION >= PHNT_WS03)
typedef
NTSTATUS(
NTAPI*
RTLDOSPATHNAMETORELATIVENTPATHNAME_U_WITHSTATUS)(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
    );
#endif

#if (PHNT_VERSION >= PHNT_REDSTONE3)
// rev
typedef
NTSTATUS(
NTAPI*
RTLDOSLONGPATHNAMETORELATIVENTPATHNAME_U_WITHSTATUS)(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
    );
#endif

#if (PHNT_VERSION >= PHNT_WS03)
typedef
VOID(
NTAPI*
RTLRELEASERELATIVENAME)(
    _Inout_ PRTL_RELATIVE_NAME_U RelativeName
    );
#endif

typedef
ULONG(
NTAPI*
RTLDOSSEARCHPATH_U)(
    _In_ PCWSTR Path,
    _In_ PCWSTR FileName,
    _In_opt_ PCWSTR Extension,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_(BufferLength) PWSTR Buffer,
    _Out_opt_ PWSTR *FilePart
    );

#define RTL_DOS_SEARCH_PATH_FLAG_APPLY_ISOLATION_REDIRECTION 0x00000001
#define RTL_DOS_SEARCH_PATH_FLAG_DISALLOW_DOT_RELATIVE_PATH_SEARCH 0x00000002
#define RTL_DOS_SEARCH_PATH_FLAG_APPLY_DEFAULT_EXTENSION_WHEN_NOT_RELATIVE_PATH_EVEN_IF_FILE_HAS_EXTENSION 0x00000004

typedef
NTSTATUS(
NTAPI*
RTLDOSSEARCHPATH_USTR)(
    _In_ ULONG Flags,
    _In_ PUNICODE_STRING Path,
    _In_ PUNICODE_STRING FileName,
    _In_opt_ PUNICODE_STRING DefaultExtension,
    _Out_opt_ PUNICODE_STRING StaticString,
    _Out_opt_ PUNICODE_STRING DynamicString,
    _Out_opt_ PCUNICODE_STRING *FullFileNameOut,
    _Out_opt_ SIZE_T *FilePartPrefixCch,
    _Out_opt_ SIZE_T *BytesRequired
    );

typedef
BOOLEAN(
NTAPI*
RTLDOESFILEEXISTS_U)(
    _In_ PCWSTR FileName
    );

typedef
NTSTATUS(
NTAPI*
RTLGETLENGTHWITHOUTLASTFULLDOSORNTPATHELEMENT)(
    _Reserved_ ULONG Flags,
    _In_ PUNICODE_STRING PathString,
    _Out_ PULONG Length
    );

typedef
NTSTATUS(
NTAPI*
RTLGETLENGTHWITHOUTTRAILINGPATHSEPERATORS)(
    _Reserved_ ULONG Flags,
    _In_ PUNICODE_STRING PathString,
    _Out_ PULONG Length
    );

typedef struct _GENERATE_NAME_CONTEXT
{
    USHORT Checksum;
    BOOLEAN CheckSumInserted;
    UCHAR NameLength;
    WCHAR NameBuffer[8];
    ULONG ExtensionLength;
    WCHAR ExtensionBuffer[4];
    ULONG LastIndexValue;
} GENERATE_NAME_CONTEXT, *PGENERATE_NAME_CONTEXT;

// private
typedef
NTSTATUS(
NTAPI*
RTLGENERATE8DOT3NAME)(
    _In_ PUNICODE_STRING Name,
    _In_ BOOLEAN AllowExtendedCharacters,
    _Inout_ PGENERATE_NAME_CONTEXT Context,
    _Inout_ PUNICODE_STRING Name8dot3
    );

#if (PHNT_VERSION >= PHNT_WIN8)

// private
typedef
NTSTATUS(
NTAPI*
RTLCOMPUTEPRIVATIZEDDLLNAME_U)(
    _In_ PUNICODE_STRING DllName,
    _Out_ PUNICODE_STRING RealName,
    _Out_ PUNICODE_STRING LocalName
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLGETSEARCHPATH)(
    _Out_ PWSTR *SearchPath
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLSETSEARCHPATHMODE)(
    _In_ ULONG Flags
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLGETEXEPATH)(
    _In_ PCWSTR DosPathName,
    _Out_ PWSTR* SearchPath
    );

// rev
typedef
VOID(
NTAPI*
RTLRELEASEPATH)(
    _In_ PWSTR Path
    );

#endif

#if (PHNT_VERSION >= PHNT_REDSTONE)
// rev
typedef
ULONG(
NTAPI*
RTLREPLACESYSTEMDIRECTORYINPATH)(
    _Inout_ PUNICODE_STRING Destination,
    _In_ ULONG Machine, // IMAGE_FILE_MACHINE_I386
    _In_ ULONG TargetMachine, // IMAGE_FILE_MACHINE_TARGET_HOST
    _In_ BOOLEAN IncludePathSeperator
    );
#endif

#if (PHNT_VERSION >= PHNT_REDSTONE2)

// private
typedef
PWSTR(
NTAPI*
RTLGETNTSYSTEMROOT)(
    VOID
    );

// rev
typedef
BOOLEAN(
NTAPI*
RTLARELONGPATHSENABLED)(
    VOID
    );

#endif

typedef
BOOLEAN(
NTAPI*
RTLISTHREADWITHINLOADERCALLOUT)(
    VOID
    );

typedef
BOOLEAN(
NTAPI*
RTLDLLSHUTDOWNINPROGRESS)(
    VOID
    );

// Heaps

typedef struct _RTL_HEAP_ENTRY
{
    SIZE_T Size;
    USHORT Flags;
    USHORT AllocatorBackTraceIndex;
    union
    {
        struct
        {
            SIZE_T Settable;
            ULONG Tag;
        } s1;
        struct
        {
            SIZE_T CommittedSize;
            PVOID FirstBlock;
        } s2;
    } u;
} RTL_HEAP_ENTRY, *PRTL_HEAP_ENTRY;

#define RTL_HEAP_BUSY (USHORT)0x0001
#define RTL_HEAP_SEGMENT (USHORT)0x0002
#define RTL_HEAP_SETTABLE_VALUE (USHORT)0x0010
#define RTL_HEAP_SETTABLE_FLAG1 (USHORT)0x0020
#define RTL_HEAP_SETTABLE_FLAG2 (USHORT)0x0040
#define RTL_HEAP_SETTABLE_FLAG3 (USHORT)0x0080
#define RTL_HEAP_SETTABLE_FLAGS (USHORT)0x00e0
#define RTL_HEAP_UNCOMMITTED_RANGE (USHORT)0x0100
#define RTL_HEAP_PROTECTED_ENTRY (USHORT)0x0200

typedef struct _RTL_HEAP_TAG
{
    ULONG NumberOfAllocations;
    ULONG NumberOfFrees;
    SIZE_T BytesAllocated;
    USHORT TagIndex;
    USHORT CreatorBackTraceIndex;
    WCHAR TagName[24];
} RTL_HEAP_TAG, *PRTL_HEAP_TAG;

typedef struct _RTL_HEAP_INFORMATION
{
    PVOID BaseAddress;
    ULONG Flags;
    USHORT EntryOverhead;
    USHORT CreatorBackTraceIndex;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    ULONG NumberOfTags;
    ULONG NumberOfEntries;
    ULONG NumberOfPseudoTags;
    ULONG PseudoTagGranularity;
    ULONG Reserved[5];
    PRTL_HEAP_TAG Tags;
    PRTL_HEAP_ENTRY Entries;
    ULONG64 HeapTag; // Windows 11 > 22000
} RTL_HEAP_INFORMATION, *PRTL_HEAP_INFORMATION;

#define RTL_HEAP_SIGNATURE 0xFFEEFFEEUL
#define RTL_HEAP_SEGMENT_SIGNATURE 0xDDEEDDEEUL

typedef struct _RTL_PROCESS_HEAPS
{
    ULONG NumberOfHeaps;
    RTL_HEAP_INFORMATION Heaps[1];
} RTL_PROCESS_HEAPS, *PRTL_PROCESS_HEAPS;

typedef NTSTATUS (NTAPI *PRTL_HEAP_COMMIT_ROUTINE)(
    _In_ PVOID Base,
    _Inout_ PVOID *CommitAddress,
    _Inout_ PSIZE_T CommitSize
    );

typedef struct _RTL_HEAP_PARAMETERS
{
    ULONG Length;
    SIZE_T SegmentReserve;
    SIZE_T SegmentCommit;
    SIZE_T DeCommitFreeBlockThreshold;
    SIZE_T DeCommitTotalFreeThreshold;
    SIZE_T MaximumAllocationSize;
    SIZE_T VirtualMemoryThreshold;
    SIZE_T InitialCommit;
    SIZE_T InitialReserve;
    PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
    SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

#define HEAP_SETTABLE_USER_VALUE 0x00000100
#define HEAP_SETTABLE_USER_FLAG1 0x00000200
#define HEAP_SETTABLE_USER_FLAG2 0x00000400
#define HEAP_SETTABLE_USER_FLAG3 0x00000800
#define HEAP_SETTABLE_USER_FLAGS 0x00000e00

#define HEAP_CLASS_0 0x00000000 // Process heap
#define HEAP_CLASS_1 0x00001000 // Private heap
#define HEAP_CLASS_2 0x00002000 // Kernel heap
#define HEAP_CLASS_3 0x00003000 // GDI heap
#define HEAP_CLASS_4 0x00004000 // User heap
#define HEAP_CLASS_5 0x00005000 // Console heap
#define HEAP_CLASS_6 0x00006000 // User desktop heap
#define HEAP_CLASS_7 0x00007000 // CSR shared heap
#define HEAP_CLASS_8 0x00008000 // CSR port heap
#define HEAP_CLASS_MASK 0x0000f000

_Must_inspect_result_
typedef
PVOID(
NTAPI*
RTLCREATEHEAP)(
    _In_ ULONG Flags,
    _In_opt_ PVOID HeapBase,
    _In_opt_ SIZE_T ReserveSize,
    _In_opt_ SIZE_T CommitSize,
    _In_opt_ PVOID Lock,
    _In_opt_ PRTL_HEAP_PARAMETERS Parameters
    );

typedef
PVOID(
NTAPI*
RTLDESTROYHEAP)(
    _In_ _Post_invalid_ PVOID HeapHandle
    );

_Must_inspect_result_
_Ret_maybenull_
_Post_writable_byte_size_(Size)
typedef
PVOID(
NTAPI*
RTLALLOCATEHEAP)(
    _In_ PVOID HeapHandle,
    _In_opt_ ULONG Flags,
    _In_ SIZE_T Size
    );

#if (PHNT_VERSION >= PHNT_WIN8)
_Success_(return != 0)
typedef
LOGICAL(
NTAPI*
RTLFREEHEAP)(
    _In_ PVOID HeapHandle,
    _In_opt_ ULONG Flags,
    _Frees_ptr_opt_ PVOID BaseAddress
    );
#else
_Success_(return)
typedef
BOOLEAN(
NTAPI*
RTLFREEHEAP)(
    _In_ PVOID HeapHandle,
    _In_opt_ ULONG Flags,
    _Frees_ptr_opt_ PVOID BaseAddress
    );
#endif

typedef
SIZE_T(
NTAPI*
RTLSIZEHEAP)(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress
    );

typedef
NTSTATUS(
NTAPI*
RTLZEROHEAP)(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags
    );

typedef
VOID(
NTAPI*
RTLPROTECTHEAP)(
    _In_ PVOID HeapHandle,
    _In_ BOOLEAN MakeReadOnly
    );

#define RtlProcessHeap() (NtCurrentPeb()->ProcessHeap)

typedef
BOOLEAN(
NTAPI*
RTLLOCKHEAP)(
    _In_ PVOID HeapHandle
    );

typedef
BOOLEAN(
NTAPI*
RTLUNLOCKHEAP)(
    _In_ PVOID HeapHandle
    );

typedef
PVOID(
NTAPI*
RTLREALLOCATEHEAP)(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _Frees_ptr_opt_ PVOID BaseAddress,
    _In_ SIZE_T Size
    );

typedef
BOOLEAN(
NTAPI*
RTLGETUSERINFOHEAP)(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress,
    _Out_opt_ PVOID *UserValue,
    _Out_opt_ PULONG UserFlags
    );

typedef
BOOLEAN(
NTAPI*
RTLSETUSERVALUEHEAP)(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress,
    _In_ PVOID UserValue
    );

typedef
BOOLEAN(
NTAPI*
RTLSETUSERFLAGSHEAP)(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress,
    _In_ ULONG UserFlagsReset,
    _In_ ULONG UserFlagsSet
    );

typedef struct _RTL_HEAP_TAG_INFO
{
    ULONG NumberOfAllocations;
    ULONG NumberOfFrees;
    SIZE_T BytesAllocated;
} RTL_HEAP_TAG_INFO, *PRTL_HEAP_TAG_INFO;

#define RTL_HEAP_MAKE_TAG HEAP_MAKE_TAG_FLAGS

typedef
ULONG(
NTAPI*
RTLCREATETAGHEAP)(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _In_opt_ PWSTR TagPrefix,
    _In_ PWSTR TagNames
    );

typedef
PWSTR(
NTAPI*
RTLQUERYTAGHEAP)(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _In_ USHORT TagIndex,
    _In_ BOOLEAN ResetCounters,
    _Out_opt_ PRTL_HEAP_TAG_INFO TagInfo
    );

typedef
NTSTATUS(
NTAPI*
RTLEXTENDHEAP)(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID Base,
    _In_ SIZE_T Size
    );

typedef
SIZE_T(
NTAPI*
RTLCOMPACTHEAP)(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags
    );

typedef
BOOLEAN(
NTAPI*
RTLVALIDATEHEAP)(
    _In_opt_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress
    );

typedef
BOOLEAN(
NTAPI*
RTLVALIDATEPROCESSHEAPS)(
    VOID
    );

typedef
ULONG(
NTAPI*
RTLGETPROCESSHEAPS)(
    _In_ ULONG NumberOfHeaps,
    _Out_ PVOID *ProcessHeaps
    );

typedef NTSTATUS (NTAPI *PRTL_ENUM_HEAPS_ROUTINE)(
    _In_ PVOID HeapHandle,
    _In_ PVOID Parameter
    );

typedef
NTSTATUS(
NTAPI*
RTLENUMPROCESSHEAPS)(
    _In_ PRTL_ENUM_HEAPS_ROUTINE EnumRoutine,
    _In_ PVOID Parameter
    );

typedef struct _RTL_HEAP_USAGE_ENTRY
{
    struct _RTL_HEAP_USAGE_ENTRY *Next;
    PVOID Address;
    SIZE_T Size;
    USHORT AllocatorBackTraceIndex;
    USHORT TagIndex;
} RTL_HEAP_USAGE_ENTRY, *PRTL_HEAP_USAGE_ENTRY;

typedef struct _RTL_HEAP_USAGE
{
    ULONG Length;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    SIZE_T BytesReserved;
    SIZE_T BytesReservedMaximum;
    PRTL_HEAP_USAGE_ENTRY Entries;
    PRTL_HEAP_USAGE_ENTRY AddedEntries;
    PRTL_HEAP_USAGE_ENTRY RemovedEntries;
    ULONG_PTR Reserved[8];
} RTL_HEAP_USAGE, *PRTL_HEAP_USAGE;

#define HEAP_USAGE_ALLOCATED_BLOCKS HEAP_REALLOC_IN_PLACE_ONLY
#define HEAP_USAGE_FREE_BUFFER HEAP_ZERO_MEMORY

typedef
NTSTATUS(
NTAPI*
RTLUSAGEHEAP)(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _Inout_ PRTL_HEAP_USAGE Usage
    );

typedef struct _RTL_HEAP_WALK_ENTRY
{
    PVOID DataAddress;
    SIZE_T DataSize;
    UCHAR OverheadBytes;
    UCHAR SegmentIndex;
    USHORT Flags;
    union
    {
        struct
        {
            SIZE_T Settable;
            USHORT TagIndex;
            USHORT AllocatorBackTraceIndex;
            ULONG Reserved[2];
        } Block;
        struct
        {
            ULONG CommittedSize;
            ULONG UnCommittedSize;
            PVOID FirstEntry;
            PVOID LastEntry;
        } Segment;
    };
} RTL_HEAP_WALK_ENTRY, *PRTL_HEAP_WALK_ENTRY;

typedef
NTSTATUS(
NTAPI*
RTLWALKHEAP)(
    _In_ PVOID HeapHandle,
    _Inout_ PRTL_HEAP_WALK_ENTRY Entry
    );

// HEAP_INFORMATION_CLASS
#define HeapCompatibilityInformation 0x0 // q; s: ULONG
#define HeapEnableTerminationOnCorruption 0x1 // q; s: NULL
#define HeapExtendedInformation 0x2 // q; s: HEAP_EXTENDED_INFORMATION
#define HeapOptimizeResources 0x3 // q; s: HEAP_OPTIMIZE_RESOURCES_INFORMATION 
#define HeapTaggingInformation 0x4
#define HeapStackDatabase 0x5
#define HeapMemoryLimit 0x6 // 19H2
#define HeapDetailedFailureInformation 0x80000001
#define HeapSetDebuggingInformation 0x80000002 // q; s: HEAP_DEBUGGING_INFORMATION

typedef enum _HEAP_COMPATIBILITY_MODE
{
    HEAP_COMPATIBILITY_STANDARD = 0UL,
    HEAP_COMPATIBILITY_LAL = 1UL,
    HEAP_COMPATIBILITY_LFH = 2UL,
} HEAP_COMPATIBILITY_MODE;

typedef struct _PROCESS_HEAP_INFORMATION
{
    ULONG_PTR ReserveSize;
    ULONG_PTR CommitSize;
    ULONG NumberOfHeaps;
    ULONG_PTR FirstHeapInformationOffset;
} PROCESS_HEAP_INFORMATION, *PPROCESS_HEAP_INFORMATION;

typedef struct _HEAP_INFORMATION
{
    ULONG_PTR Address;
    ULONG Mode;
    ULONG_PTR ReserveSize;
    ULONG_PTR CommitSize;
    ULONG_PTR FirstRegionInformationOffset;
    ULONG_PTR NextHeapInformationOffset;
} HEAP_INFORMATION, *PHEAP_INFORMATION;

typedef struct _HEAP_EXTENDED_INFORMATION
{
    HANDLE Process;
    ULONG_PTR Heap;
    ULONG Level;
    PVOID CallbackRoutine;
    PVOID CallbackContext;
    union
    {
        PROCESS_HEAP_INFORMATION ProcessHeapInformation;
        HEAP_INFORMATION HeapInformation;
    };
} HEAP_EXTENDED_INFORMATION, *PHEAP_EXTENDED_INFORMATION;

// rev
typedef NTSTATUS (NTAPI *PRTL_HEAP_LEAK_ENUMERATION_ROUTINE)(
    _In_ LONG Reserved,
    _In_ PVOID HeapHandle,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T BlockSize,
    _In_ ULONG StackTraceDepth,
    _In_ PVOID *StackTrace
    );

// symbols
typedef struct _HEAP_DEBUGGING_INFORMATION
{
    PVOID InterceptorFunction;
    USHORT InterceptorValue;
    ULONG ExtendedOptions;
    ULONG StackTraceDepth;
    SIZE_T MinTotalBlockSize;
    SIZE_T MaxTotalBlockSize;
    PRTL_HEAP_LEAK_ENUMERATION_ROUTINE HeapLeakEnumerationRoutine;
} HEAP_DEBUGGING_INFORMATION, *PHEAP_DEBUGGING_INFORMATION;

typedef
NTSTATUS(
NTAPI*
RTLQUERYHEAPINFORMATION)(
    _In_ PVOID HeapHandle,
    _In_ HEAP_INFORMATION_CLASS HeapInformationClass,
    _Out_opt_ PVOID HeapInformation,
    _In_opt_ SIZE_T HeapInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
RTLSETHEAPINFORMATION)(
    _In_ PVOID HeapHandle,
    _In_ HEAP_INFORMATION_CLASS HeapInformationClass,
    _In_opt_ PVOID HeapInformation,
    _In_opt_ SIZE_T HeapInformationLength
    );

typedef
ULONG(
NTAPI*
RTLMULTIPLEALLOCATEHEAP)(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _In_ SIZE_T Size,
    _In_ ULONG Count,
    _Out_ PVOID *Array
    );

typedef
ULONG(
NTAPI*
RTLMULTIPLEFREEHEAP)(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _In_ ULONG Count,
    _In_ PVOID *Array
    );

#if (PHNT_VERSION >= PHNT_WIN7)
typedef
VOID(
NTAPI*
RTLDETECTHEAPLEAKS)(
    VOID
    );
#endif

typedef
VOID(
NTAPI*
RTLFLUSHHEAPS)(
    VOID
    );

// Memory zones

// begin_private

typedef struct _RTL_MEMORY_ZONE_SEGMENT
{
    struct _RTL_MEMORY_ZONE_SEGMENT *NextSegment;
    SIZE_T Size;
    PVOID Next;
    PVOID Limit;
} RTL_MEMORY_ZONE_SEGMENT, *PRTL_MEMORY_ZONE_SEGMENT;

typedef struct _RTL_MEMORY_ZONE
{
    RTL_MEMORY_ZONE_SEGMENT Segment;
    RTL_SRWLOCK Lock;
    ULONG LockCount;
    PRTL_MEMORY_ZONE_SEGMENT FirstSegment;
} RTL_MEMORY_ZONE, *PRTL_MEMORY_ZONE;

#if (PHNT_VERSION >= PHNT_VISTA)

typedef
NTSTATUS(
NTAPI*
RTLCREATEMEMORYZONE)(
    _Out_ PVOID *MemoryZone,
    _In_ SIZE_T InitialSize,
    _Reserved_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
RTLDESTROYMEMORYZONE)(
    _In_ _Post_invalid_ PVOID MemoryZone
    );

typedef
NTSTATUS(
NTAPI*
RTLALLOCATEMEMORYZONE)(
    _In_ PVOID MemoryZone,
    _In_ SIZE_T BlockSize,
    _Out_ PVOID *Block
    );

typedef
NTSTATUS(
NTAPI*
RTLRESETMEMORYZONE)(
    _In_ PVOID MemoryZone
    );

typedef
NTSTATUS(
NTAPI*
RTLLOCKMEMORYZONE)(
    _In_ PVOID MemoryZone
    );

typedef
NTSTATUS(
NTAPI*
RTLUNLOCKMEMORYZONE)(
    _In_ PVOID MemoryZone
    );

#endif

// end_private

// Memory block lookaside lists

// begin_private

#if (PHNT_VERSION >= PHNT_VISTA)

typedef
NTSTATUS(
NTAPI*
RTLCREATEMEMORYBLOCKLOOKASIDE)(
    _Out_ PVOID *MemoryBlockLookaside,
    _Reserved_ ULONG Flags,
    _In_ ULONG InitialSize,
    _In_ ULONG MinimumBlockSize,
    _In_ ULONG MaximumBlockSize
    );

typedef
NTSTATUS(
NTAPI*
RTLDESTROYMEMORYBLOCKLOOKASIDE)(
    _In_ PVOID MemoryBlockLookaside
    );

typedef
NTSTATUS(
NTAPI*
RTLALLOCATEMEMORYBLOCKLOOKASIDE)(
    _In_ PVOID MemoryBlockLookaside,
    _In_ ULONG BlockSize,
    _Out_ PVOID *Block
    );

typedef
NTSTATUS(
NTAPI*
RTLFREEMEMORYBLOCKLOOKASIDE)(
    _In_ PVOID MemoryBlockLookaside,
    _In_ PVOID Block
    );

typedef
NTSTATUS(
NTAPI*
RTLEXTENDMEMORYBLOCKLOOKASIDE)(
    _In_ PVOID MemoryBlockLookaside,
    _In_ ULONG Increment
    );

typedef
NTSTATUS(
NTAPI*
RTLRESETMEMORYBLOCKLOOKASIDE)(
    _In_ PVOID MemoryBlockLookaside
    );

typedef
NTSTATUS(
NTAPI*
RTLLOCKMEMORYBLOCKLOOKASIDE)(
    _In_ PVOID MemoryBlockLookaside
    );

typedef
NTSTATUS(
NTAPI*
RTLUNLOCKMEMORYBLOCKLOOKASIDE)(
    _In_ PVOID MemoryBlockLookaside
    );

#endif

// end_private

// Transactions

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
HANDLE(
NTAPI*
RTLGETCURRENTTRANSACTION)(
    VOID
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
LOGICAL(
NTAPI*
RTLSETCURRENTTRANSACTION)(
    _In_opt_ HANDLE TransactionHandle
    );
#endif

// LUIDs

FORCEINLINE BOOLEAN RtlIsEqualLuid( // RtlEqualLuid
    _In_ PLUID L1,
    _In_ PLUID L2
    )
{
    return L1->LowPart == L2->LowPart &&
        L1->HighPart == L2->HighPart;
}

FORCEINLINE BOOLEAN RtlIsZeroLuid(
    _In_ PLUID L1
    )
{
    return (L1->LowPart | L1->HighPart) == 0;
}

FORCEINLINE LUID RtlConvertLongToLuid(
    _In_ LONG Long
    )
{
    LUID tempLuid;
    LARGE_INTEGER tempLi;

    tempLi.QuadPart = Long;
    tempLuid.LowPart = tempLi.LowPart;
    tempLuid.HighPart = tempLi.HighPart;

    return tempLuid;
}

FORCEINLINE LUID RtlConvertUlongToLuid(
    _In_ ULONG Ulong
    )
{
    LUID tempLuid;

    tempLuid.LowPart = Ulong;
    tempLuid.HighPart = 0;

    return tempLuid;
}

typedef
VOID(
NTAPI*
RTLCOPYLUID)(
    _Out_ PLUID DestinationLuid,
    _In_ PLUID SourceLuid
    );

// ros
typedef
VOID(
NTAPI*
RTLCOPYLUIDANDATTRIBUTESARRAY)(
    _In_ ULONG Count,
    _In_ PLUID_AND_ATTRIBUTES Src,
    _In_ PLUID_AND_ATTRIBUTES Dest
    );

// Byte swap routines.

#ifndef PHNT_RTL_BYTESWAP
#define RtlUshortByteSwap(_x) _byteswap_ushort((USHORT)(_x))
#define RtlUlongByteSwap(_x) _byteswap_ulong((_x))
#define RtlUlonglongByteSwap(_x) _byteswap_uint64((_x))
#else
typedef
USHORT(
FASTCALL*
RTLUSHORTBYTESWAP)(
    _In_ USHORT Source
    );

typedef
ULONG(
FASTCALL*
RTLULONGBYTESWAP)(
    _In_ ULONG Source
    );

typedef
ULONGLONG(
FASTCALL*
RTLULONGLONGBYTESWAP)(
    _In_ ULONGLONG Source
    );
#endif

// Debugging

// private
typedef struct _RTL_PROCESS_VERIFIER_OPTIONS
{
    ULONG SizeStruct;
    ULONG Option;
    UCHAR OptionData[1];
} RTL_PROCESS_VERIFIER_OPTIONS, *PRTL_PROCESS_VERIFIER_OPTIONS;

// private
typedef struct _RTL_DEBUG_INFORMATION
{
    HANDLE SectionHandleClient;
    PVOID ViewBaseClient;
    PVOID ViewBaseTarget;
    ULONG_PTR ViewBaseDelta;
    HANDLE EventPairClient;
    HANDLE EventPairTarget;
    HANDLE TargetProcessId;
    HANDLE TargetThreadHandle;
    ULONG Flags;
    SIZE_T OffsetFree;
    SIZE_T CommitSize;
    SIZE_T ViewSize;
    union
    {
        struct _RTL_PROCESS_MODULES *Modules;
        struct _RTL_PROCESS_MODULE_INFORMATION_EX *ModulesEx;
    };
    struct _RTL_PROCESS_BACKTRACES *BackTraces;
    struct _RTL_PROCESS_HEAPS *Heaps;
    struct _RTL_PROCESS_LOCKS *Locks;
    PVOID SpecificHeap;
    HANDLE TargetProcessHandle;
    PRTL_PROCESS_VERIFIER_OPTIONS VerifierOptions;
    PVOID ProcessHeap;
    HANDLE CriticalSectionHandle;
    HANDLE CriticalSectionOwnerThread;
    PVOID Reserved[4];
} RTL_DEBUG_INFORMATION, *PRTL_DEBUG_INFORMATION;

typedef
PRTL_DEBUG_INFORMATION(
NTAPI*
RTLCREATEQUERYDEBUGBUFFER)(
    _In_opt_ ULONG MaximumCommit,
    _In_ BOOLEAN UseEventPair
    );

typedef
NTSTATUS(
NTAPI*
RTLDESTROYQUERYDEBUGBUFFER)(
    _In_ PRTL_DEBUG_INFORMATION Buffer
    );

#if (PHNT_VERSION >= PHNT_VISTA)

// private
typedef
PVOID(
NTAPI*
RTLCOMMITDEBUGINFO)(
    _Inout_ PRTL_DEBUG_INFORMATION Buffer,
    _In_ SIZE_T Size
    );

// private
typedef
VOID(
NTAPI*
RTLDECOMMITDEBUGINFO)(
    _Inout_ PRTL_DEBUG_INFORMATION Buffer,
    _In_ PVOID p,
    _In_ SIZE_T Size
    );

#endif

#define RTL_QUERY_PROCESS_MODULES 0x00000001
#define RTL_QUERY_PROCESS_BACKTRACES 0x00000002
#define RTL_QUERY_PROCESS_HEAP_SUMMARY 0x00000004
#define RTL_QUERY_PROCESS_HEAP_TAGS 0x00000008
#define RTL_QUERY_PROCESS_HEAP_ENTRIES 0x00000010
#define RTL_QUERY_PROCESS_LOCKS 0x00000020
#define RTL_QUERY_PROCESS_MODULES32 0x00000040
#define RTL_QUERY_PROCESS_VERIFIER_OPTIONS 0x00000080 // rev
#define RTL_QUERY_PROCESS_MODULESEX 0x00000100 // rev
#define RTL_QUERY_PROCESS_HEAP_SEGMENTS 0x00000200
#define RTL_QUERY_PROCESS_CS_OWNER 0x00000400 // rev
#define RTL_QUERY_PROCESS_NONINVASIVE 0x80000000

typedef
NTSTATUS(
NTAPI*
RTLQUERYPROCESSDEBUGINFORMATION)(
    _In_ HANDLE UniqueProcessId,
    _In_ ULONG Flags,
    _Inout_ PRTL_DEBUG_INFORMATION Buffer
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLSETPROCESSDEBUGINFORMATION)(
    _In_ HANDLE UniqueProcessId,
    _In_ ULONG Flags,
    _Inout_ PRTL_DEBUG_INFORMATION Buffer
    );

// Messages

typedef
NTSTATUS(
NTAPI*
RTLFINDMESSAGE)(
    _In_ PVOID DllHandle,
    _In_ ULONG MessageTableId,
    _In_ ULONG MessageLanguageId,
    _In_ ULONG MessageId,
    _Out_ PMESSAGE_RESOURCE_ENTRY *MessageEntry
    );

typedef
NTSTATUS(
NTAPI*
RTLFORMATMESSAGE)(
    _In_ PWSTR MessageFormat,
    _In_ ULONG MaximumWidth,
    _In_ BOOLEAN IgnoreInserts,
    _In_ BOOLEAN ArgumentsAreAnsi,
    _In_ BOOLEAN ArgumentsAreAnArray,
    _In_ va_list *Arguments,
    _Out_writes_bytes_to_(Length, *ReturnLength) PWSTR Buffer,
    _In_ ULONG Length,
    _Out_opt_ PULONG ReturnLength
    );

typedef struct _PARSE_MESSAGE_CONTEXT
{
    ULONG fFlags;
    ULONG cwSavColumn;
    SIZE_T iwSrc;
    SIZE_T iwDst;
    SIZE_T iwDstSpace;
    va_list lpvArgStart;
} PARSE_MESSAGE_CONTEXT, *PPARSE_MESSAGE_CONTEXT;

#define INIT_PARSE_MESSAGE_CONTEXT(ctx) { (ctx)->fFlags = 0; }
#define TEST_PARSE_MESSAGE_CONTEXT_FLAG(ctx, flag) ((ctx)->fFlags & (flag))
#define SET_PARSE_MESSAGE_CONTEXT_FLAG(ctx, flag) ((ctx)->fFlags |= (flag))
#define CLEAR_PARSE_MESSAGE_CONTEXT_FLAG(ctx, flag) ((ctx)->fFlags &= ~(flag))

typedef
NTSTATUS(
NTAPI*
RTLFORMATMESSAGEEX)(
    _In_ PWSTR MessageFormat,
    _In_ ULONG MaximumWidth,
    _In_ BOOLEAN IgnoreInserts,
    _In_ BOOLEAN ArgumentsAreAnsi,
    _In_ BOOLEAN ArgumentsAreAnArray,
    _In_ va_list *Arguments,
    _Out_writes_bytes_to_(Length, *ReturnLength) PWSTR Buffer,
    _In_ ULONG Length,
    _Out_opt_ PULONG ReturnLength,
    _Out_opt_ PPARSE_MESSAGE_CONTEXT ParseContext
    );

typedef
NTSTATUS(
NTAPI*
RTLGETFILEMUIPATH)(
    _In_ ULONG Flags,
    _In_ PCWSTR FilePath,
    _Inout_opt_ PWSTR Language,
    _Inout_ PULONG LanguageLength,
    _Out_opt_ PWSTR FileMUIPath,
    _Inout_ PULONG FileMUIPathLength,
    _Inout_ PULONGLONG Enumerator
    );

// private
typedef
NTSTATUS(
NTAPI*
RTLLOADSTRING)(
    _In_ PVOID DllHandle,
    _In_ ULONG StringId,
    _In_opt_ PCWSTR StringLanguage,
    _In_ ULONG Flags,
    _Out_ PCWSTR *ReturnString,
    _Out_opt_ PUSHORT ReturnStringLen,
    _Out_writes_(ReturnLanguageLen) PWSTR ReturnLanguageName,
    _Inout_opt_ PULONG ReturnLanguageLen
    );

// Errors

typedef
ULONG(
NTAPI*
RTLNTSTATUSTODOSERROR)(
    _In_ NTSTATUS Status
    );

typedef
ULONG(
NTAPI*
RTLNTSTATUSTODOSERRORNOTEB)(
    _In_ NTSTATUS Status
    );

typedef
NTSTATUS(
NTAPI*
RTLGETLASTNTSTATUS)(
    VOID
    );

typedef
LONG(
NTAPI*
RTLGETLASTWIN32ERROR)(
    VOID
    );

typedef
VOID(
NTAPI*
RTLSETLASTWIN32ERRORANDNTSTATUSFROMNTSTATUS)(
    _In_ NTSTATUS Status
    );

typedef
VOID(
NTAPI*
RTLSETLASTWIN32ERROR)(
    _In_ LONG Win32Error
    );

typedef
VOID(
NTAPI*
RTLRESTORELASTWIN32ERROR)(
    _In_ LONG Win32Error
    );

#define RTL_ERRORMODE_FAILCRITICALERRORS 0x0010
#define RTL_ERRORMODE_NOGPFAULTERRORBOX 0x0020
#define RTL_ERRORMODE_NOOPENFILEERRORBOX 0x0040

typedef
ULONG(
NTAPI*
RTLGETTHREADERRORMODE)(
    VOID
    );

typedef
NTSTATUS(
NTAPI*
RTLSETTHREADERRORMODE)(
    _In_ ULONG NewMode,
    _Out_opt_ PULONG OldMode
    );

// Windows Error Reporting

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
RTLREPORTEXCEPTION)(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord,
    _In_ ULONG Flags
    );
#endif

#if (PHNT_VERSION >= PHNT_REDSTONE)
// rev
typedef
NTSTATUS(
NTAPI*
RTLREPORTEXCEPTIONEX)(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord,
    _In_ ULONG Flags,
    _In_ PLARGE_INTEGER Timeout
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
RTLWERPREPORTEXCEPTION)(
    _In_ ULONG ProcessId,
    _In_ HANDLE CrashReportSharedMem,
    _In_ ULONG Flags,
    _Out_ PHANDLE CrashVerticalProcessHandle
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN7)
// rev
typedef
NTSTATUS(
NTAPI*
RTLREPORTSILENTPROCESSEXIT)(
    _In_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus
    );
#endif

// Random

typedef
ULONG(
NTAPI*
RTLUNIFORM)(
    _Inout_ PULONG Seed
    );

_Ret_range_(<=, MAXLONG)
typedef
ULONG(
NTAPI*
RTLRANDOM)(
    _Inout_ PULONG Seed
    );

_Ret_range_(<=, MAXLONG)
typedef
ULONG(
NTAPI*
RTLRANDOMEX)(
    _Inout_ PULONG Seed
    );

#define RTL_IMPORT_TABLE_HASH_REVISION 1

typedef
NTSTATUS(
NTAPI*
RTLCOMPUTEIMPORTTABLEHASH)(
    _In_ HANDLE FileHandle,
    _Out_writes_bytes_(16) PCHAR Hash,
    _In_ ULONG ImportTableHashRevision // must be 1
    );

// Integer conversion

typedef
NTSTATUS(
NTAPI*
RTLINTEGERTOCHAR)(
    _In_ ULONG Value,
    _In_opt_ ULONG Base,
    _In_ LONG OutputLength, // negative to pad to width
    _Out_ PSTR String
    );

typedef
NTSTATUS(
NTAPI*
RTLCHARTOINTEGER)(
    _In_ PCSTR String,
    _In_opt_ ULONG Base,
    _Out_ PULONG Value
    );

typedef
NTSTATUS(
NTAPI*
RTLLARGEINTEGERTOCHAR)(
    _In_ PLARGE_INTEGER Value,
    _In_opt_ ULONG Base,
    _In_ LONG OutputLength,
    _Out_ PSTR String
    );

typedef
NTSTATUS(
NTAPI*
RTLINTEGERTOUNICODESTRING)(
    _In_ ULONG Value,
    _In_opt_ ULONG Base,
    _Inout_ PUNICODE_STRING String
    );

typedef
NTSTATUS(
NTAPI*
RTLINT64TOUNICODESTRING)(
    _In_ ULONGLONG Value,
    _In_opt_ ULONG Base,
    _Inout_ PUNICODE_STRING String
    );

#ifdef _WIN64
#define RtlIntPtrToUnicodeString(Value, Base, String) RtlInt64ToUnicodeString(Value, Base, String)
#else
#define RtlIntPtrToUnicodeString(Value, Base, String) RtlIntegerToUnicodeString(Value, Base, String)
#endif

typedef
NTSTATUS(
NTAPI*
RTLUNICODESTRINGTOINTEGER)(
    _In_ PUNICODE_STRING String,
    _In_opt_ ULONG Base,
    _Out_ PULONG Value
    );

// IPv4/6 conversion

struct in_addr;
struct in6_addr;

typedef
PWSTR(
NTAPI*
RTLIPV4ADDRESSTOSTRINGW)(
    _In_ const struct in_addr *Address,
    _Out_writes_(16) PWSTR AddressString
    );

typedef
NTSTATUS(
NTAPI*
RTLIPV4ADDRESSTOSTRINGEXW)(
    _In_ const struct in_addr *Address,
    _In_ USHORT Port,
    _Out_writes_to_(*AddressStringLength, *AddressStringLength) PWSTR AddressString,
    _Inout_ PULONG AddressStringLength
    );

typedef
PWSTR(
NTAPI*
RTLIPV6ADDRESSTOSTRINGW)(
    _In_ const struct in6_addr *Address,
    _Out_writes_(46) PWSTR AddressString
    );

typedef
NTSTATUS(
NTAPI*
RTLIPV6ADDRESSTOSTRINGEXW)(
    _In_ const struct in6_addr *Address,
    _In_ ULONG ScopeId,
    _In_ USHORT Port,
    _Out_writes_to_(*AddressStringLength, *AddressStringLength) PWSTR AddressString,
    _Inout_ PULONG AddressStringLength
    );

typedef
NTSTATUS(
NTAPI*
RTLIPV4STRINGTOADDRESSW)(
    _In_ PCWSTR AddressString,
    _In_ BOOLEAN Strict,
    _Out_ LPCWSTR *Terminator,
    _Out_ struct in_addr *Address
    );

typedef
NTSTATUS(
NTAPI*
RTLIPV4STRINGTOADDRESSEXW)(
    _In_ PCWSTR AddressString,
    _In_ BOOLEAN Strict,
    _Out_ struct in_addr *Address,
    _Out_ PUSHORT Port
    );

typedef
NTSTATUS(
NTAPI*
RTLIPV6STRINGTOADDRESSW)(
    _In_ PCWSTR AddressString,
    _Out_ PCWSTR *Terminator,
    _Out_ struct in6_addr *Address
    );

typedef
NTSTATUS(
NTAPI*
RTLIPV6STRINGTOADDRESSEXW)(
    _In_ PCWSTR AddressString,
    _Out_ struct in6_addr *Address,
    _Out_ PULONG ScopeId,
    _Out_ PUSHORT Port
    );

#define RtlIpv4AddressToString RtlIpv4AddressToStringW
#define RtlIpv4AddressToStringEx RtlIpv4AddressToStringExW
#define RtlIpv6AddressToString RtlIpv6AddressToStringW
#define RtlIpv6AddressToStringEx RtlIpv6AddressToStringExW
#define RtlIpv4StringToAddress RtlIpv4StringToAddressW
#define RtlIpv4StringToAddressEx RtlIpv4StringToAddressExW
#define RtlIpv6StringToAddress RtlIpv6StringToAddressW
#define RtlIpv6StringToAddressEx RtlIpv6StringToAddressExW

// Time

typedef struct _TIME_FIELDS
{
    CSHORT Year; // 1601...
    CSHORT Month; // 1..12
    CSHORT Day; // 1..31
    CSHORT Hour; // 0..23
    CSHORT Minute; // 0..59
    CSHORT Second; // 0..59
    CSHORT Milliseconds; // 0..999
    CSHORT Weekday; // 0..6 = Sunday..Saturday
} TIME_FIELDS, *PTIME_FIELDS;

typedef
BOOLEAN(
NTAPI*
RTLCUTOVERTIMETOSYSTEMTIME)(
    _In_ PTIME_FIELDS CutoverTime,
    _Out_ PLARGE_INTEGER SystemTime,
    _In_ PLARGE_INTEGER CurrentSystemTime,
    _In_ BOOLEAN ThisYear
    );

typedef
NTSTATUS(
NTAPI*
RTLSYSTEMTIMETOLOCALTIME)(
    _In_ PLARGE_INTEGER SystemTime,
    _Out_ PLARGE_INTEGER LocalTime
    );

typedef
NTSTATUS(
NTAPI*
RTLLOCALTIMETOSYSTEMTIME)(
    _In_ PLARGE_INTEGER LocalTime,
    _Out_ PLARGE_INTEGER SystemTime
    );

typedef
VOID(
NTAPI*
RTLTIMETOELAPSEDTIMEFIELDS)(
    _In_ PLARGE_INTEGER Time,
    _Out_ PTIME_FIELDS TimeFields
    );

typedef
VOID(
NTAPI*
RTLTIMETOTIMEFIELDS)(
    _In_ PLARGE_INTEGER Time,
    _Out_ PTIME_FIELDS TimeFields
    );

typedef
BOOLEAN(
NTAPI*
RTLTIMEFIELDSTOTIME)(
    _In_ PTIME_FIELDS TimeFields, // Weekday is ignored
    _Out_ PLARGE_INTEGER Time
    );

typedef
BOOLEAN(
NTAPI*
RTLTIMETOSECONDSSINCE1980)(
    _In_ PLARGE_INTEGER Time,
    _Out_ PULONG ElapsedSeconds
    );

typedef
VOID(
NTAPI*
RTLSECONDSSINCE1980TOTIME)(
    _In_ ULONG ElapsedSeconds,
    _Out_ PLARGE_INTEGER Time
    );

typedef
BOOLEAN(
NTAPI*
RTLTIMETOSECONDSSINCE1970)(
    _In_ PLARGE_INTEGER Time,
    _Out_ PULONG ElapsedSeconds
    );

typedef
VOID(
NTAPI*
RTLSECONDSSINCE1970TOTIME)(
    _In_ ULONG ElapsedSeconds,
    _Out_ PLARGE_INTEGER Time
    );

#if (PHNT_VERSION >= PHNT_WIN8)
typedef
ULONGLONG(
NTAPI*
RTLGETSYSTEMTIMEPRECISE)(
    VOID
    );
#endif

#if (PHNT_VERSION >= PHNT_21H2)
typedef
KSYSTEM_TIME(
NTAPI*
RTLGETSYSTEMTIMEANDBIAS)(
    _Out_ KSYSTEM_TIME TimeZoneBias,
    _Out_opt_ PLARGE_INTEGER TimeZoneBiasEffectiveStart,
    _Out_opt_ PLARGE_INTEGER TimeZoneBiasEffectiveEnd
    );
#endif

#if (PHNT_VERSION >= PHNT_THRESHOLD)
typedef
LARGE_INTEGER(
NTAPI*
RTLGETINTERRUPTTIMEPRECISE)(
    _Out_ PLARGE_INTEGER PerformanceCounter
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN8)
typedef
BOOLEAN(
NTAPI*
RTLQUERYUNBIASEDINTERRUPTTIME)(
    _Out_ PLARGE_INTEGER InterruptTime
    );
#endif

// Time zones

typedef struct _RTL_TIME_ZONE_INFORMATION
{
    LONG Bias;
    WCHAR StandardName[32];
    TIME_FIELDS StandardStart;
    LONG StandardBias;
    WCHAR DaylightName[32];
    TIME_FIELDS DaylightStart;
    LONG DaylightBias;
} RTL_TIME_ZONE_INFORMATION, *PRTL_TIME_ZONE_INFORMATION;

typedef
NTSTATUS(
NTAPI*
RTLQUERYTIMEZONEINFORMATION)(
    _Out_ PRTL_TIME_ZONE_INFORMATION TimeZoneInformation
    );

typedef
NTSTATUS(
NTAPI*
RTLSETTIMEZONEINFORMATION)(
    _In_ PRTL_TIME_ZONE_INFORMATION TimeZoneInformation
    );

// Bitmaps

typedef struct _RTL_BITMAP
{
    ULONG SizeOfBitMap;
    PULONG Buffer;
} RTL_BITMAP, *PRTL_BITMAP;

typedef
VOID(
NTAPI*
RTLINITIALIZEBITMAP)(
    _Out_ PRTL_BITMAP BitMapHeader,
    _In_ PULONG BitMapBuffer,
    _In_ ULONG SizeOfBitMap
    );

#if (PHNT_MODE == PHNT_MODE_KERNEL || PHNT_VERSION >= PHNT_WIN8)
typedef
VOID(
NTAPI*
RTLCLEARBIT)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber
    );
#endif

#if (PHNT_MODE == PHNT_MODE_KERNEL || PHNT_VERSION >= PHNT_WIN8)
typedef
VOID(
NTAPI*
RTLSETBIT)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber
    );
#endif

_Check_return_
typedef
BOOLEAN(
NTAPI*
RTLTESTBIT)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber
    );

typedef
VOID(
NTAPI*
RTLCLEARALLBITS)(
    _In_ PRTL_BITMAP BitMapHeader
    );

typedef
VOID(
NTAPI*
RTLSETALLBITS)(
    _In_ PRTL_BITMAP BitMapHeader
    );

_Success_(return != -1)
_Check_return_
typedef
ULONG(
NTAPI*
RTLFINDCLEARBITS)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG NumberToFind,
    _In_ ULONG HintIndex
    );

_Success_(return != -1)
_Check_return_
typedef
ULONG(
NTAPI*
RTLFINDSETBITS)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG NumberToFind,
    _In_ ULONG HintIndex
    );

_Success_(return != -1)
typedef
ULONG(
NTAPI*
RTLFINDCLEARBITSANDSET)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG NumberToFind,
    _In_ ULONG HintIndex
    );

_Success_(return != -1)
typedef
ULONG(
NTAPI*
RTLFINDSETBITSANDCLEAR)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG NumberToFind,
    _In_ ULONG HintIndex
    );

typedef
VOID(
NTAPI*
RTLCLEARBITS)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(0, BitMapHeader->SizeOfBitMap - NumberToClear) ULONG StartingIndex,
    _In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToClear
    );

typedef
VOID(
NTAPI*
RTLSETBITS)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(0, BitMapHeader->SizeOfBitMap - NumberToSet) ULONG StartingIndex,
    _In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToSet
    );

typedef
CCHAR(
NTAPI*
RTLFINDMOSTSIGNIFICANTBIT)(
    _In_ ULONGLONG Set
    );

typedef
CCHAR(
NTAPI*
RTLFINDLEASTSIGNIFICANTBIT)(
    _In_ ULONGLONG Set
    );

typedef struct _RTL_BITMAP_RUN
{
    ULONG StartingIndex;
    ULONG NumberOfBits;
} RTL_BITMAP_RUN, *PRTL_BITMAP_RUN;

typedef
ULONG(
NTAPI*
RTLFINDCLEARRUNS)(
    _In_ PRTL_BITMAP BitMapHeader,
    _Out_writes_to_(SizeOfRunArray, return) PRTL_BITMAP_RUN RunArray,
    _In_range_(>, 0) ULONG SizeOfRunArray,
    _In_ BOOLEAN LocateLongestRuns
    );

typedef
ULONG(
NTAPI*
RTLFINDLONGESTRUNCLEAR)(
    _In_ PRTL_BITMAP BitMapHeader,
    _Out_ PULONG StartingIndex
    );

typedef
ULONG(
NTAPI*
RTLFINDFIRSTRUNCLEAR)(
    _In_ PRTL_BITMAP BitMapHeader,
    _Out_ PULONG StartingIndex
    );

_Check_return_
FORCEINLINE
BOOLEAN
RtlCheckBit(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG BitPosition
    )
{
#ifdef _WIN64
    return BitTest64((LONG64 const *)BitMapHeader->Buffer, (LONG64)BitPosition);
#else
    return (((PLONG)BitMapHeader->Buffer)[BitPosition / 32] >> (BitPosition % 32)) & 0x1;
#endif
}

typedef
ULONG(
NTAPI*
RTLNUMBEROFCLEARBITS)(
    _In_ PRTL_BITMAP BitMapHeader
    );

typedef
ULONG(
NTAPI*
RTLNUMBEROFSETBITS)(
    _In_ PRTL_BITMAP BitMapHeader
    );

_Check_return_
typedef
BOOLEAN(
NTAPI*
RTLAREBITSCLEAR)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG Length
    );

_Check_return_
typedef
BOOLEAN(
NTAPI*
RTLAREBITSSET)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG Length
    );

typedef
ULONG(
NTAPI*
RTLFINDNEXTFORWARDRUNCLEAR)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG FromIndex,
    _Out_ PULONG StartingRunIndex
    );

typedef
ULONG(
NTAPI*
RTLFINDLASTBACKWARDRUNCLEAR)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG FromIndex,
    _Out_ PULONG StartingRunIndex
    );

#if (PHNT_VERSION >= PHNT_VISTA)

typedef
ULONG(
NTAPI*
RTLNUMBEROFSETBITSULONGPTR)(
    _In_ ULONG_PTR Target
    );

#endif

#if (PHNT_VERSION >= PHNT_WIN7)

// rev
typedef
VOID(
NTAPI*
RTLINTERLOCKEDCLEARBITRUN)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(0, BitMapHeader->SizeOfBitMap - NumberToClear) ULONG StartingIndex,
    _In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToClear
    );

// rev
typedef
VOID(
NTAPI*
RTLINTERLOCKEDSETBITRUN)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(0, BitMapHeader->SizeOfBitMap - NumberToSet) ULONG StartingIndex,
    _In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToSet
    );

#endif

#if (PHNT_VERSION >= PHNT_WIN8)

typedef
VOID(
NTAPI*
RTLCOPYBITMAP)(
    _In_ PRTL_BITMAP Source,
    _In_ PRTL_BITMAP Destination,
    _In_range_(0, Destination->SizeOfBitMap - 1) ULONG TargetBit
    );

typedef
VOID(
NTAPI*
RTLEXTRACTBITMAP)(
    _In_ PRTL_BITMAP Source,
    _In_ PRTL_BITMAP Destination,
    _In_range_(0, Source->SizeOfBitMap - 1) ULONG TargetBit,
    _In_range_(0, Source->SizeOfBitMap) ULONG NumberOfBits
    );

typedef
ULONG(
NTAPI*
RTLNUMBEROFCLEARBITSINRANGE)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG Length
    );

typedef
ULONG(
NTAPI*
RTLNUMBEROFSETBITSINRANGE)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG Length
    );

#endif


#if (PHNT_VERSION >= PHNT_THRESHOLD)

// private
typedef struct _RTL_BITMAP_EX
{
    ULONG64 SizeOfBitMap;
    PULONG64 Buffer;
} RTL_BITMAP_EX, *PRTL_BITMAP_EX;

// rev
typedef
VOID(
NTAPI*
RTLINITIALIZEBITMAPEX)(
    _Out_ PRTL_BITMAP_EX BitMapHeader,
    _In_ PULONG64 BitMapBuffer,
    _In_ ULONG64 SizeOfBitMap
    );

// rev
_Check_return_
typedef
BOOLEAN(
NTAPI*
RTLTESTBITEX)(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG64 BitNumber
    );

#if (PHNT_MODE == PHNT_MODE_KERNEL)
// rev
typedef
VOID(
NTAPI*
RTLCLEARALLBITSEX)(
    _In_ PRTL_BITMAP_EX BitMapHeader
    );

// rev
typedef
VOID(
NTAPI*
RTLCLEARBITEX)(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG64 BitNumber
    );

// rev
typedef
VOID(
NTAPI*
RTLSETBITEX)(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_range_(<, BitMapHeader->SizeOfBitMap) ULONG64 BitNumber
    );

// rev
typedef
ULONG64(
NTAPI*
RTLFINDSETBITSEX)(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_ ULONG64 NumberToFind,
    _In_ ULONG64 HintIndex
    );

typedef
ULONG64(
NTAPI*
RTLFINDSETBITSANDCLEAREX)(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_ ULONG64 NumberToFind,
    _In_ ULONG64 HintIndex
    );
#endif

#endif

// Handle tables

typedef struct _RTL_HANDLE_TABLE_ENTRY
{
    union
    {
        ULONG Flags; // allocated entries have the low bit set
        struct _RTL_HANDLE_TABLE_ENTRY *NextFree;
    };
} RTL_HANDLE_TABLE_ENTRY, *PRTL_HANDLE_TABLE_ENTRY;

#define RTL_HANDLE_ALLOCATED (USHORT)0x0001

typedef struct _RTL_HANDLE_TABLE
{
    ULONG MaximumNumberOfHandles;
    ULONG SizeOfHandleTableEntry;
    ULONG Reserved[2];
    PRTL_HANDLE_TABLE_ENTRY FreeHandles;
    PRTL_HANDLE_TABLE_ENTRY CommittedHandles;
    PRTL_HANDLE_TABLE_ENTRY UnCommittedHandles;
    PRTL_HANDLE_TABLE_ENTRY MaxReservedHandles;
} RTL_HANDLE_TABLE, *PRTL_HANDLE_TABLE;

typedef
VOID(
NTAPI*
RTLINITIALIZEHANDLETABLE)(
    _In_ ULONG MaximumNumberOfHandles,
    _In_ ULONG SizeOfHandleTableEntry,
    _Out_ PRTL_HANDLE_TABLE HandleTable
    );

typedef
NTSTATUS(
NTAPI*
RTLDESTROYHANDLETABLE)(
    _Inout_ PRTL_HANDLE_TABLE HandleTable
    );

typedef
PRTL_HANDLE_TABLE_ENTRY(
NTAPI*
RTLALLOCATEHANDLE)(
    _In_ PRTL_HANDLE_TABLE HandleTable,
    _Out_opt_ PULONG HandleIndex
    );

typedef
BOOLEAN(
NTAPI*
RTLFREEHANDLE)(
    _In_ PRTL_HANDLE_TABLE HandleTable,
    _In_ PRTL_HANDLE_TABLE_ENTRY Handle
    );

typedef
BOOLEAN(
NTAPI*
RTLISVALIDHANDLE)(
    _In_ PRTL_HANDLE_TABLE HandleTable,
    _In_ PRTL_HANDLE_TABLE_ENTRY Handle
    );

typedef
BOOLEAN(
NTAPI*
RTLISVALIDINDEXHANDLE)(
    _In_ PRTL_HANDLE_TABLE HandleTable,
    _In_ ULONG HandleIndex,
    _Out_ PRTL_HANDLE_TABLE_ENTRY *Handle
    );

// Atom tables

#define RTL_ATOM_MAXIMUM_INTEGER_ATOM (RTL_ATOM)0xc000
#define RTL_ATOM_INVALID_ATOM (RTL_ATOM)0x0000
#define RTL_ATOM_TABLE_DEFAULT_NUMBER_OF_BUCKETS 37
#define RTL_ATOM_MAXIMUM_NAME_LENGTH 255
#define RTL_ATOM_PINNED 0x01

typedef
NTSTATUS(
NTAPI*
RTLCREATEATOMTABLE)(
    _In_ ULONG NumberOfBuckets,
    _Out_ PVOID *AtomTableHandle
    );

typedef
NTSTATUS(
NTAPI*
RTLDESTROYATOMTABLE)(
    _In_ _Post_invalid_ PVOID AtomTableHandle
    );

typedef
NTSTATUS(
NTAPI*
RTLEMPTYATOMTABLE)(
    _In_ PVOID AtomTableHandle,
    _In_ BOOLEAN IncludePinnedAtoms
    );

typedef
NTSTATUS(
NTAPI*
RTLADDATOMTOATOMTABLE)(
    _In_ PVOID AtomTableHandle,
    _In_ PWSTR AtomName,
    _Inout_opt_ PRTL_ATOM Atom
    );

typedef
NTSTATUS(
NTAPI*
RTLLOOKUPATOMINATOMTABLE)(
    _In_ PVOID AtomTableHandle,
    _In_ PWSTR AtomName,
    _Out_opt_ PRTL_ATOM Atom
    );

typedef
NTSTATUS(
NTAPI*
RTLDELETEATOMFROMATOMTABLE)(
    _In_ PVOID AtomTableHandle,
    _In_ RTL_ATOM Atom
    );

typedef
NTSTATUS(
NTAPI*
RTLPINATOMINATOMTABLE)(
    _In_ PVOID AtomTableHandle,
    _In_ RTL_ATOM Atom
    );

typedef
NTSTATUS(
NTAPI*
RTLQUERYATOMINATOMTABLE)(
    _In_ PVOID AtomTableHandle,
    _In_ RTL_ATOM Atom,
    _Out_opt_ PULONG AtomUsage,
    _Out_opt_ PULONG AtomFlags,
    _Inout_updates_bytes_to_opt_(*AtomNameLength, *AtomNameLength) PWSTR AtomName,
    _Inout_opt_ PULONG AtomNameLength
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// rev
typedef
BOOLEAN(
NTAPI*
RTLGETINTEGERATOM)(
    _In_ PWSTR AtomName,
    _Out_opt_ PUSHORT IntegerAtom
    );
#endif

// SIDs

_Must_inspect_result_
typedef
BOOLEAN(
NTAPI*
RTLVALIDSID)(
    _In_ PSID Sid
    );

_Must_inspect_result_
typedef
BOOLEAN(
NTAPI*
RTLEQUALSID)(
    _In_ PSID Sid1,
    _In_ PSID Sid2
    );

_Must_inspect_result_
typedef
BOOLEAN(
NTAPI*
RTLEQUALPREFIXSID)(
    _In_ PSID Sid1,
    _In_ PSID Sid2
    );

typedef
ULONG(
NTAPI*
RTLLENGTHREQUIREDSID)(
    _In_ ULONG SubAuthorityCount
    );

typedef
PVOID(
NTAPI*
RTLFREESID)(
    _In_ _Post_invalid_ PSID Sid
    );

_Must_inspect_result_
typedef
NTSTATUS(
NTAPI*
RTLALLOCATEANDINITIALIZESID)(
    _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    _In_ UCHAR SubAuthorityCount,
    _In_ ULONG SubAuthority0,
    _In_ ULONG SubAuthority1,
    _In_ ULONG SubAuthority2,
    _In_ ULONG SubAuthority3,
    _In_ ULONG SubAuthority4,
    _In_ ULONG SubAuthority5,
    _In_ ULONG SubAuthority6,
    _In_ ULONG SubAuthority7,
    _Outptr_ PSID *Sid
    );

#if (PHNT_VERSION >= PHNT_WINBLUE)
_Must_inspect_result_
typedef
NTSTATUS(
NTAPI*
RTLALLOCATEANDINITIALIZESIDEX)(
    _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    _In_ UCHAR SubAuthorityCount,
    _In_reads_(SubAuthorityCount) PULONG SubAuthorities,
    _Outptr_ PSID *Sid
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLINITIALIZESID)(
    _Out_ PSID Sid,
    _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    _In_ UCHAR SubAuthorityCount
    );

#if (PHNT_VERSION >= PHNT_THRESHOLD)
typedef
NTSTATUS(
NTAPI*
RTLINITIALIZESIDEX)(
    _Out_writes_bytes_(SECURITY_SID_SIZE(SubAuthorityCount)) PSID Sid,
    _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    _In_ UCHAR SubAuthorityCount,
    ...
    );
#endif

typedef
PSID_IDENTIFIER_AUTHORITY(
NTAPI*
RTLIDENTIFIERAUTHORITYSID)(
    _In_ PSID Sid
    );

typedef
PULONG(
NTAPI*
RTLSUBAUTHORITYSID)(
    _In_ PSID Sid,
    _In_ ULONG SubAuthority
    );

typedef
PUCHAR(
NTAPI*
RTLSUBAUTHORITYCOUNTSID)(
    _In_ PSID Sid
    );

typedef
ULONG(
NTAPI*
RTLLENGTHSID)(
    _In_ PSID Sid
    );

typedef
NTSTATUS(
NTAPI*
RTLCOPYSID)(
    _In_ ULONG DestinationSidLength,
    _Out_writes_bytes_(DestinationSidLength) PSID DestinationSid,
    _In_ PSID SourceSid
    );

// ros
typedef
NTSTATUS(
NTAPI*
RTLCOPYSIDANDATTRIBUTESARRAY)(
    _In_ ULONG Count,
    _In_ PSID_AND_ATTRIBUTES Src,
    _In_ ULONG SidAreaSize,
    _In_ PSID_AND_ATTRIBUTES Dest,
    _In_ PSID SidArea,
    _Out_ PSID *RemainingSidArea,
    _Out_ PULONG RemainingSidAreaSize
    );

#if (PHNT_VERSION >= PHNT_VISTA)

typedef
NTSTATUS(
NTAPI*
RTLCREATESERVICESID)(
    _In_ PUNICODE_STRING ServiceName,
    _Out_writes_bytes_opt_(*ServiceSidLength) PSID ServiceSid,
    _Inout_ PULONG ServiceSidLength
    );

#endif

#if (PHNT_VERSION >= PHNT_VISTA)

// private
typedef
NTSTATUS(
NTAPI*
RTLSIDDOMINATES)(
    _In_ PSID Sid1,
    _In_ PSID Sid2,
    _Out_ PBOOLEAN Dominates
    );

#endif

#if (PHNT_VERSION >= PHNT_WINBLUE)

// rev
typedef
NTSTATUS(
NTAPI*
RTLSIDDOMINATESFORTRUST)(
    _In_ PSID Sid1,
    _In_ PSID Sid2,
    _Out_ PBOOLEAN DominatesTrust // TokenProcessTrustLevel
    );

#endif

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
RTLSIDEQUALLEVEL)(
    _In_ PSID Sid1,
    _In_ PSID Sid2,
    _Out_ PBOOLEAN EqualLevel
    );

// private
typedef
NTSTATUS(
NTAPI*
RTLSIDISHIGHERLEVEL)(
    _In_ PSID Sid1,
    _In_ PSID Sid2,
    _Out_ PBOOLEAN HigherLevel
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN7)
typedef
NTSTATUS(
NTAPI*
RTLCREATEVIRTUALACCOUNTSID)(
    _In_ PUNICODE_STRING Name,
    _In_ ULONG BaseSubAuthority,
    _Out_writes_bytes_(*SidLength) PSID Sid,
    _Inout_ PULONG SidLength
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN7)
typedef
NTSTATUS(
NTAPI*
RTLREPLACESIDINSD)(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ PSID OldSid,
    _In_ PSID NewSid,
    _Out_ ULONG *NumChanges
    );
#endif

#define MAX_UNICODE_STACK_BUFFER_LENGTH 256

typedef
NTSTATUS(
NTAPI*
RTLLENGTHSIDASUNICODESTRING)(
    _In_ PSID Sid,
    _Out_ PULONG StringLength
    );

typedef
NTSTATUS(
NTAPI*
RTLCONVERTSIDTOUNICODESTRING)(
    _Inout_ PUNICODE_STRING UnicodeString,
    _In_ PSID Sid,
    _In_ BOOLEAN AllocateDestinationString
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
RTLSIDHASHINITIALIZE)(
    _In_reads_(SidCount) PSID_AND_ATTRIBUTES SidAttr,
    _In_ ULONG SidCount,
    _Out_ PSID_AND_ATTRIBUTES_HASH SidAttrHash
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
PSID_AND_ATTRIBUTES(
NTAPI*
RTLSIDHASHLOOKUP)(
    _In_ PSID_AND_ATTRIBUTES_HASH SidAttrHash,
    _In_ PSID Sid
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
// rev
typedef
BOOLEAN(
NTAPI*
RTLISELEVATEDRID)(
    _In_ PSID_AND_ATTRIBUTES SidAttr
    );
#endif

#if (PHNT_VERSION >= PHNT_THRESHOLD)
// rev
typedef
NTSTATUS(
NTAPI*
RTLDERIVECAPABILITYSIDSFROMNAME)(
    _Inout_ PUNICODE_STRING UnicodeString,
    _Out_ PSID CapabilityGroupSid,
    _Out_ PSID CapabilitySid
    );
#endif

// Security Descriptors

typedef
NTSTATUS(
NTAPI*
RTLCREATESECURITYDESCRIPTOR)(
    _Out_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG Revision
    );

_Check_return_
typedef
BOOLEAN(
NTAPI*
RTLVALIDSECURITYDESCRIPTOR)(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
    );

typedef
ULONG(
NTAPI*
RTLLENGTHSECURITYDESCRIPTOR)(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
    );

_Check_return_
typedef
BOOLEAN(
NTAPI*
RTLVALIDRELATIVESECURITYDESCRIPTOR)(
    _In_reads_bytes_(SecurityDescriptorLength) PSECURITY_DESCRIPTOR SecurityDescriptorInput,
    _In_ ULONG SecurityDescriptorLength,
    _In_ SECURITY_INFORMATION RequiredInformation
    );

typedef
NTSTATUS(
NTAPI*
RTLGETCONTROLSECURITYDESCRIPTOR)(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PSECURITY_DESCRIPTOR_CONTROL Control,
    _Out_ PULONG Revision
    );

typedef
NTSTATUS(
NTAPI*
RTLSETCONTROLSECURITYDESCRIPTOR)(
     _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
     _In_ SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest,
     _In_ SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet
     );

typedef
NTSTATUS(
NTAPI*
RTLSETATTRIBUTESSECURITYDESCRIPTOR)(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ SECURITY_DESCRIPTOR_CONTROL Control,
    _Out_ PULONG Revision
    );

typedef
BOOLEAN(
NTAPI*
RTLGETSECURITYDESCRIPTORRMCONTROL)(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PUCHAR RMControl
    );

typedef
VOID(
NTAPI*
RTLSETSECURITYDESCRIPTORRMCONTROL)(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PUCHAR RMControl
    );

typedef
NTSTATUS(
NTAPI*
RTLSETDACLSECURITYDESCRIPTOR)(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN DaclPresent,
    _In_opt_ PACL Dacl,
    _In_ BOOLEAN DaclDefaulted
    );

typedef
NTSTATUS(
NTAPI*
RTLGETDACLSECURITYDESCRIPTOR)(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PBOOLEAN DaclPresent,
    _Outptr_result_maybenull_ PACL *Dacl,
    _Out_ PBOOLEAN DaclDefaulted
    );

typedef
NTSTATUS(
NTAPI*
RTLSETSACLSECURITYDESCRIPTOR)(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN SaclPresent,
    _In_opt_ PACL Sacl,
    _In_ BOOLEAN SaclDefaulted
    );

typedef
NTSTATUS(
NTAPI*
RTLGETSACLSECURITYDESCRIPTOR)(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PBOOLEAN SaclPresent,
    _Out_ PACL *Sacl,
    _Out_ PBOOLEAN SaclDefaulted
    );

typedef
NTSTATUS(
NTAPI*
RTLSETOWNERSECURITYDESCRIPTOR)(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID Owner,
    _In_ BOOLEAN OwnerDefaulted
    );

typedef
NTSTATUS(
NTAPI*
RTLGETOWNERSECURITYDESCRIPTOR)(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Outptr_result_maybenull_ PSID *Owner,
    _Out_ PBOOLEAN OwnerDefaulted
    );

typedef
NTSTATUS(
NTAPI*
RTLSETGROUPSECURITYDESCRIPTOR)(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID Group,
    _In_ BOOLEAN GroupDefaulted
    );

typedef
NTSTATUS(
NTAPI*
RTLGETGROUPSECURITYDESCRIPTOR)(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Outptr_result_maybenull_ PSID *Group,
    _Out_ PBOOLEAN GroupDefaulted
    );

typedef
NTSTATUS(
NTAPI*
RTLMAKESELFRELATIVESD)(
    _In_ PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    _Out_writes_bytes_(*BufferLength) PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Inout_ PULONG BufferLength
    );

typedef
NTSTATUS(
NTAPI*
RTLABSOLUTETOSELFRELATIVESD)(
    _In_ PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Inout_ PULONG BufferLength
    );

typedef
NTSTATUS(
NTAPI*
RTLSELFRELATIVETOABSOLUTESD)(
    _In_ PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Out_writes_bytes_to_opt_(*AbsoluteSecurityDescriptorSize, *AbsoluteSecurityDescriptorSize) PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    _Inout_ PULONG AbsoluteSecurityDescriptorSize,
    _Out_writes_bytes_to_opt_(*DaclSize, *DaclSize) PACL Dacl,
    _Inout_ PULONG DaclSize,
    _Out_writes_bytes_to_opt_(*SaclSize, *SaclSize) PACL Sacl,
    _Inout_ PULONG SaclSize,
    _Out_writes_bytes_to_opt_(*OwnerSize, *OwnerSize) PSID Owner,
    _Inout_ PULONG OwnerSize,
    _Out_writes_bytes_to_opt_(*PrimaryGroupSize, *PrimaryGroupSize) PSID PrimaryGroup,
    _Inout_ PULONG PrimaryGroupSize
    );

// private
typedef
NTSTATUS(
NTAPI*
RTLSELFRELATIVETOABSOLUTESD2)(
    _Inout_ PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    _Inout_ PULONG BufferSize
    );

// Access masks

#ifndef PHNT_NO_INLINE_ACCESSES_GRANTED
FORCEINLINE
BOOLEAN
NTAPI
RtlAreAllAccessesGranted(
    _In_ ACCESS_MASK GrantedAccess,
    _In_ ACCESS_MASK DesiredAccess
    )
{
    return (~GrantedAccess & DesiredAccess) == 0;
}

FORCEINLINE
BOOLEAN
NTAPI
RtlAreAnyAccessesGranted(
    _In_ ACCESS_MASK GrantedAccess,
    _In_ ACCESS_MASK DesiredAccess
    )
{
    return (GrantedAccess & DesiredAccess) != 0;
}
#else
typedef
BOOLEAN(
NTAPI*
RTLAREALLACCESSESGRANTED)(
    _In_ ACCESS_MASK GrantedAccess,
    _In_ ACCESS_MASK DesiredAccess
    );

typedef
BOOLEAN(
NTAPI*
RTLAREANYACCESSESGRANTED)(
    _In_ ACCESS_MASK GrantedAccess,
    _In_ ACCESS_MASK DesiredAccess
    );
#endif

typedef
VOID(
NTAPI*
RTLMAPGENERICMASK)(
    _Inout_ PACCESS_MASK AccessMask,
    _In_ PGENERIC_MAPPING GenericMapping
    );

// ACLs

typedef
NTSTATUS(
NTAPI*
RTLCREATEACL)(
    _Out_writes_bytes_(AclLength) PACL Acl,
    _In_ ULONG AclLength,
    _In_ ULONG AclRevision
    );

typedef
BOOLEAN(
NTAPI*
RTLVALIDACL)(
    _In_ PACL Acl
    );

typedef
NTSTATUS(
NTAPI*
RTLQUERYINFORMATIONACL)(
    _In_ PACL Acl,
    _Out_writes_bytes_(AclInformationLength) PVOID AclInformation,
    _In_ ULONG AclInformationLength,
    _In_ ACL_INFORMATION_CLASS AclInformationClass
    );

typedef
NTSTATUS(
NTAPI*
RTLSETINFORMATIONACL)(
    _Inout_ PACL Acl,
    _In_reads_bytes_(AclInformationLength) PVOID AclInformation,
    _In_ ULONG AclInformationLength,
    _In_ ACL_INFORMATION_CLASS AclInformationClass
    );

typedef
NTSTATUS(
NTAPI*
RTLADDACE)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG StartingAceIndex,
    _In_reads_bytes_(AceListLength) PVOID AceList,
    _In_ ULONG AceListLength
    );

typedef
NTSTATUS(
NTAPI*
RTLDELETEACE)(
    _Inout_ PACL Acl,
    _In_ ULONG AceIndex
    );

typedef
NTSTATUS(
NTAPI*
RTLGETACE)(
    _In_ PACL Acl,
    _In_ ULONG AceIndex,
    _Outptr_ PVOID *Ace
    );

typedef
BOOLEAN(
NTAPI*
RTLFIRSTFREEACE)(
    _In_ PACL Acl,
    _Out_ PVOID *FirstFree
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
PVOID(
NTAPI*
RTLFINDACEBYTYPE)(
    _In_ PACL Acl,
    _In_ UCHAR AceType,
    _Out_opt_ PULONG Index
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
BOOLEAN(
NTAPI*
RTLOWNERACESPRESENT)(
    _In_ PACL pAcl
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLADDACCESSALLOWEDACE)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid
    );

typedef
NTSTATUS(
NTAPI*
RTLADDACCESSALLOWEDACEEX)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid
    );

typedef
NTSTATUS(
NTAPI*
RTLADDACCESSDENIEDACE)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid
    );

typedef
NTSTATUS(
NTAPI*
RTLADDACCESSDENIEDACEEX)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid
    );

typedef
NTSTATUS(
NTAPI*
RTLADDAUDITACCESSACE)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid,
    _In_ BOOLEAN AuditSuccess,
    _In_ BOOLEAN AuditFailure
    );

typedef
NTSTATUS(
NTAPI*
RTLADDAUDITACCESSACEEX)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid,
    _In_ BOOLEAN AuditSuccess,
    _In_ BOOLEAN AuditFailure
    );

typedef
NTSTATUS(
NTAPI*
RTLADDACCESSALLOWEDOBJECTACE)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_opt_ PGUID ObjectTypeGuid,
    _In_opt_ PGUID InheritedObjectTypeGuid,
    _In_ PSID Sid
    );

typedef
NTSTATUS(
NTAPI*
RTLADDACCESSDENIEDOBJECTACE)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_opt_ PGUID ObjectTypeGuid,
    _In_opt_ PGUID InheritedObjectTypeGuid,
    _In_ PSID Sid
    );

typedef
NTSTATUS(
NTAPI*
RTLADDAUDITACCESSOBJECTACE)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_opt_ PGUID ObjectTypeGuid,
    _In_opt_ PGUID InheritedObjectTypeGuid,
    _In_ PSID Sid,
    _In_ BOOLEAN AuditSuccess,
    _In_ BOOLEAN AuditFailure
    );

typedef
NTSTATUS(
NTAPI*
RTLADDCOMPOUNDACE)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ UCHAR AceType,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID ServerSid,
    _In_ PSID ClientSid
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
RTLADDMANDATORYACE)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ PSID Sid,
    _In_ UCHAR AceType,
    _In_ ACCESS_MASK AccessMask
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN8)
typedef
NTSTATUS(
NTAPI*
RTLADDRESOURCEATTRIBUTEACE)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ULONG AccessMask,
    _In_ PSID Sid,
    _In_ PCLAIM_SECURITY_ATTRIBUTES_INFORMATION AttributeInfo,
    _Out_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
RTLADDSCOPEDPOLICYIDACE)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ULONG AccessMask,
    _In_ PSID Sid
    );
#endif

// Named pipes

typedef
NTSTATUS(
NTAPI*
RTLDEFAULTNPACL)(
    _Out_ PACL *Acl
    );

// Security objects

typedef
NTSTATUS(
NTAPI*
RTLNEWSECURITYOBJECT)(
    _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
    _In_opt_ PSECURITY_DESCRIPTOR CreatorDescriptor,
    _Out_ PSECURITY_DESCRIPTOR *NewDescriptor,
    _In_ BOOLEAN IsDirectoryObject,
    _In_opt_ HANDLE Token,
    _In_ PGENERIC_MAPPING GenericMapping
    );

typedef
NTSTATUS(
NTAPI*
RTLNEWSECURITYOBJECTEX)(
    _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
    _In_opt_ PSECURITY_DESCRIPTOR CreatorDescriptor,
    _Out_ PSECURITY_DESCRIPTOR *NewDescriptor,
    _In_opt_ GUID *ObjectType,
    _In_ BOOLEAN IsDirectoryObject,
    _In_ ULONG AutoInheritFlags, // SEF_*
    _In_opt_ HANDLE Token,
    _In_ PGENERIC_MAPPING GenericMapping
    );

typedef
NTSTATUS(
NTAPI*
RTLNEWSECURITYOBJECTWITHMULTIPLEINHERITANCE)(
    _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
    _In_opt_ PSECURITY_DESCRIPTOR CreatorDescriptor,
    _Out_ PSECURITY_DESCRIPTOR *NewDescriptor,
    _In_opt_ GUID **ObjectType,
    _In_ ULONG GuidCount,
    _In_ BOOLEAN IsDirectoryObject,
    _In_ ULONG AutoInheritFlags, // SEF_*
    _In_opt_ HANDLE Token,
    _In_ PGENERIC_MAPPING GenericMapping
    );

typedef
NTSTATUS(
NTAPI*
RTLDELETESECURITYOBJECT)(
    _Inout_ PSECURITY_DESCRIPTOR *ObjectDescriptor
    );

typedef
NTSTATUS(
NTAPI*
RTLQUERYSECURITYOBJECT)(
     _In_ PSECURITY_DESCRIPTOR ObjectDescriptor,
     _In_ SECURITY_INFORMATION SecurityInformation,
     _Out_opt_ PSECURITY_DESCRIPTOR ResultantDescriptor,
     _In_ ULONG DescriptorLength,
     _Out_ PULONG ReturnLength
     );

typedef
NTSTATUS(
NTAPI*
RTLSETSECURITYOBJECT)(
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR ModificationDescriptor,
    _Inout_ PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_opt_ HANDLE Token
    );

typedef
NTSTATUS(
NTAPI*
RTLSETSECURITYOBJECTEX)(
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR ModificationDescriptor,
    _Inout_ PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
    _In_ ULONG AutoInheritFlags, // SEF_*
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_opt_ HANDLE Token
    );

typedef
NTSTATUS(
NTAPI*
RTLCONVERTTOAUTOINHERITSECURITYOBJECT)(
    _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
    _In_ PSECURITY_DESCRIPTOR CurrentSecurityDescriptor,
    _Out_ PSECURITY_DESCRIPTOR *NewSecurityDescriptor,
    _In_opt_ GUID *ObjectType,
    _In_ BOOLEAN IsDirectoryObject,
    _In_ PGENERIC_MAPPING GenericMapping
    );

typedef
NTSTATUS(
NTAPI*
RTLNEWINSTANCESECURITYOBJECT)(
    _In_ BOOLEAN ParentDescriptorChanged,
    _In_ BOOLEAN CreatorDescriptorChanged,
    _In_ PLUID OldClientTokenModifiedId,
    _Out_ PLUID NewClientTokenModifiedId,
    _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
    _In_opt_ PSECURITY_DESCRIPTOR CreatorDescriptor,
    _Out_ PSECURITY_DESCRIPTOR *NewDescriptor,
    _In_ BOOLEAN IsDirectoryObject,
    _In_ HANDLE Token,
    _In_ PGENERIC_MAPPING GenericMapping
    );

typedef
NTSTATUS(
NTAPI*
RTLCOPYSECURITYDESCRIPTOR)(
    _In_ PSECURITY_DESCRIPTOR InputSecurityDescriptor,
    _Out_ PSECURITY_DESCRIPTOR *OutputSecurityDescriptor
    );

// private
typedef struct _RTL_ACE_DATA
{
    UCHAR AceType;
    UCHAR InheritFlags;
    UCHAR AceFlags;
    ACCESS_MASK AccessMask;
    PSID* Sid;
} RTL_ACE_DATA, *PRTL_ACE_DATA;

typedef
NTSTATUS(
NTAPI*
RTLCREATEUSERSECURITYOBJECT)(
    _In_ PRTL_ACE_DATA AceData,
    _In_ ULONG AceCount,
    _In_ PSID OwnerSid,
    _In_ PSID GroupSid,
    _In_ BOOLEAN IsDirectoryObject,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_ PSECURITY_DESCRIPTOR* NewSecurityDescriptor
    );

typedef
NTSTATUS(
NTAPI*
RTLCREATEANDSETSD)(
    _In_ PRTL_ACE_DATA AceData,
    _In_ ULONG AceCount,
    _In_opt_ PSID OwnerSid,
    _In_opt_ PSID GroupSid,
    _Out_ PSECURITY_DESCRIPTOR* NewSecurityDescriptor
    );

// Misc. security

typedef
VOID(
NTAPI*
RTLRUNENCODEUNICODESTRING)(
    _Inout_ PUCHAR Seed,
    _Inout_ PUNICODE_STRING String
    );

typedef
VOID(
NTAPI*
RTLRUNDECODEUNICODESTRING)(
    _In_ UCHAR Seed,
    _Inout_ PUNICODE_STRING String
    );

typedef
NTSTATUS(
NTAPI*
RTLIMPERSONATESELF)(
    _In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
RTLIMPERSONATESELFEX)(
    _In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    _In_opt_ ACCESS_MASK AdditionalAccess,
    _Out_opt_ PHANDLE ThreadToken
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLADJUSTPRIVILEGE)(
    _In_ ULONG Privilege,
    _In_ BOOLEAN Enable,
    _In_ BOOLEAN Client,
    _Out_ PBOOLEAN WasEnabled
    );

#define RTL_ACQUIRE_PRIVILEGE_REVERT 0x00000001
#define RTL_ACQUIRE_PRIVILEGE_PROCESS 0x00000002

typedef
NTSTATUS(
NTAPI*
RTLACQUIREPRIVILEGE)(
    _In_ PULONG Privilege,
    _In_ ULONG NumPriv,
    _In_ ULONG Flags,
    _Out_ PVOID *ReturnedState
    );

typedef
VOID(
NTAPI*
RTLRELEASEPRIVILEGE)(
    _In_ PVOID StatePointer
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// private
typedef
NTSTATUS(
NTAPI*
RTLREMOVEPRIVILEGES)(
    _In_ HANDLE TokenHandle,
    _In_ PULONG PrivilegesToKeep,
    _In_ ULONG PrivilegeCount
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN8)

// rev
typedef
NTSTATUS(
NTAPI*
RTLISUNTRUSTEDOBJECT)(
    _In_opt_ HANDLE Handle,
    _In_opt_ PVOID Object,
    _Out_ PBOOLEAN IsUntrustedObject
    );

typedef
ULONG(
NTAPI*
RTLQUERYVALIDATIONRUNLEVEL)(
    _In_opt_ PUNICODE_STRING ComponentName
    );

#endif

// Private namespaces

#if (PHNT_VERSION >= PHNT_VISTA)

// rev
#define BOUNDARY_DESCRIPTOR_ADD_APPCONTAINER_SID 0x0001

// begin_private

_Ret_maybenull_
_Success_(return != NULL)
typedef
POBJECT_BOUNDARY_DESCRIPTOR(
NTAPI*
RTLCREATEBOUNDARYDESCRIPTOR)(
    _In_ PUNICODE_STRING Name,
    _In_ ULONG Flags
    );

typedef
VOID(
NTAPI*
RTLDELETEBOUNDARYDESCRIPTOR)(
    _In_ _Post_invalid_ POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor
    );

typedef
NTSTATUS(
NTAPI*
RTLADDSIDTOBOUNDARYDESCRIPTOR)(
    _Inout_ POBJECT_BOUNDARY_DESCRIPTOR *BoundaryDescriptor,
    _In_ PSID RequiredSid
    );

#if (PHNT_VERSION >= PHNT_WIN7)
// rev
typedef
NTSTATUS(
NTAPI*
RTLADDINTEGRITYLABELTOBOUNDARYDESCRIPTOR)(
    _Inout_ POBJECT_BOUNDARY_DESCRIPTOR *BoundaryDescriptor,
    _In_ PSID IntegrityLabel
    );
#endif

// end_private

#endif

// Version

typedef
NTSTATUS(
NTAPI*
RTLGETVERSION)(
    _Out_ PRTL_OSVERSIONINFOEXW VersionInformation // PRTL_OSVERSIONINFOW
    );

typedef
NTSTATUS(
NTAPI*
RTLVERIFYVERSIONINFO)(
    _In_ PRTL_OSVERSIONINFOEXW VersionInformation, // PRTL_OSVERSIONINFOW
    _In_ ULONG TypeMask,
    _In_ ULONGLONG ConditionMask
    );

// rev
typedef
VOID(
NTAPI*
RTLGETNTVERSIONNUMBERS)(
    _Out_opt_ PULONG NtMajorVersion,
    _Out_opt_ PULONG NtMinorVersion,
    _Out_opt_ PULONG NtBuildNumber
    );

// System information

// rev
typedef
ULONG(
NTAPI*
RTLGETNTGLOBALFLAGS)(
    VOID
    );

// rev
typedef
BOOLEAN(
NTAPI*
RTLGETNTPRODUCTTYPE)(
    _Out_ PNT_PRODUCT_TYPE NtProductType
    );

#if (PHNT_VERSION >= PHNT_REDSTONE)
// private
typedef
ULONG(
NTAPI*
RTLGETSUITEMASK)(
    VOID
    );
#endif

// Thread pool (old)

typedef
NTSTATUS(
NTAPI*
RTLREGISTERWAIT)(
    _Out_ PHANDLE WaitHandle,
    _In_ HANDLE Handle,
    _In_ WAITORTIMERCALLBACKFUNC Function,
    _In_ PVOID Context,
    _In_ ULONG Milliseconds,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
RTLDEREGISTERWAIT)(
    _In_ HANDLE WaitHandle
    );

#define RTL_WAITER_DEREGISTER_WAIT_FOR_COMPLETION ((HANDLE)(LONG_PTR)-1)

typedef
NTSTATUS(
NTAPI*
RTLDEREGISTERWAITEX)(
    _In_ HANDLE WaitHandle,
    _In_opt_ HANDLE Event // optional: RTL_WAITER_DEREGISTER_WAIT_FOR_COMPLETION
    );

typedef
NTSTATUS(
NTAPI*
RTLQUEUEWORKITEM)(
    _In_ WORKERCALLBACKFUNC Function,
    _In_ PVOID Context,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
RTLSETIOCOMPLETIONCALLBACK)(
    _In_ HANDLE FileHandle,
    _In_ APC_CALLBACK_FUNCTION CompletionProc,
    _In_ ULONG Flags
    );

typedef NTSTATUS (NTAPI *PRTL_START_POOL_THREAD)(
    _In_ PTHREAD_START_ROUTINE Function,
    _In_ PVOID Parameter,
    _Out_ PHANDLE ThreadHandle
    );

typedef NTSTATUS (NTAPI *PRTL_EXIT_POOL_THREAD)(
    _In_ NTSTATUS ExitStatus
    );

typedef
NTSTATUS(
NTAPI*
RTLSETTHREADPOOLSTARTFUNC)(
    _In_ PRTL_START_POOL_THREAD StartPoolThread,
    _In_ PRTL_EXIT_POOL_THREAD ExitPoolThread
    );

typedef
VOID(
NTAPI*
RTLUSERTHREADSTART)(
    _In_ PTHREAD_START_ROUTINE Function,
    _In_ PVOID Parameter
    );

typedef
VOID(
NTAPI*
LDRINITIALIZETHUNK)(
    _In_ PCONTEXT ContextRecord,
    _In_ PVOID Parameter
    );

// Thread execution

typedef
NTSTATUS(
NTAPI*
RTLDELAYEXECUTION)(
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER DelayInterval
    );

// Timer support

typedef
NTSTATUS(
NTAPI*
RTLCREATETIMERQUEUE)(
    _Out_ PHANDLE TimerQueueHandle
    );

typedef
NTSTATUS(
NTAPI*
RTLCREATETIMER)(
    _In_ HANDLE TimerQueueHandle,
    _Out_ PHANDLE Handle,
    _In_ WAITORTIMERCALLBACKFUNC Function,
    _In_opt_ PVOID Context,
    _In_ ULONG DueTime,
    _In_ ULONG Period,
    _In_ ULONG Flags
    );

typedef
NTSTATUS(
NTAPI*
RTLUPDATETIMER)(
    _In_ HANDLE TimerQueueHandle,
    _In_ HANDLE TimerHandle,
    _In_ ULONG DueTime,
    _In_ ULONG Period
    );

#define RTL_TIMER_DELETE_WAIT_FOR_COMPLETION ((HANDLE)(LONG_PTR)-1)

typedef
NTSTATUS(
NTAPI*
RTLDELETETIMER)(
    _In_ HANDLE TimerQueueHandle,
    _In_ HANDLE TimerToCancel,
    _In_opt_ HANDLE Event // optional: RTL_TIMER_DELETE_WAIT_FOR_COMPLETION
    );

typedef
NTSTATUS(
NTAPI*
RTLDELETETIMERQUEUE)(
    _In_ HANDLE TimerQueueHandle
    );

typedef
NTSTATUS(
NTAPI*
RTLDELETETIMERQUEUEEX)(
    _In_ HANDLE TimerQueueHandle,
    _In_opt_ HANDLE Event
    );

// Registry access

typedef
NTSTATUS(
NTAPI*
RTLFORMATCURRENTUSERKEYPATH)(
    _Out_ PUNICODE_STRING CurrentUserKeyPath
    );

typedef
NTSTATUS(
NTAPI*
RTLOPENCURRENTUSER)(
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE CurrentUserKey
    );

#define RTL_REGISTRY_ABSOLUTE 0
#define RTL_REGISTRY_SERVICES 1 // \Registry\Machine\System\CurrentControlSet\Services
#define RTL_REGISTRY_CONTROL 2 // \Registry\Machine\System\CurrentControlSet\Control
#define RTL_REGISTRY_WINDOWS_NT 3 // \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion
#define RTL_REGISTRY_DEVICEMAP 4 // \Registry\Machine\Hardware\DeviceMap
#define RTL_REGISTRY_USER 5 // \Registry\User\CurrentUser
#define RTL_REGISTRY_MAXIMUM 6
#define RTL_REGISTRY_HANDLE 0x40000000
#define RTL_REGISTRY_OPTIONAL 0x80000000

typedef
NTSTATUS(
NTAPI*
RTLCREATEREGISTRYKEY)(
    _In_ ULONG RelativeTo,
    _In_ PWSTR Path
    );

typedef
NTSTATUS(
NTAPI*
RTLCHECKREGISTRYKEY)(
    _In_ ULONG RelativeTo,
    _In_ PWSTR Path
    );

typedef NTSTATUS (NTAPI *PRTL_QUERY_REGISTRY_ROUTINE)(
    _In_ PWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength,
    _In_ PVOID Context,
    _In_ PVOID EntryContext
    );

typedef struct _RTL_QUERY_REGISTRY_TABLE
{
    PRTL_QUERY_REGISTRY_ROUTINE QueryRoutine;
    ULONG Flags;
    PWSTR Name;
    PVOID EntryContext;
    ULONG DefaultType;
    PVOID DefaultData;
    ULONG DefaultLength;
} RTL_QUERY_REGISTRY_TABLE, *PRTL_QUERY_REGISTRY_TABLE;

#define RTL_QUERY_REGISTRY_SUBKEY 0x00000001
#define RTL_QUERY_REGISTRY_TOPKEY 0x00000002
#define RTL_QUERY_REGISTRY_REQUIRED 0x00000004
#define RTL_QUERY_REGISTRY_NOVALUE 0x00000008
#define RTL_QUERY_REGISTRY_NOEXPAND 0x00000010
#define RTL_QUERY_REGISTRY_DIRECT 0x00000020
#define RTL_QUERY_REGISTRY_DELETE 0x00000040

typedef
NTSTATUS(
NTAPI*
RTLQUERYREGISTRYVALUES)(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _In_ PRTL_QUERY_REGISTRY_TABLE QueryTable,
    _In_ PVOID Context,
    _In_opt_ PVOID Environment
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLQUERYREGISTRYVALUESEX)(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _In_ PRTL_QUERY_REGISTRY_TABLE QueryTable,
    _In_ PVOID Context,
    _In_opt_ PVOID Environment
    );

typedef
NTSTATUS(
NTAPI*
RTLWRITEREGISTRYVALUE)(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _In_ PCWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength
    );

typedef
NTSTATUS(
NTAPI*
RTLDELETEREGISTRYVALUE)(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _In_ PCWSTR ValueName
    );

// Thread profiling

#if (PHNT_VERSION >= PHNT_WIN7)

// rev
typedef
NTSTATUS(
NTAPI*
RTLENABLETHREADPROFILING)(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG Flags,
    _In_ ULONG64 HardwareCounters,
    _Out_ PVOID *PerformanceDataHandle
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLDISABLETHREADPROFILING)(
    _In_ PVOID PerformanceDataHandle
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLQUERYTHREADPROFILING)(
    _In_ HANDLE ThreadHandle,
    _Out_ PBOOLEAN Enabled
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLREADTHREADPROFILINGDATA)(
    _In_ HANDLE PerformanceDataHandle,
    _In_ ULONG Flags,
    _Out_ PPERFORMANCE_DATA PerformanceData
    );

#endif

// WOW64

typedef
NTSTATUS(
NTAPI*
RTLGETNATIVESYSTEMINFORMATION)(
    _In_ ULONG SystemInformationClass,
    _In_ PVOID NativeSystemInformation,
    _In_ ULONG InformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef
NTSTATUS(
NTAPI*
RTLQUEUEAPCWOW64THREAD)(
    _In_ HANDLE ThreadHandle,
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );

typedef
NTSTATUS(
NTAPI*
RTLWOW64ENABLEFSREDIRECTION)(
    _In_ BOOLEAN Wow64FsEnableRedirection
    );

typedef
NTSTATUS(
NTAPI*
RTLWOW64ENABLEFSREDIRECTIONEX)(
    _In_ PVOID Wow64FsEnableRedirection,
    _Out_ PVOID *OldFsRedirectionLevel
    );

// Misc.

typedef
ULONG32(
NTAPI*
RTLCOMPUTECRC32)(
    _In_ ULONG32 PartialCrc,
    _In_ PVOID Buffer,
    _In_ ULONG Length
    );

typedef
PVOID(
NTAPI*
RTLENCODEPOINTER)(
    _In_ PVOID Ptr
    );

typedef
PVOID(
NTAPI*
RTLDECODEPOINTER)(
    _In_ PVOID Ptr
    );

typedef
PVOID(
NTAPI*
RTLENCODESYSTEMPOINTER)(
    _In_ PVOID Ptr
    );

typedef
PVOID(
NTAPI*
RTLDECODESYSTEMPOINTER)(
    _In_ PVOID Ptr
    );

#if (PHNT_VERSION >= PHNT_THRESHOLD)
// rev
typedef
NTSTATUS(
NTAPI*
RTLENCODEREMOTEPOINTER)(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID Pointer,
    _Out_ PVOID *EncodedPointer
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLDECODEREMOTEPOINTER)(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID Pointer,
    _Out_ PVOID *DecodedPointer
    );
#endif

// rev
typedef
BOOLEAN(
NTAPI*
RTLISPROCESSORFEATUREPRESENT)(
    _In_ ULONG ProcessorFeature
    );

// rev
typedef
ULONG(
NTAPI*
RTLGETCURRENTPROCESSORNUMBER)(
    VOID
    );

#if (PHNT_VERSION >= PHNT_WIN7)

// rev
typedef
VOID(
NTAPI*
RTLGETCURRENTPROCESSORNUMBEREX)(
    _Out_ PPROCESSOR_NUMBER ProcessorNumber
    );

#endif

// Stack support

typedef
VOID(
NTAPI*
RTLPUSHFRAME)(
    _In_ PTEB_ACTIVE_FRAME Frame
    );

typedef
VOID(
NTAPI*
RTLPOPFRAME)(
    _In_ PTEB_ACTIVE_FRAME Frame
    );

typedef
PTEB_ACTIVE_FRAME(
NTAPI*
RTLGETFRAME)(
    VOID
    );

#define RTL_WALK_USER_MODE_STACK 0x00000001
#define RTL_WALK_VALID_FLAGS 0x00000001
#define RTL_STACK_WALKING_MODE_FRAMES_TO_SKIP_SHIFT 0x00000008

// private
typedef
ULONG(
NTAPI*
RTLWALKFRAMECHAIN)(
    _Out_writes_(Count - (Flags >> RTL_STACK_WALKING_MODE_FRAMES_TO_SKIP_SHIFT)) PVOID *Callers,
    _In_ ULONG Count,
    _In_ ULONG Flags
    );

// rev
typedef
VOID(
NTAPI*
RTLGETCALLERSADDRESS)( // Use the intrinsic _ReturnAddress instead.
    _Out_ PVOID *CallersAddress,
    _Out_ PVOID *CallersCaller
    );

#if (PHNT_VERSION >= PHNT_WIN7)

typedef
ULONG64(
NTAPI*
RTLGETENABLEDEXTENDEDFEATURES)(
    _In_ ULONG64 FeatureMask
    );

#endif

#if (PHNT_VERSION >= PHNT_REDSTONE4)

// msdn
typedef
ULONG64(
NTAPI*
RTLGETENABLEDEXTENDEDANDSUPERVISORFEATURES)(
    _In_ ULONG64 FeatureMask
    );

// msdn
_Ret_maybenull_
_Success_(return != NULL)
typedef
PVOID(
NTAPI*
RTLLOCATESUPERVISORFEATURE)(
    _In_ PXSAVE_AREA_HEADER XStateHeader,
    _In_range_(XSTATE_AVX, MAXIMUM_XSTATE_FEATURES - 1) ULONG FeatureId,
    _Out_opt_ PULONG Length
    );

#endif

// private
typedef union _RTL_ELEVATION_FLAGS
{
    ULONG Flags;
    struct
    {
        ULONG ElevationEnabled : 1;
        ULONG VirtualizationEnabled : 1;
        ULONG InstallerDetectEnabled : 1;
        ULONG ReservedBits : 29;
    };
} RTL_ELEVATION_FLAGS, *PRTL_ELEVATION_FLAGS;

#if (PHNT_VERSION >= PHNT_VISTA)

// private
typedef
NTSTATUS(
NTAPI*
RTLQUERYELEVATIONFLAGS)(
    _Out_ PRTL_ELEVATION_FLAGS Flags
    );

#endif

#if (PHNT_VERSION >= PHNT_VISTA)

// private
typedef
NTSTATUS(
NTAPI*
RTLREGISTERTHREADWITHCSRSS)(
    VOID
    );

#endif

#if (PHNT_VERSION >= PHNT_VISTA)

// private
typedef
NTSTATUS(
NTAPI*
RTLLOCKCURRENTTHREAD)(
    VOID
    );

#endif

#if (PHNT_VERSION >= PHNT_VISTA)

// private
typedef
NTSTATUS(
NTAPI*
RTLUNLOCKCURRENTTHREAD)(
    VOID
    );

#endif

#if (PHNT_VERSION >= PHNT_VISTA)

// private
typedef
NTSTATUS(
NTAPI*
RTLLOCKMODULESECTION)(
    _In_ PVOID Address
    );

#endif

#if (PHNT_VERSION >= PHNT_VISTA)

// private
typedef
NTSTATUS(
NTAPI*
RTLUNLOCKMODULESECTION)(
    _In_ PVOID Address
    );

#endif

// begin_msdn:"Winternl"

#define RTL_UNLOAD_EVENT_TRACE_NUMBER 64

// private
typedef struct _RTL_UNLOAD_EVENT_TRACE
{
    PVOID BaseAddress;
    SIZE_T SizeOfImage;
    ULONG Sequence;
    ULONG TimeDateStamp;
    ULONG CheckSum;
    WCHAR ImageName[32];
    ULONG Version[2];
} RTL_UNLOAD_EVENT_TRACE, *PRTL_UNLOAD_EVENT_TRACE;

typedef struct _RTL_UNLOAD_EVENT_TRACE32 
{
    ULONG BaseAddress;
    ULONG SizeOfImage;
    ULONG Sequence;
    ULONG TimeDateStamp;
    ULONG CheckSum;
    WCHAR ImageName[32];
    ULONG Version[2];
} RTL_UNLOAD_EVENT_TRACE32, *PRTL_UNLOAD_EVENT_TRACE32;

typedef
PRTL_UNLOAD_EVENT_TRACE(
NTAPI*
RTLGETUNLOADEVENTTRACE)(
    VOID
    );

#if (PHNT_VERSION >= PHNT_VISTA)
typedef
VOID(
NTAPI*
RTLGETUNLOADEVENTTRACEEX)(
    _Out_ PULONG *ElementSize,
    _Out_ PULONG *ElementCount,
    _Out_ PVOID *EventTrace // works across all processes
    );
#endif

// end_msdn

#if (PHNT_VERSION >= PHNT_WIN7)
// rev
typedef
LOGICAL(
NTAPI*
RTLQUERYPERFORMANCECOUNTER)(
    _Out_ PLARGE_INTEGER PerformanceCounter
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN7)
// rev
typedef
LOGICAL(
NTAPI*
RTLQUERYPERFORMANCEFREQUENCY)(
    _Out_ PLARGE_INTEGER PerformanceFrequency
    );
#endif

// Image Mitigation

// rev
typedef enum _IMAGE_MITIGATION_POLICY
{
    ImageDepPolicy, // RTL_IMAGE_MITIGATION_DEP_POLICY
    ImageAslrPolicy, // RTL_IMAGE_MITIGATION_ASLR_POLICY
    ImageDynamicCodePolicy, // RTL_IMAGE_MITIGATION_DYNAMIC_CODE_POLICY
    ImageStrictHandleCheckPolicy, // RTL_IMAGE_MITIGATION_STRICT_HANDLE_CHECK_POLICY
    ImageSystemCallDisablePolicy, // RTL_IMAGE_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
    ImageMitigationOptionsMask,
    ImageExtensionPointDisablePolicy, // RTL_IMAGE_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
    ImageControlFlowGuardPolicy, // RTL_IMAGE_MITIGATION_CONTROL_FLOW_GUARD_POLICY
    ImageSignaturePolicy, // RTL_IMAGE_MITIGATION_BINARY_SIGNATURE_POLICY
    ImageFontDisablePolicy, // RTL_IMAGE_MITIGATION_FONT_DISABLE_POLICY
    ImageImageLoadPolicy, // RTL_IMAGE_MITIGATION_IMAGE_LOAD_POLICY
    ImagePayloadRestrictionPolicy, // RTL_IMAGE_MITIGATION_PAYLOAD_RESTRICTION_POLICY
    ImageChildProcessPolicy, // RTL_IMAGE_MITIGATION_CHILD_PROCESS_POLICY
    ImageSehopPolicy, // RTL_IMAGE_MITIGATION_SEHOP_POLICY
    ImageHeapPolicy, // RTL_IMAGE_MITIGATION_HEAP_POLICY
    ImageUserShadowStackPolicy, // RTL_IMAGE_MITIGATION_USER_SHADOW_STACK_POLICY
    MaxImageMitigationPolicy
} IMAGE_MITIGATION_POLICY;

// rev
typedef union _RTL_IMAGE_MITIGATION_POLICY
{
    struct
    {
        ULONG64 AuditState : 2;
        ULONG64 AuditFlag : 1;
        ULONG64 EnableAdditionalAuditingOption : 1;
        ULONG64 Reserved : 60;
    };
    struct
    {
        ULONG64 PolicyState : 2;
        ULONG64 AlwaysInherit : 1;
        ULONG64 EnableAdditionalPolicyOption : 1;
        ULONG64 AuditReserved : 60;
    };
} RTL_IMAGE_MITIGATION_POLICY, *PRTL_IMAGE_MITIGATION_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_DEP_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY Dep;
} RTL_IMAGE_MITIGATION_DEP_POLICY, *PRTL_IMAGE_MITIGATION_DEP_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_ASLR_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY ForceRelocateImages;
    RTL_IMAGE_MITIGATION_POLICY BottomUpRandomization;
    RTL_IMAGE_MITIGATION_POLICY HighEntropyRandomization;
} RTL_IMAGE_MITIGATION_ASLR_POLICY, *PRTL_IMAGE_MITIGATION_ASLR_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_DYNAMIC_CODE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY BlockDynamicCode;
} RTL_IMAGE_MITIGATION_DYNAMIC_CODE_POLICY, *PRTL_IMAGE_MITIGATION_DYNAMIC_CODE_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_STRICT_HANDLE_CHECK_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY StrictHandleChecks;
} RTL_IMAGE_MITIGATION_STRICT_HANDLE_CHECK_POLICY, *PRTL_IMAGE_MITIGATION_STRICT_HANDLE_CHECK_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY BlockWin32kSystemCalls;
} RTL_IMAGE_MITIGATION_SYSTEM_CALL_DISABLE_POLICY, *PRTL_IMAGE_MITIGATION_SYSTEM_CALL_DISABLE_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY DisableExtensionPoints;
} RTL_IMAGE_MITIGATION_EXTENSION_POINT_DISABLE_POLICY, *PRTL_IMAGE_MITIGATION_EXTENSION_POINT_DISABLE_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_CONTROL_FLOW_GUARD_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY ControlFlowGuard;
    RTL_IMAGE_MITIGATION_POLICY StrictControlFlowGuard;
} RTL_IMAGE_MITIGATION_CONTROL_FLOW_GUARD_POLICY, *PRTL_IMAGE_MITIGATION_CONTROL_FLOW_GUARD_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_BINARY_SIGNATURE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY BlockNonMicrosoftSignedBinaries;
    RTL_IMAGE_MITIGATION_POLICY EnforceSigningOnModuleDependencies;
} RTL_IMAGE_MITIGATION_BINARY_SIGNATURE_POLICY, *PRTL_IMAGE_MITIGATION_BINARY_SIGNATURE_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_FONT_DISABLE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY DisableNonSystemFonts;
} RTL_IMAGE_MITIGATION_FONT_DISABLE_POLICY, *PRTL_IMAGE_MITIGATION_FONT_DISABLE_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_IMAGE_LOAD_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY BlockRemoteImageLoads;
    RTL_IMAGE_MITIGATION_POLICY BlockLowLabelImageLoads;
    RTL_IMAGE_MITIGATION_POLICY PreferSystem32;
} RTL_IMAGE_MITIGATION_IMAGE_LOAD_POLICY, *PRTL_IMAGE_MITIGATION_IMAGE_LOAD_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_PAYLOAD_RESTRICTION_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY EnableExportAddressFilter;
    RTL_IMAGE_MITIGATION_POLICY EnableExportAddressFilterPlus;
    RTL_IMAGE_MITIGATION_POLICY EnableImportAddressFilter;
    RTL_IMAGE_MITIGATION_POLICY EnableRopStackPivot;
    RTL_IMAGE_MITIGATION_POLICY EnableRopCallerCheck;
    RTL_IMAGE_MITIGATION_POLICY EnableRopSimExec;
    WCHAR EafPlusModuleList[512]; // 19H1
} RTL_IMAGE_MITIGATION_PAYLOAD_RESTRICTION_POLICY, *PRTL_IMAGE_MITIGATION_PAYLOAD_RESTRICTION_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_CHILD_PROCESS_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY DisallowChildProcessCreation;
} RTL_IMAGE_MITIGATION_CHILD_PROCESS_POLICY, *PRTL_IMAGE_MITIGATION_CHILD_PROCESS_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_SEHOP_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY Sehop;
} RTL_IMAGE_MITIGATION_SEHOP_POLICY, *PRTL_IMAGE_MITIGATION_SEHOP_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_HEAP_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY TerminateOnHeapErrors;
} RTL_IMAGE_MITIGATION_HEAP_POLICY, *PRTL_IMAGE_MITIGATION_HEAP_POLICY;

// rev
typedef struct _RTL_IMAGE_MITIGATION_USER_SHADOW_STACK_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY UserShadowStack;
    RTL_IMAGE_MITIGATION_POLICY SetContextIpValidation;
    RTL_IMAGE_MITIGATION_POLICY BlockNonCetBinaries;
} RTL_IMAGE_MITIGATION_USER_SHADOW_STACK_POLICY, *PRTL_IMAGE_MITIGATION_USER_SHADOW_STACK_POLICY;

typedef enum _RTL_IMAGE_MITIGATION_OPTION_STATE
{
    RtlMitigationOptionStateNotConfigured,
    RtlMitigationOptionStateOn,
    RtlMitigationOptionStateOff,
    RtlMitigationOptionStateForce,
    RtlMitigationOptionStateOption
} RTL_IMAGE_MITIGATION_OPTION_STATE;

#define RTL_IMAGE_MITIGATION_OPTION_STATEMASK 3UL
#define RTL_IMAGE_MITIGATION_OPTION_FORCEMASK 4UL
#define RTL_IMAGE_MITIGATION_OPTION_OPTIONMASK 8UL

// rev from PROCESS_MITIGATION_FLAGS
#define RTL_IMAGE_MITIGATION_FLAG_RESET 0x1
#define RTL_IMAGE_MITIGATION_FLAG_REMOVE 0x2
#define RTL_IMAGE_MITIGATION_FLAG_OSDEFAULT 0x4
#define RTL_IMAGE_MITIGATION_FLAG_AUDIT 0x8

#if (PHNT_VERSION >= PHNT_REDSTONE3)

// rev
typedef
NTSTATUS(
NTAPI*
RTLQUERYIMAGEMITIGATIONPOLICY)(
    _In_opt_ PWSTR ImagePath, // NULL for system-wide defaults
    _In_ IMAGE_MITIGATION_POLICY Policy,
    _In_ ULONG Flags,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLSETIMAGEMITIGATIONPOLICY)(
    _In_opt_ PWSTR ImagePath, // NULL for system-wide defaults
    _In_ IMAGE_MITIGATION_POLICY Policy,
    _In_ ULONG Flags,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize
    );

#endif

// session 

// rev
typedef
ULONG(
NTAPI*
RTLGETCURRENTSERVICESESSIONID)(
    VOID
    );

// private
typedef
ULONG(
NTAPI*
RTLGETACTIVECONSOLEID)(
    VOID
    );

#if (PHNT_VERSION >= PHNT_REDSTONE)
// private
typedef
ULONGLONG(
NTAPI*
RTLGETCONSOLESESSIONFOREGROUNDPROCESSID)(
    VOID
    );
#endif

// Appcontainer

#if (PHNT_VERSION >= PHNT_REDSTONE2)
// rev
typedef
NTSTATUS(
NTAPI*
RTLGETTOKENNAMEDOBJECTPATH)(
    _In_ HANDLE Token, 
    _In_opt_ PSID Sid, 
    _Out_ PUNICODE_STRING ObjectPath // RtlFreeUnicodeString
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN8)
// rev
typedef
NTSTATUS(
NTAPI*
RTLGETAPPCONTAINERNAMEDOBJECTPATH)(
    _In_opt_ HANDLE Token,
    _In_opt_ PSID AppContainerSid,
    _In_ BOOLEAN RelativePath,
    _Out_ PUNICODE_STRING ObjectPath // RtlFreeUnicodeString
    );
#endif

#if (PHNT_VERSION >= PHNT_WINBLUE)
// rev
typedef
NTSTATUS(
NTAPI*
RTLGETAPPCONTAINERPARENT)(
    _In_ PSID AppContainerSid, 
    _Out_ PSID* AppContainerSidParent // RtlFreeSid
    );
#endif

#if (PHNT_VERSION >= PHNT_THRESHOLD)
// rev
typedef
NTSTATUS(
NTAPI*
RTLCHECKSANDBOXEDTOKEN)(
    _In_opt_ HANDLE TokenHandle,
    _Out_ PBOOLEAN IsSandboxed
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN8)
// rev
typedef
NTSTATUS(
NTAPI*
RTLCHECKTOKENCAPABILITY)(
    _In_opt_ HANDLE TokenHandle,
    _In_ PSID CapabilitySidToCheck,
    _Out_ PBOOLEAN HasCapability
    );
#endif

#if (PHNT_VERSION >= PHNT_THRESHOLD)
// rev
typedef
NTSTATUS(
NTAPI*
RTLCAPABILITYCHECK)(
    _In_opt_ HANDLE TokenHandle,
    _In_ PUNICODE_STRING CapabilityName,
    _Out_ PBOOLEAN HasCapability
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN8)
// rev
typedef
NTSTATUS(
NTAPI*
RTLCHECKTOKENMEMBERSHIP)(
    _In_opt_ HANDLE TokenHandle,
    _In_ PSID SidToCheck,
    _Out_ PBOOLEAN IsMember
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLCHECKTOKENMEMBERSHIPEX)(
    _In_opt_ HANDLE TokenHandle,
    _In_ PSID SidToCheck,
    _In_ ULONG Flags, // CTMF_VALID_FLAGS
    _Out_ PBOOLEAN IsMember
    );
#endif

#if (PHNT_VERSION >= PHNT_REDSTONE4)
// rev
typedef
NTSTATUS(
NTAPI*
RTLQUERYTOKENHOSTIDASULONG64)(
    _In_ HANDLE TokenHandle,
    _Out_ PULONG64 HostId // (WIN://PKGHOSTID)
    );
#endif

#if (PHNT_VERSION >= PHNT_WINBLUE)
// rev
typedef
BOOLEAN(
NTAPI*
RTLISPARENTOFCHILDAPPCONTAINER)(
    _In_ PSID ParentAppContainerSid,
    _In_ PSID ChildAppContainerSid
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN11)
// rev
typedef
NTSTATUS(
NTAPI*
RTLISAPISETIMPLEMENTED)(
    _In_ PCSTR Namespace
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN8)
// rev
typedef
BOOLEAN(
NTAPI*
RTLISCAPABILITYSID)(
    _In_ PSID Sid
    );

// rev
typedef
BOOLEAN(
NTAPI*
RTLISPACKAGESID)(
    _In_ PSID Sid
    );
#endif

#if (PHNT_VERSION >= PHNT_WINBLUE)
// rev
typedef
BOOLEAN(
NTAPI*
RTLISVALIDPROCESSTRUSTLABELSID)(
    _In_ PSID Sid
    );
#endif

#if (PHNT_VERSION >= PHNT_REDSTONE3)
typedef
BOOLEAN(
NTAPI*
RTLISSTATESEPARATIONENABLED)(
    VOID
    );
#endif

typedef enum _APPCONTAINER_SID_TYPE
{
    NotAppContainerSidType,
    ChildAppContainerSidType,
    ParentAppContainerSidType,
    InvalidAppContainerSidType,
    MaxAppContainerSidType
} APPCONTAINER_SID_TYPE, *PAPPCONTAINER_SID_TYPE;

#if (PHNT_VERSION >= PHNT_WINBLUE)
// rev
typedef
NTSTATUS(
NTAPI*
RTLGETAPPCONTAINERSIDTYPE)(
    _In_ PSID AppContainerSid,
    _Out_ PAPPCONTAINER_SID_TYPE AppContainerSidType
    );
#endif

typedef
NTSTATUS(
NTAPI*
RTLFLSALLOC)(
    _In_ PFLS_CALLBACK_FUNCTION Callback,
    _Out_ PULONG FlsIndex
    );

typedef
NTSTATUS(
NTAPI*
RTLFLSFREE)(
    _In_ ULONG FlsIndex
    );

typedef enum _STATE_LOCATION_TYPE 
{
    LocationTypeRegistry,
    LocationTypeFileSystem,
    LocationTypeMaximum
} STATE_LOCATION_TYPE;

#if (PHNT_VERSION >= PHNT_REDSTONE3)
// private
typedef
NTSTATUS(
NTAPI*
RTLGETPERSISTEDSTATELOCATION)(
    _In_ PCWSTR SourceID,
    _In_opt_ PCWSTR CustomValue,
    _In_opt_ PCWSTR DefaultPath,
    _In_ STATE_LOCATION_TYPE StateLocationType,
    _Out_writes_bytes_to_opt_(BufferLengthIn, *BufferLengthOut) PWCHAR TargetPath,
    _In_ ULONG BufferLengthIn,
    _Out_opt_ PULONG BufferLengthOut
    );

// msdn
typedef
BOOLEAN(
NTAPI*
RTLISCLOUDFILESPLACEHOLDER)(
    _In_ ULONG FileAttributes,
    _In_ ULONG ReparseTag
    );

// msdn
typedef
BOOLEAN(
NTAPI*
RTLISPARTIALPLACEHOLDER)(
    _In_ ULONG FileAttributes,
    _In_ ULONG ReparseTag
    );

// msdn
typedef
NTSTATUS(
NTAPI*
RTLISPARTIALPLACEHOLDERFILEHANDLE)(
    _In_ HANDLE FileHandle,
    _Out_ PBOOLEAN IsPartialPlaceholder
    );

// msdn
typedef
NTSTATUS(
NTAPI*
RTLISPARTIALPLACEHOLDERFILEINFO)(
    _In_ PVOID InfoBuffer,
    _In_ FILE_INFORMATION_CLASS InfoClass,
    _Out_ PBOOLEAN IsPartialPlaceholder
    );

#undef PHCM_MAX
#define PHCM_APPLICATION_DEFAULT ((CHAR)0)
#define PHCM_DISGUISE_PLACEHOLDERS ((CHAR)1)
#define PHCM_EXPOSE_PLACEHOLDERS ((CHAR)2)
#define PHCM_MAX ((CHAR)2)

#define PHCM_ERROR_INVALID_PARAMETER ((CHAR)-1)
#define PHCM_ERROR_NO_TEB ((CHAR)-2)

typedef
CHAR(
NTAPI*
RTLQUERYTHREADPLACEHOLDERCOMPATIBILITYMODE)(
    VOID
    );

typedef
CHAR(
NTAPI*
RTLSETTHREADPLACEHOLDERCOMPATIBILITYMODE)(
    _In_ CHAR Mode
    );

#endif

#if (PHNT_VERSION >= PHNT_REDSTONE4)

#undef PHCM_MAX
#define PHCM_DISGUISE_FULL_PLACEHOLDERS ((CHAR)3)
#define PHCM_MAX ((CHAR)3)
#define PHCM_ERROR_NO_PEB ((CHAR)-3)

typedef
CHAR(
NTAPI*
RTLQUERYPROCESSPLACEHOLDERCOMPATIBILITYMODE)(
    VOID
    );

typedef
CHAR(
NTAPI*
RTLSETPROCESSPLACEHOLDERCOMPATIBILITYMODE)(
    _In_ CHAR Mode
    );

#endif

#if (PHNT_VERSION >= PHNT_REDSTONE2)
// rev
typedef
BOOLEAN(
NTAPI*
RTLISNONEMPTYDIRECTORYREPARSEPOINTALLOWED)(
    _In_ ULONG ReparseTag
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN8)
// rev
typedef
NTSTATUS(
NTAPI*
RTLAPPXISFILEOWNEDBYTRUSTEDINSTALLER)(
    _In_ HANDLE FileHandle, 
    _Out_ PBOOLEAN IsFileOwnedByTrustedInstaller
    );
#endif

// Windows Internals book
#define PSM_ACTIVATION_TOKEN_PACKAGED_APPLICATION 0x1
#define PSM_ACTIVATION_TOKEN_SHARED_ENTITY 0x2
#define PSM_ACTIVATION_TOKEN_FULL_TRUST 0x4
#define PSM_ACTIVATION_TOKEN_NATIVE_SERVICE 0x8
#define PSM_ACTIVATION_TOKEN_DEVELOPMENT_APP 0x10
#define BREAKAWAY_INHIBITED 0x20

// private
typedef struct _PS_PKG_CLAIM
{
    ULONG Flags;  // PSM_ACTIVATION_TOKEN_*
    ULONG Origin; // PackageOrigin from appmodel.h
} PS_PKG_CLAIM, *PPS_PKG_CLAIM;

#if (PHNT_VERSION >= PHNT_THRESHOLD)
typedef
NTSTATUS(
NTAPI*
RTLQUERYPACKAGECLAIMS)(
    _In_ HANDLE TokenHandle,
    _Out_writes_bytes_to_opt_(*PackageSize, *PackageSize) PWSTR PackageFullName,
    _Inout_opt_ PSIZE_T PackageSize,
    _Out_writes_bytes_to_opt_(*AppIdSize, *AppIdSize) PWSTR AppId,
    _Inout_opt_ PSIZE_T AppIdSize,
    _Out_opt_ PGUID DynamicId,
    _Out_opt_ PPS_PKG_CLAIM PkgClaim,
    _Out_opt_ PULONG64 AttributesPresent
    );
#endif

// Protected policies

#if (PHNT_VERSION >= PHNT_WINBLUE)
// rev
typedef
NTSTATUS(
NTAPI*
RTLQUERYPROTECTEDPOLICY)(
    _In_ PGUID PolicyGuid,
    _Out_ PULONG_PTR PolicyValue
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLSETPROTECTEDPOLICY)(
    _In_ PGUID PolicyGuid,
    _In_ ULONG_PTR PolicyValue,
    _Out_ PULONG_PTR OldPolicyValue
    );
#endif

#if (PHNT_VERSION >= PHNT_THRESHOLD)
// private
typedef
BOOLEAN(
NTAPI*
RTLISMULTISESSIONSKU)(
    VOID
    );
#endif

#if (PHNT_VERSION >= PHNT_REDSTONE)
// private
typedef
BOOLEAN(
NTAPI*
RTLISMULTIUSERSINSESSIONSKU)(
    VOID
    );
#endif

// private
typedef enum _RTL_BSD_ITEM_TYPE
{
    RtlBsdItemVersionNumber, // q; s: ULONG
    RtlBsdItemProductType, // q; s: NT_PRODUCT_TYPE (ULONG)
    RtlBsdItemAabEnabled, // q: s: BOOLEAN // AutoAdvancedBoot
    RtlBsdItemAabTimeout, // q: s: UCHAR // AdvancedBootMenuTimeout
    RtlBsdItemBootGood, // q: s: BOOLEAN // LastBootSucceeded
    RtlBsdItemBootShutdown, // q: s: BOOLEAN // LastBootShutdown
    RtlBsdSleepInProgress, // q: s: BOOLEAN // SleepInProgress
    RtlBsdPowerTransition, // q: s: RTL_BSD_DATA_POWER_TRANSITION
    RtlBsdItemBootAttemptCount, // q: s: UCHAR // BootAttemptCount
    RtlBsdItemBootCheckpoint, // q: s: UCHAR // LastBootCheckpoint
    RtlBsdItemBootId, // q; s: ULONG (USER_SHARED_DATA->BootId)
    RtlBsdItemShutdownBootId, // q; s: ULONG
    RtlBsdItemReportedAbnormalShutdownBootId, // q; s: ULONG
    RtlBsdItemErrorInfo, // RTL_BSD_DATA_ERROR_INFO
    RtlBsdItemPowerButtonPressInfo, // RTL_BSD_POWER_BUTTON_PRESS_INFO
    RtlBsdItemChecksum, // q: s: UCHAR
    RtlBsdPowerTransitionExtension,
    RtlBsdItemFeatureConfigurationState, // q; s: ULONG
    RtlBsdItemMax
} RTL_BSD_ITEM_TYPE;

// ros
typedef struct _RTL_BSD_DATA_POWER_TRANSITION
{
    LARGE_INTEGER PowerButtonTimestamp;
    struct
    {
        BOOLEAN SystemRunning : 1;
        BOOLEAN ConnectedStandbyInProgress : 1;
        BOOLEAN UserShutdownInProgress : 1;
        BOOLEAN SystemShutdownInProgress : 1;
        BOOLEAN SleepInProgress : 4;
    } Flags;
    UCHAR ConnectedStandbyScenarioInstanceId;
    UCHAR ConnectedStandbyEntryReason;
    UCHAR ConnectedStandbyExitReason;
    USHORT SystemSleepTransitionCount;
    LARGE_INTEGER LastReferenceTime;
    ULONG LastReferenceTimeChecksum;
    ULONG LastUpdateBootId;
} RTL_BSD_DATA_POWER_TRANSITION, *PRTL_BSD_DATA_POWER_TRANSITION;

// ros
typedef struct _RTL_BSD_DATA_ERROR_INFO
{
    ULONG BootId;
    ULONG RepeatCount;
    ULONG OtherErrorCount;
    ULONG Code;
    ULONG OtherErrorCount2;
} RTL_BSD_DATA_ERROR_INFO, *PRTL_BSD_DATA_ERROR_INFO;

// ros
typedef struct _RTL_BSD_POWER_BUTTON_PRESS_INFO
{
    LARGE_INTEGER LastPressTime;
    ULONG CumulativePressCount;
    USHORT LastPressBootId;
    UCHAR LastPowerWatchdogStage;
    struct
    {
        UCHAR WatchdogArmed : 1;
        UCHAR ShutdownInProgress : 1;
    } Flags;
    LARGE_INTEGER LastReleaseTime;
    ULONG CumulativeReleaseCount;
    USHORT LastReleaseBootId;
    USHORT ErrorCount;
    UCHAR CurrentConnectedStandbyPhase;
    ULONG TransitionLatestCheckpointId;
    ULONG TransitionLatestCheckpointType;
    ULONG TransitionLatestCheckpointSequenceNumber;
} RTL_BSD_POWER_BUTTON_PRESS_INFO, *PRTL_BSD_POWER_BUTTON_PRESS_INFO;

// private
typedef struct _RTL_BSD_ITEM
{
    RTL_BSD_ITEM_TYPE Type;
    PVOID DataBuffer;
    ULONG DataLength;
} RTL_BSD_ITEM, *PRTL_BSD_ITEM;

// ros
typedef
NTSTATUS(
NTAPI*
RTLCREATEBOOTSTATUSDATAFILE)(
    VOID
    );

// ros
typedef
NTSTATUS(
NTAPI*
RTLLOCKBOOTSTATUSDATA)(
    _Out_ PHANDLE FileHandle
    );

// ros
typedef
NTSTATUS(
NTAPI*
RTLUNLOCKBOOTSTATUSDATA)(
    _In_ HANDLE FileHandle
    );

// ros
typedef
NTSTATUS(
NTAPI*
RTLGETSETBOOTSTATUSDATA)(
    _In_ HANDLE FileHandle,
    _In_ BOOLEAN Read,
    _In_ RTL_BSD_ITEM_TYPE DataClass,
    _In_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG ReturnLength
    );

#if (PHNT_VERSION >= PHNT_REDSTONE)
// rev
typedef
NTSTATUS(
NTAPI*
RTLCHECKBOOTSTATUSINTEGRITY)(
    _In_ HANDLE FileHandle, 
    _Out_ PBOOLEAN Verified
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLRESTOREBOOTSTATUSDEFAULTS)(
    _In_ HANDLE FileHandle
    );
#endif

#if (PHNT_VERSION >= PHNT_REDSTONE3)
// rev
typedef
NTSTATUS(
NTAPI*
RTLRESTORESYSTEMBOOTSTATUSDEFAULTS)(
    VOID
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLGETSYSTEMBOOTSTATUS)(
    _In_ RTL_BSD_ITEM_TYPE BootStatusInformationClass,
    _Out_ PVOID DataBuffer,
    _In_ ULONG DataLength,
    _Out_opt_ PULONG ReturnLength
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLSETSYSTEMBOOTSTATUS)(
    _In_ RTL_BSD_ITEM_TYPE BootStatusInformationClass,
    _In_ PVOID DataBuffer,
    _In_ ULONG DataLength,
    _Out_opt_ PULONG ReturnLength
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN8)
// rev
typedef
NTSTATUS(
NTAPI*
RTLCHECKPORTABLEOPERATINGSYSTEM)(
    _Out_ PBOOLEAN IsPortable // VOID
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLSETPORTABLEOPERATINGSYSTEM)(
    _In_ BOOLEAN IsPortable
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)

typedef
NTSTATUS(
NTAPI*
RTLFINDCLOSESTENCODABLELENGTH)(
    _In_ ULONGLONG SourceLength,
    _Out_ PULONGLONG TargetLength
    );

#endif

// Memory cache

typedef NTSTATUS (NTAPI *PRTL_SECURE_MEMORY_CACHE_CALLBACK)(
    _In_ PVOID Address,
    _In_ SIZE_T Length
    );

// ros
typedef
NTSTATUS(
NTAPI*
RTLREGISTERSECUREMEMORYCACHECALLBACK)(
    _In_ PRTL_SECURE_MEMORY_CACHE_CALLBACK Callback
    );

typedef
NTSTATUS(
NTAPI*
RTLDEREGISTERSECUREMEMORYCACHECALLBACK)(
    _In_ PRTL_SECURE_MEMORY_CACHE_CALLBACK Callback
    );

// ros
typedef
BOOLEAN(
NTAPI*
RTLFLUSHSECUREMEMORYCACHE)(
    _In_ PVOID MemoryCache,
    _In_opt_ SIZE_T MemoryLength
    );

#if (PHNT_VERSION >= PHNT_20H1)

// Feature configuration

typedef struct __RTL_FEATURE_USAGE_REPORT
{
    ULONG FeatureId;
    USHORT ReportingKind;
    USHORT ReportingOptions;
} RTL_FEATURE_USAGE_REPORT, *PRTL_FEATURE_USAGE_REPORT;

// rev
typedef
NTSTATUS(
NTAPI*
RTLNOTIFYFEATUREUSAGE)(
    _In_ PRTL_FEATURE_USAGE_REPORT FeatureUsageReport
    );

typedef enum _RTL_FEATURE_CONFIGURATION_TYPE
{
    RtlFeatureConfigurationBoot,
    RtlFeatureConfigurationRuntime,
    RtlFeatureConfigurationCount
} RTL_FEATURE_CONFIGURATION_TYPE;

// rev
typedef struct _RTL_FEATURE_CONFIGURATION
{
    ULONG FeatureId;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG Priority : 4;
            ULONG EnabledState : 2;
            ULONG IsWexpConfiguration : 1;
            ULONG HasSubscriptions : 1;
            ULONG Variant : 6;
            ULONG VariantPayloadKind : 2;
            ULONG Reserved : 16;
        };
    };
    ULONG VariantPayload;
} RTL_FEATURE_CONFIGURATION, *PRTL_FEATURE_CONFIGURATION;

// rev
typedef
NTSTATUS(
NTAPI*
RTLQUERYFEATURECONFIGURATION)(
    _In_ ULONG FeatureId,
    _In_ RTL_FEATURE_CONFIGURATION_TYPE FeatureType,
    _Inout_ PULONGLONG ChangeStamp,
    _In_ PRTL_FEATURE_CONFIGURATION FeatureConfiguration
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLSETFEATURECONFIGURATIONS)(
    _Inout_ PULONGLONG ChangeStamp,
    _In_ RTL_FEATURE_CONFIGURATION_TYPE FeatureType,
    _In_ PRTL_FEATURE_CONFIGURATION FeatureConfiguration,
    _In_ ULONG FeatureConfigurationCount
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLQUERYALLFEATURECONFIGURATIONS)(
    _In_ RTL_FEATURE_CONFIGURATION_TYPE FeatureType,
    _Inout_ PULONGLONG ChangeStamp,
    _Out_ PRTL_FEATURE_CONFIGURATION FeatureConfigurations,
    _Inout_ PULONG FeatureConfigurationCount
    );

// rev
typedef
ULONGLONG(
NTAPI*
RTLQUERYFEATURECONFIGURATIONCHANGESTAMP)(
    VOID
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLQUERYFEATUREUSAGENOTIFICATIONSUBSCRIPTIONS)(
    _Out_ PRTL_FEATURE_CONFIGURATION FeatureConfiguration,
    _Inout_ PULONG FeatureConfigurationCount
    );

typedef VOID (NTAPI *PRTL_FEATURE_CONFIGURATION_CHANGE_NOTIFICATION)(
    _In_opt_ PVOID Context
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLREGISTERFEATURECONFIGURATIONCHANGENOTIFICATION)(
    _In_ PRTL_FEATURE_CONFIGURATION_CHANGE_NOTIFICATION Callback,
    _In_opt_ PVOID Context,
    _Inout_opt_ PULONGLONG ChangeStamp,
    _Out_ PHANDLE NotificationHandle
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLUNREGISTERFEATURECONFIGURATIONCHANGENOTIFICATION)(
    _In_ HANDLE NotificationHandle
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLSUBSCRIBEFORFEATUREUSAGENOTIFICATION)(
    _In_ PRTL_FEATURE_CONFIGURATION FeatureConfiguration,
    _In_ ULONG FeatureConfigurationCount
    );

// rev
typedef
NTSTATUS(
NTAPI*
RTLUNSUBSCRIBEFROMFEATUREUSAGENOTIFICATIONS)(
    _In_ PRTL_FEATURE_CONFIGURATION FeatureConfiguration,
    _In_ ULONG FeatureConfigurationCount
    );
#endif

#endif