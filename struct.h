#pragma once

#include <fltkernel.h>

typedef unsigned char BYTE;
typedef unsigned int UINT;
typedef int BOOL;

// TODO This is rather ugly, but does the job for now.
#define DWORD UINT

#pragma warning( push )
#pragma warning( disable : 4200 )	// warning C4200: nonstandard extension used : zero-sized array in struct/union
#pragma warning( disable : 4201 )	// warning C4201: nonstandard extension used : nameless struct/union

typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS, *PSECTION_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE {
	PVOID reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG ModulesCount;
	SYSTEM_MODULE Modules[];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSDBG_COMMAND {
	SysDbgQueryModuleInformation = 1,
	SysDbgQueryTraceInformation,
	SysDbgSetTracepoint,
	SysDbgSetSpecialCall,
	SysDbgClearSpecialCalls,
	SysDbgQuerySpecialCalls
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	UCHAR          Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PS_ATTRIBUTE {
	ULONG_PTR Attribute;
	SIZE_T Size;
	union {
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef struct _INITIAL_TEB {
	PVOID StackBase;
	PVOID StackLimit;
	PVOID StackCommit;
	PVOID StackCommitMax;
	PVOID StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	ULONG PrivatePageCount;
	VM_COUNTERS VirtualMemoryCounters;
	IO_COUNTERS IoCounters;
	PVOID Threads[0];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemWhatTheFuckInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID     EntryPoint;
	ULONG     unknown[14];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS  ExitStatus;
	PVOID     TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG     AffinityMask;
	ULONG     Priority;
	ULONG     BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	LONG  *Base;
	ULONG *ServiceCounterTableBase;
	ULONG NumberOfServices;
	UCHAR *ParamTableBase;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

typedef struct _MEMORY_BASIC_INFORMATION {
	PVOID  BaseAddress;
	PVOID  AllocationBase;
	ULONG  AllocationProtect;
	SIZE_T RegionSize;
	ULONG  State;
	ULONG  Protect;
	ULONG  Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

NTSYSAPI NTSTATUS NTAPI ZwQuerySection(
	HANDLE SectionHandle, SECTION_INFORMATION_CLASS InformationClass,
	PVOID InformationBuffer, SIZE_T InformationBufferSize,
	PSIZE_T ResultLength
);

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
	SIZE_T SystemInformationLength, PSIZE_T ReturnLength
);

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
	HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation, ULONG ProcessInformationLength,
	PULONG ReturnLength
);

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationThread(
	HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation, SIZE_T ThreadInformationLength,
	PSIZE_T ReturnLength
);

NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(
	HANDLE ProcessHandle, PVOID BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation,
	SIZE_T MemoryInformationLength, PSIZE_T ReturnLength
);

typedef struct tagGETCLIPBDATA {
	UINT uFmtRet;
	BOOL fGlobalHandle;
	union {
		HANDLE hLocale;
		HANDLE hPalette;
	};
} GETCLIPBDATA, *PGETCLIPBDATA;

typedef struct tagSETCLIPBDATA {
	BOOL fGlobalHandle;
	BOOL fIncSerialNumber;
} SETCLIPBDATA, *PSETCLIPBDATA;

#include "pshpack4.h"

#define WOW64_SIZE_OF_80387_REGISTERS      80
#define WOW64_MAXIMUM_SUPPORTED_EXTENSION  512

typedef struct _WOW64_FLOATING_SAVE_AREA {
	DWORD   ControlWord;
	DWORD   StatusWord;
	DWORD   TagWord;
	DWORD   ErrorOffset;
	DWORD   ErrorSelector;
	DWORD   DataOffset;
	DWORD   DataSelector;
	BYTE    RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
	DWORD   Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA;

typedef struct _WOW64_CONTEXT {
	DWORD ContextFlags;
	DWORD   Dr0;
	DWORD   Dr1;
	DWORD   Dr2;
	DWORD   Dr3;
	DWORD   Dr6;
	DWORD   Dr7;
	WOW64_FLOATING_SAVE_AREA FloatSave;
	DWORD   SegGs;
	DWORD   SegFs;
	DWORD   SegEs;
	DWORD   SegDs;
	DWORD   Edi;
	DWORD   Esi;
	DWORD   Ebx;
	DWORD   Edx;
	DWORD   Ecx;
	DWORD   Eax;
	DWORD   Ebp;
	DWORD   Eip;
	DWORD   SegCs;              // MUST BE SANITIZED
	DWORD   EFlags;             // MUST BE SANITIZED
	DWORD   Esp;
	DWORD   SegSs;
	BYTE    ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];
} WOW64_CONTEXT;

typedef WOW64_CONTEXT *PWOW64_CONTEXT;

#include "poppack.h"

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_MODULE {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID BaseAddress;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN Spare;
	HANDLE  Mutant;
	PVOID   ImageBaseAddress;
	PPEB_LDR_DATA LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID   SubSystemData;
	PVOID   ProcessHeap;
	PVOID   FastPebLock;
	void   *FastPebLockRoutine;
	void   *FastPebUnlockRoutine;
	ULONG   EnvironmentUpdateCount;
	PVOID   KernelCallbackTable;
	PVOID   EventLogSection;
	PVOID   EventLog;
	void   *FreeList;
	ULONG   TlsExpansionCounter;
	PVOID   TlsBitmap;
	ULONG   TlsBitmapBits[0x2];
	PVOID   ReadOnlySharedMemoryBase;
	PVOID   ReadOnlySharedMemoryHeap;
	PVOID   ReadOnlyStaticServerData;
	PVOID   AnsiCodePageData;
	PVOID   OemCodePageData;
	PVOID   UnicodeCaseTableData;
	ULONG   NumberOfProcessors;
	ULONG   NtGlobalFlag;
	BYTE    Spare2[0x4];
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG   HeapSegmentReserve;
	ULONG   HeapSegmentCommit;
	ULONG   HeapDeCommitTotalFreeThreshold;
	ULONG   HeapDeCommitFreeBlockThreshold;
	ULONG   NumberOfHeaps;
	ULONG   MaximumNumberOfHeaps;
	PVOID  *ProcessHeaps;
	PVOID   GdiSharedHandleTable;
	PVOID   ProcessStarterHelper;
	PVOID   GdiDCAttributeList;
	PVOID   LoaderLock;
	ULONG   OSMajorVersion;
	ULONG   OSMinorVersion;
	ULONG   OSBuildNumber;
	ULONG   OSPlatformId;
	ULONG   ImageSubSystem;
	ULONG   ImageSubSystemMajorVersion;
	ULONG   ImageSubSystemMinorVersion;
	ULONG   GdiHandleBuffer[0x22];
	ULONG   PostProcessInitRoutine;
	ULONG   TlsExpansionBitmap;
	BYTE    TlsExpansionBitmapBits[0x80];
	ULONG   SessionId;
} PEB, *PPEB;

extern PDEVICE_OBJECT g_device_object;

#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004

#define PROC_THREAD_ATTRIBUTE_NUMBER    0x0000FFFF
#define PROC_THREAD_ATTRIBUTE_THREAD    0x00010000  // Attribute may be used with thread creation
#define PROC_THREAD_ATTRIBUTE_INPUT     0x00020000  // Attribute is input only
#define PROC_THREAD_ATTRIBUTE_ADDITIVE  0x00040000  // Attribute may be "accumulated," e.g. bitmasks, counters, etc.

typedef enum _PROC_THREAD_ATTRIBUTE_NUM {
	ProcThreadAttributeParentProcess = 0,
	ProcThreadAttributeExtendedFlags,
	ProcThreadAttributeHandleList,
	ProcThreadAttributeGroupAffinity,
	ProcThreadAttributePreferredNode,
	ProcThreadAttributeIdealProcessor,
	ProcThreadAttributeUmsThread,
	ProcThreadAttributeMitigationPolicy,
	ProcThreadAttributeMax
} PROC_THREAD_ATTRIBUTE_NUM;

#define ProcThreadAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PROC_THREAD_ATTRIBUTE_NUMBER) | \
     ((Thread != FALSE) ? PROC_THREAD_ATTRIBUTE_THREAD : 0) | \
     ((Input != FALSE) ? PROC_THREAD_ATTRIBUTE_INPUT : 0) | \
     ((Additive != FALSE) ? PROC_THREAD_ATTRIBUTE_ADDITIVE : 0))

#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS \
    ProcThreadAttributeValue (ProcThreadAttributeParentProcess, FALSE, TRUE, FALSE)
#define PROC_THREAD_ATTRIBUTE_EXTENDED_FLAGS \
    ProcThreadAttributeValue (ProcThreadAttributeExtendedFlags, FALSE, TRUE, TRUE)
#define PROC_THREAD_ATTRIBUTE_HANDLE_LIST \
    ProcThreadAttributeValue (ProcThreadAttributeHandleList, FALSE, TRUE, FALSE)
#define PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY \
    ProcThreadAttributeValue (ProcThreadAttributeGroupAffinity, TRUE, TRUE, FALSE)
#define PROC_THREAD_ATTRIBUTE_PREFERRED_NODE \
    ProcThreadAttributeValue (ProcThreadAttributePreferredNode, FALSE, TRUE, FALSE)
#define PROC_THREAD_ATTRIBUTE_IDEAL_PROCESSOR \
    ProcThreadAttributeValue (ProcThreadAttributeIdealProcessor, TRUE, TRUE, FALSE)
#define PROC_THREAD_ATTRIBUTE_UMS_THREAD \
    ProcThreadAttributeValue (ProcThreadAttributeUmsThread, TRUE, TRUE, FALSE)
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY \
    ProcThreadAttributeValue (ProcThreadAttributeMitigationPolicy, FALSE, TRUE, FALSE)

typedef HANDLE ALPC_HANDLE, *PALPC_HANDLE;

typedef struct _PORT_MESSAGE {
	union {
		struct {
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union {
		struct {
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union {
		CLIENT_ID ClientId;
		QUAD DoNotUseThisField;
	};
	ULONG MessageId;
	union {
		SIZE_T ClientViewSize;
		ULONG CallbackId;
	} u3;
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES {
	ULONG AllocatedAttributes;
	ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ATTRIBUTES {
	ULONG Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	SIZE_T MaxMessageLength;
	SIZE_T MemoryBandwidth;
	SIZE_T MaxPoolUsage;
	SIZE_T MaxSectionSize;
	SIZE_T MaxViewSize;
	SIZE_T MaxTotalSectionSize;
	ULONG DupObjectTypes;
#ifdef _WIN64
	ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

typedef enum _ALPC_MESSAGE_INFORMATION_CLASS {
	AlpcMessageSidInformation, // q: out SID
	AlpcMessageTokenModifiedIdInformation,  // q: out LUID
	AlpcMessageDirectStatusInformation,
	AlpcMessageHandleInformation, // ALPC_MESSAGE_HANDLE_INFORMATION
	MaxAlpcMessageInfoClass
} ALPC_MESSAGE_INFORMATION_CLASS, *PALPC_MESSAGE_INFORMATION_CLASS;

typedef enum _ALPC_PORT_INFORMATION_CLASS {
	AlpcBasicInformation, // q: out ALPC_BASIC_INFORMATION
	AlpcPortInformation, // s: in ALPC_PORT_ATTRIBUTES
	AlpcAssociateCompletionPortInformation, // s: in ALPC_PORT_ASSOCIATE_COMPLETION_PORT
	AlpcConnectedSIDInformation, // q: in SID
	AlpcServerInformation, // q: inout ALPC_SERVER_INFORMATION
	AlpcMessageZoneInformation, // s: in ALPC_PORT_MESSAGE_ZONE_INFORMATION
	AlpcRegisterCompletionListInformation, // s: in ALPC_PORT_COMPLETION_LIST_INFORMATION
	AlpcUnregisterCompletionListInformation, // s: VOID
	AlpcAdjustCompletionListConcurrencyCountInformation, // s: in ULONG
	AlpcRegisterCallbackInformation, // kernel-mode only
	AlpcCompletionListRundownInformation, // s: VOID
	AlpcWaitForPortReferences
} ALPC_PORT_INFORMATION_CLASS;

typedef struct _LPC_MESSAGE {
	USHORT                  DataLength;
	USHORT                  Length;
	USHORT                  MessageType;
	USHORT                  DataInfoOffset;
	CLIENT_ID               ClientId;
	ULONG                   MessageId;
	ULONG                   CallbackId;
} LPC_MESSAGE, *PLPC_MESSAGE;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	DWORD Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	DWORD CheckSum;
	DWORD TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#pragma warning( pop )