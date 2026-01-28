/*
 * ntdefs.h - Structures NT non documentées
 *
 * Définitions des structures internes Windows nécessaires pour
 * le PEB walking et les syscalls indirects.
 */

#ifndef NTDEFS_H
#define NTDEFS_H

#include <windows.h>

/* NT base types */

typedef LONG NTSTATUS;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define STATUS_SUCCESS_NT ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

/* UNICODE_STRING (used throughout the kernel) */
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

/* PEB structures (needed for PEB walking and API resolution) */

typedef struct _PEB_LDR_DATA {
  ULONG Length;
  BOOLEAN Initialized;
  HANDLE SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID EntryInProgress;
  BOOLEAN ShutdownInProgress;
  HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  USHORT LoadCount;
  USHORT TlsIndex;
  union {
    LIST_ENTRY HashLinks;
    struct {
      PVOID SectionPointer;
      ULONG CheckSum;
    };
  };
  union {
    ULONG TimeDateStamp;
    PVOID LoadedImports;
  };
  PVOID EntryPointActivationContext;
  PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE Reserved1[16];
  PVOID Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  union {
    BOOLEAN BitField;
    struct {
      BOOLEAN ImageUsesLargePages : 1;
      BOOLEAN IsProtectedProcess : 1;
      BOOLEAN IsImageDynamicallyRelocated : 1;
      BOOLEAN SkipPatchingUser32Forwarders : 1;
      BOOLEAN IsPackagedProcess : 1;
      BOOLEAN IsAppContainer : 1;
      BOOLEAN IsProtectedProcessLight : 1;
      BOOLEAN IsLongPathAwareProcess : 1;
    };
  };
  HANDLE Mutant;
  PVOID ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID SubSystemData;
  PVOID ProcessHeap;
  PRTL_CRITICAL_SECTION FastPebLock;
  PVOID AtlThunkSListPtr;
  PVOID IFEOKey;
  union {
    ULONG CrossProcessFlags;
    struct {
      ULONG ProcessInJob : 1;
      ULONG ProcessInitializing : 1;
      ULONG ProcessUsingVEH : 1;
      ULONG ProcessUsingVCH : 1;
      ULONG ProcessUsingFTH : 1;
      ULONG ProcessPreviouslyThrottled : 1;
      ULONG ProcessCurrentlyThrottled : 1;
      ULONG ReservedBits0 : 25;
    };
  };
  union {
    PVOID KernelCallbackTable;
    PVOID UserSharedInfoPtr;
  };
  ULONG SystemReserved[1];
  ULONG AtlThunkSListPtr32;
  PVOID ApiSetMap;
  /* ... y'a d'autres champs mais on s'en fout pour l'instant */
} PEB, *PPEB;

/* CLIENT_ID */
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/* TEB (Thread Environment Block) */
typedef struct _TEB {
  NT_TIB NtTib;
  PVOID EnvironmentPointer;
  CLIENT_ID ClientId;
  PVOID ActiveRpcHandle;
  PVOID ThreadLocalStoragePointer;
  PPEB ProcessEnvironmentBlock;
  /* ... on s'arrête là, c'est ce qu'on a besoin */
} TEB, *PTEB;

/* OBJECT_ATTRIBUTES (for NT syscalls) */
typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s)                              \
  {                                                                            \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);                                   \
    (p)->RootDirectory = r;                                                    \
    (p)->Attributes = a;                                                       \
    (p)->ObjectName = n;                                                       \
    (p)->SecurityDescriptor = s;                                               \
    (p)->SecurityQualityOfService = NULL;                                      \
  }

/* IO_STATUS_BLOCK (I/O operation return status) */
typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/* PROCESS_BASIC_INFORMATION (for NtQueryInformationProcess) */
typedef struct _PROCESS_BASIC_INFORMATION {
  NTSTATUS ExitStatus;
  PPEB PebBaseAddress;
  ULONG_PTR AffinityMask;
  LONG BasePriority;
  ULONG_PTR UniqueProcessId;
  ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
  ProcessBasicInformation = 0,
  ProcessDebugPort = 7,
  ProcessWow64Information = 26,
  ProcessImageFileName = 27,
  ProcessBreakOnTermination = 29,
  ProcessDebugObjectHandle = 30,
  ProcessDebugFlags = 31,
} PROCESSINFOCLASS;

/* PEB/TEB access macros */

/* Récupère le TEB du thread courant via le registre GS (x64) */
#if defined(_M_X64) || defined(__x86_64__)
#define NtCurrentTeb() ((PTEB)__readgsqword(0x30))
#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)
#else
#define NtCurrentTeb() ((PTEB)__readfsdword(0x18))
#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)
#endif

/* NT function typedefs (for dynamic resolution) */

typedef NTSTATUS(NTAPI *fn_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

typedef NTSTATUS(NTAPI *fn_NtFreeVirtualMemory)(HANDLE ProcessHandle,
                                                PVOID *BaseAddress,
                                                PSIZE_T RegionSize,
                                                ULONG FreeType);

typedef NTSTATUS(NTAPI *fn_NtProtectVirtualMemory)(HANDLE ProcessHandle,
                                                   PVOID *BaseAddress,
                                                   PSIZE_T RegionSize,
                                                   ULONG NewProtect,
                                                   PULONG OldProtect);

typedef NTSTATUS(NTAPI *fn_NtQueryInformationProcess)(
    HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS(NTAPI *fn_NtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

typedef NTSTATUS(NTAPI *fn_NtDelayExecution)(BOOLEAN Alertable,
                                             PLARGE_INTEGER DelayInterval);

typedef NTSTATUS(NTAPI *fn_NtClose)(HANDLE Handle);

typedef NTSTATUS(NTAPI *fn_NtWriteVirtualMemory)(HANDLE ProcessHandle,
                                                 PVOID BaseAddress,
                                                 PVOID Buffer,
                                                 SIZE_T NumberOfBytesToWrite,
                                                 PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS(NTAPI *fn_NtReadVirtualMemory)(HANDLE ProcessHandle,
                                                PVOID BaseAddress, PVOID Buffer,
                                                SIZE_T NumberOfBytesToRead,
                                                PSIZE_T NumberOfBytesRead);

typedef NTSTATUS(NTAPI *fn_NtOpenProcess)(PHANDLE ProcessHandle,
                                          ACCESS_MASK DesiredAccess,
                                          POBJECT_ATTRIBUTES ObjectAttributes,
                                          PCLIENT_ID ClientId);

typedef NTSTATUS(NTAPI *fn_NtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits,
    SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);

#endif /* NTDEFS_H */
