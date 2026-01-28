/*
 * syscalls.h - Indirect Syscalls pour bypass EDR
 *
 * Les EDRs hookent les fonctions NTDLL pour monitorer les appels.
 * En faisant des syscalls directs, on bypass ces hooks.
 */

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "../../include/common.h"
#include "../../include/ntdefs.h"

/*
 * Initialise le module de syscalls.
 * Parse ntdll pour trouver les numéros de syscall.
 */
int syscalls_init(void);

/*
 * Cleanup du module.
 */
void syscalls_cleanup(void);

/* Syscall wrappers - direct system calls bypassing ntdll */

/*
 * NtAllocateVirtualMemory - Alloue de la mémoire
 */
NTSTATUS sys_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                     ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                     ULONG AllocationType, ULONG Protect);

/*
 * NtFreeVirtualMemory - Libère de la mémoire
 */
NTSTATUS sys_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                 PSIZE_T RegionSize, ULONG FreeType);

/*
 * NtProtectVirtualMemory - Change les protections mémoire
 */
NTSTATUS sys_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                    PSIZE_T RegionSize, ULONG NewProtect,
                                    PULONG OldProtect);

/*
 * NtQueryInformationProcess - Info sur un process
 */
NTSTATUS sys_NtQueryInformationProcess(HANDLE ProcessHandle,
                                       PROCESSINFOCLASS ProcessInformationClass,
                                       PVOID ProcessInformation,
                                       ULONG ProcessInformationLength,
                                       PULONG ReturnLength);

/*
 * NtDelayExecution - Sleep
 */
NTSTATUS sys_NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

/*
 * NtClose - Ferme un handle
 */
NTSTATUS sys_NtClose(HANDLE Handle);

/*
 * NtWriteVirtualMemory - Écrit dans la mémoire d'un process
 */
NTSTATUS sys_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                  PVOID Buffer, SIZE_T NumberOfBytesToWrite,
                                  PSIZE_T NumberOfBytesWritten);

/*
 * NtReadVirtualMemory - Lit la mémoire d'un process
 */
NTSTATUS sys_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                 PVOID Buffer, SIZE_T NumberOfBytesToRead,
                                 PSIZE_T NumberOfBytesRead);

/*
 * NtOpenProcess - Ouvre un process
 */
NTSTATUS sys_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                           POBJECT_ATTRIBUTES ObjectAttributes,
                           PCLIENT_ID ClientId);

#endif /* SYSCALLS_H */
