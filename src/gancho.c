#include "../include/gancho.h"
#include "../include/hde64.h"

HANDLE hProcess;
char  *dllName = "injection.dll";

PVOID AllocNear(HANDLE hProcess, PVOID reference, SIZE_T size) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD granularity = si.dwAllocationGranularity;

    UINT64 base    = (UINT64)reference;
    UINT64 lo      = (base > 0x40000000) ? (base - 0x40000000) : 0x10000;
    UINT64 hi      = base + 0x40000000;
    UINT64 current = lo;

    while (current < hi) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, (PVOID)current, &mbi, sizeof(mbi)) == 0) break;

        if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
            UINT64 candidate = ((UINT64)mbi.BaseAddress + granularity - 1) & ~(UINT64)(granularity - 1);
            if (candidate + size <= hi) {
                PVOID result = VirtualAllocEx(hProcess, (PVOID)candidate, size,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (result) return result;
            }
        }

        current = (UINT64)mbi.BaseAddress + mbi.RegionSize;
    }

    return NULL;
}

PVOID CreateStubProxy(HANDLE hProcess, PVOID funcHook, PVOID funcTarget, PVOID trampoline) {
    BYTE buffer[256];
    int p = 0;

    // sub rsp, 0x68  (104 bytes: shadow(32) + slots args(32) + alinhamento(8) para manter RSP%16==0 antes do call)
    // Na entrada do stub RSP%16==8 (return addr do caller no topo).
    // sub rsp, 0x68 (104 = 6*16 + 8): RSP%16 == 8-8 == 0. Antes do call RSP%16==0 -> apos call RSP%16==8 ✓
    buffer[p++] = 0x48; buffer[p++] = 0x83; buffer[p++] = 0xEC; buffer[p++] = 0x68;

    // Salva args originais apos o shadow space (rsp+0x20 .. rsp+0x38)
    // [rsp+0x00..0x18] = shadow space pro call abaixo
    // [rsp+0x20] = RCX
    // [rsp+0x28] = RDX
    // [rsp+0x30] = R8
    // [rsp+0x38] = R9
    buffer[p++] = 0x48; buffer[p++] = 0x89; buffer[p++] = 0x4C; buffer[p++] = 0x24; buffer[p++] = 0x20;
    buffer[p++] = 0x48; buffer[p++] = 0x89; buffer[p++] = 0x54; buffer[p++] = 0x24; buffer[p++] = 0x28;
    buffer[p++] = 0x4C; buffer[p++] = 0x89; buffer[p++] = 0x44; buffer[p++] = 0x24; buffer[p++] = 0x30;
    buffer[p++] = 0x4C; buffer[p++] = 0x89; buffer[p++] = 0x4C; buffer[p++] = 0x24; buffer[p++] = 0x38;

    // mov rax, funcHook
    buffer[p++] = 0x48; buffer[p++] = 0xB8;
    *(UINT64*)(buffer + p) = (UINT64)funcHook; p += 8;
    // call rax
    buffer[p++] = 0xFF; buffer[p++] = 0xD0;

    // Restaura args
    buffer[p++] = 0x48; buffer[p++] = 0x8B; buffer[p++] = 0x4C; buffer[p++] = 0x24; buffer[p++] = 0x20;
    buffer[p++] = 0x48; buffer[p++] = 0x8B; buffer[p++] = 0x54; buffer[p++] = 0x24; buffer[p++] = 0x28;
    buffer[p++] = 0x4C; buffer[p++] = 0x8B; buffer[p++] = 0x44; buffer[p++] = 0x24; buffer[p++] = 0x30;
    buffer[p++] = 0x4C; buffer[p++] = 0x8B; buffer[p++] = 0x4C; buffer[p++] = 0x24; buffer[p++] = 0x38;

    // add rsp, 0x68
    buffer[p++] = 0x48; buffer[p++] = 0x83; buffer[p++] = 0xC4; buffer[p++] = 0x68;

    // jmp [rip+0] -> trampoline (absoluto, nao precisa ficar perto)
    buffer[p++] = 0xFF; buffer[p++] = 0x25;
    *(DWORD*)(buffer + p) = 0x00000000; p += 4;
    *(UINT64*)(buffer + p) = (UINT64)trampoline; p += 8;

    PVOID remoteStub = AllocNear(hProcess, funcTarget, p);
    if (!remoteStub) return NULL;
    WriteProcessMemory(hProcess, remoteStub, buffer, p, NULL);
    return remoteStub;
}

BOOL HookFunction(HANDLE hProcess, PVOID funcTarget, PVOID stub, PVOID trampoline) {
    BYTE patch[14] = {0};
    patch[0] = 0xFF;
    patch[1] = 0x25;
    *(DWORD*)(patch + 2)  = 0x00000000;
    *(UINT64*)(patch + 6) = (UINT64)stub;

    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, funcTarget, 14, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] Erro ao desproteger memoria\n");
        VirtualFreeEx(hProcess, trampoline, 0, MEM_RELEASE);
        return FALSE;
    }

    WriteProcessMemory(hProcess, funcTarget, patch, 14, NULL);
    VirtualProtectEx(hProcess, funcTarget, 14, oldProtect, &oldProtect);

    printf("[+] Hook aplicado! stub=%p trampoline=%p\n", stub, trampoline);
    return TRUE;
}

BOOL CreateTrampoline(HANDLE hProcess, PVOID funcTarget, PVOID *pTrampoline) {
    BYTE original[64] = {0};
    if (!ReadProcessMemory(hProcess, funcTarget, original, sizeof(original), NULL))
        return FALSE;

    int bytesNecessarios = 0;
    BYTE *ptr = original;
    while (bytesNecessarios < 14) {
        hde64s hs;
        hde64_disasm(ptr, &hs);
        if (hs.flags & F_ERROR) return FALSE;
        bytesNecessarios += hs.len;
        ptr += hs.len;
    }

    SIZE_T allocSize = bytesNecessarios + 14;
    PVOID trampoline = AllocNear(hProcess, funcTarget, allocSize);
    if (!trampoline) return FALSE;

    BYTE trampolineBuffer[128] = {0};
    memcpy(trampolineBuffer, original, bytesNecessarios);

    int offset = 0;
    ptr = original;
    while (offset < bytesNecessarios) {
        hde64s hs;
        hde64_disasm(ptr, &hs);

        if (hs.flags & F_RELATIVE) {
            UINT64 oldRIP    = (UINT64)funcTarget + offset + hs.len;
            UINT64 newRIP    = (UINT64)trampoline  + offset + hs.len;
            UINT64 absTarget = 0;

            if (hs.flags & F_IMM8)
                absTarget = oldRIP + (INT64)(INT8)hs.imm.imm8;
            else if (hs.flags & F_IMM16)
                absTarget = oldRIP + (INT64)(INT16)hs.imm.imm16;
            else if (hs.flags & F_IMM32)
                absTarget = oldRIP + (INT64)(INT32)hs.imm.imm32;
            else if (hs.flags & F_IMM64)
                absTarget = oldRIP + (INT64)hs.imm.imm64;

            INT64 newDisp = (INT64)(absTarget - newRIP);

            if (hs.flags & F_IMM8) {
                if (newDisp > INT8_MAX || newDisp < INT8_MIN) {
                    VirtualFreeEx(hProcess, trampoline, 0, MEM_RELEASE);
                    return FALSE;
                }
                trampolineBuffer[offset + hs.len - 1] = (BYTE)(INT8)newDisp;
            } else if (hs.flags & F_IMM32) {
                if (newDisp > INT32_MAX || newDisp < INT32_MIN) {
                    VirtualFreeEx(hProcess, trampoline, 0, MEM_RELEASE);
                    return FALSE;
                }
                *(INT32*)(trampolineBuffer + offset + hs.len - 4) = (INT32)newDisp;
            }
        }

        if ((hs.flags & F_MODRM) && ((hs.modrm & 0xC7) == 0x05)) {
            UINT64 oldRIP    = (UINT64)funcTarget + offset + hs.len;
            UINT64 newRIP    = (UINT64)trampoline  + offset + hs.len;
            INT32  oldDisp   = *(INT32*)(trampolineBuffer + offset + hs.len - 4);
            UINT64 absTarget = oldRIP + (INT64)oldDisp;
            INT64  newDisp   = (INT64)(absTarget - newRIP);
            if (newDisp > INT32_MAX || newDisp < INT32_MIN) {
                VirtualFreeEx(hProcess, trampoline, 0, MEM_RELEASE);
                return FALSE;
            }
            *(INT32*)(trampolineBuffer + offset + hs.len - 4) = (INT32)newDisp;
        }

        offset += hs.len;
        ptr    += hs.len;
    }

    PVOID retAddr = (BYTE*)funcTarget + bytesNecessarios;
    trampolineBuffer[bytesNecessarios + 0] = 0xFF;
    trampolineBuffer[bytesNecessarios + 1] = 0x25;
    *(DWORD*)(trampolineBuffer + bytesNecessarios + 2)  = 0x00000000;
    *(UINT64*)(trampolineBuffer + bytesNecessarios + 6) = (UINT64)retAddr;

    if (!WriteProcessMemory(hProcess, trampoline, trampolineBuffer, bytesNecessarios + 14, NULL)) {
        VirtualFreeEx(hProcess, trampoline, 0, MEM_RELEASE);
        return FALSE;
    }

    *pTrampoline = trampoline;
    return TRUE;
}

int main() {
    PROCESS_INFORMATION     processInfo;
    mPEB                    pPeb;
    PEB_LDR_DATA            pLdr;
    DLL_ENTRY               *pAllDlls = NULL;
    LPVOID                  trampoline = NULL;

    ZeroMemory(&processInfo, sizeof(processInfo));
    OpenDebugProcess(&processInfo);
    Sleep(500);
    InjectDLL(dllName, processInfo.dwProcessId);
    Sleep(1000);
    GetRemotePEB(hProcess, &pPeb);
    GetRemoteLDR(hProcess, &pPeb, &pLdr);
    GetLoadedDLLs(hProcess, &pLdr, &pAllDlls);

    DLL_ENTRY *cur = pAllDlls;
    while (cur != NULL) {
        PopulateDLLExports(hProcess, cur);
        cur = cur->next;
    }

    DLL_ENTRY *myDll = FindDLL(pAllDlls, dllName);
    if (!myDll) {
        printf("[-] DLL nao encontrada\n");
        return 1;
    }

    DLL_ENTRY *kernel32 = FindDLL(pAllDlls, "kernel32.dll");
    if (!kernel32) {
        printf("[-] kernel32.dll nao encontrada\n");
        return 1;
    }

    DLL_ENTRY *user32 = FindDLL(pAllDlls, "user32.dll");
    if (!user32) {
        printf("[-] user32.dll nao encontrada no processo alvo\n");
        return 1;
    }

    // ========================================================================
    // 1. HOOK: CreateFileW (kernel32.dll)
    // ========================================================================
    printf("[*] Aplicando primeiro Hook: CreateFileW\n");
    PVOID funcHook = FindFunction(myDll,    "HookCreateFileW");
    PVOID funcAlvo = FindFunction(kernel32, "CreateFileW");
    
    printf("[*] FuncaoAlvo      em: %p\n", funcAlvo);
    printf("[*] HookCreateFileW em: %p\n", funcHook);

    if (!CreateTrampoline(hProcess, funcAlvo, &trampoline)) {
        printf("[-] Falha ao criar trampoline\n");
        return 1;
    }
    printf("[*] Trampoline em: %p\n", trampoline);

    PVOID stub = CreateStubProxy(hProcess, funcHook, funcAlvo, trampoline);
    if (!stub) {
        printf("[-] Falha ao criar stub\n");
        return 1;
    }
    printf("[*] Stub em: %p\n", stub);

    if (!HookFunction(hProcess, funcAlvo, stub, trampoline)) {
        printf("[-] Falha ao aplicar hook\n");
        return 1;
    }

    // ========================================================================
    // 2. HOOK: DispatchMessageW (user32.dll)
    // ========================================================================
    printf("\n[*] Aplicando segundo Hook: DispatchMessageW\n");
    PVOID funcHookMsg = FindFunction(myDll,    "HookDispatchMessageW");
    PVOID funcAlvoMsg = FindFunction(user32,   "DispatchMessageW");
    
    printf("[*] FuncAlvoMsg       em: %p\n", funcAlvoMsg);
    printf("[*] HookDispatchMsg   em: %p\n", funcHookMsg);

    LPVOID trampolineMsg = NULL;
    if (!CreateTrampoline(hProcess, funcAlvoMsg, &trampolineMsg)) {
        printf("[-] Falha ao criar trampoline para DispatchMessageW\n");
        return 1;
    }
    printf("[*] TrampolineMsg em: %p\n", trampolineMsg);

    PVOID stubMsg = CreateStubProxy(hProcess, funcHookMsg, funcAlvoMsg, trampolineMsg);
    if (!stubMsg) {
        printf("[-] Falha ao criar stub para DispatchMessageW\n");
        return 1;
    }
    printf("[*] StubMsg em: %p\n", stubMsg);

    if (!HookFunction(hProcess, funcAlvoMsg, stubMsg, trampolineMsg)) {
        printf("[-] Falha ao aplicar hook em DispatchMessageW\n");
        return 1;
    }

    // ========================================================================
    // 3. HOOK: WriteFile (kernel32.dll)
    // ========================================================================
    printf("\n[*] Aplicando terceiro Hook: WriteFile\n");
    PVOID funcHookWrite = FindFunction(myDll,    "HookWriteFile");
    PVOID funcAlvoWrite = FindFunction(kernel32, "WriteFile");
    
    printf("[*] FuncAlvoWrite     em: %p\n", funcAlvoWrite);
    printf("[*] HookWriteFile     em: %p\n", funcHookWrite);

    LPVOID trampolineWrite = NULL;
    if (!CreateTrampoline(hProcess, funcAlvoWrite, &trampolineWrite)) {
        printf("[-] Falha ao criar trampoline para WriteFile\n");
        return 1;
    }
    printf("[*] TrampolineWrite em: %p\n", trampolineWrite);

    PVOID stubWrite = CreateStubProxy(hProcess, funcHookWrite, funcAlvoWrite, trampolineWrite);
    if (!stubWrite) {
        printf("[-] Falha ao criar stub para WriteFile\n");
        return 1;
    }
    printf("[*] StubWrite em: %p\n", stubWrite);

    if (!HookFunction(hProcess, funcAlvoWrite, stubWrite, trampolineWrite)) {
        printf("[-] Falha ao aplicar hook em WriteFile\n");
        return 1;
    }

    // ========================================================================
    // 4. HOOK: SetWindowTextW (user32.dll)
    // ========================================================================
    printf("\n[*] Aplicando quarto Hook: SetWindowTextW\n");
    PVOID funcHookText = FindFunction(myDll,    "HookSetWindowTextW");
    PVOID funcAlvoText = FindFunction(user32,   "SetWindowTextW");
    
    printf("[*] FuncAlvoText      em: %p\n", funcAlvoText);
    printf("[*] HookSetWindowText em: %p\n", funcHookText);

    LPVOID trampolineText = NULL;
    if (!CreateTrampoline(hProcess, funcAlvoText, &trampolineText)) {
        printf("[-] Falha ao criar trampoline para SetWindowTextW\n");
        return 1;
    }
    printf("[*] TrampolineText em: %p\n", trampolineText);

    PVOID stubText = CreateStubProxy(hProcess, funcHookText, funcAlvoText, trampolineText);
    if (!stubText) {
        printf("[-] Falha ao criar stub para SetWindowTextW\n");
        return 1;
    }
    printf("[*] StubText em: %p\n", stubText);

    if (!HookFunction(hProcess, funcAlvoText, stubText, trampolineText)) {
        printf("[-] Falha ao aplicar hook em SetWindowTextW\n");
        return 1;
    }

    // ========================================================================
    // Inicialização Concluída
    // ========================================================================
    printf("\n[+] G.A.N.C.H.O. totalmente operacional com 4 Hooks ativos! (Ctrl+C para sair)\n");
    while (1) { Sleep(1000); }
}

BOOL InjectDLL(char *pathdll, int pid) {
    char fullPath[MAX_PATH];
    char exePath[MAX_PATH];
    
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    char *lastSlash = strrchr(exePath, '\\');
    if (lastSlash != NULL) {
        *(lastSlash + 1) = '\0'; 
    }

    snprintf(fullPath, MAX_PATH, "%s%s", exePath, pathdll);
    printf("[*] Caminho real da DLL: %s\n", fullPath);

    DWORD dwAttrib = GetFileAttributesA(fullPath);
    if (dwAttrib == INVALID_FILE_ATTRIBUTES) {
        printf("[-] Erro: DLL nao encontrada no caminho especificado.\n");
        return FALSE;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("Erro ao abrir processo (PID: %d). Erro: %lu\n", pid, GetLastError());
        return FALSE;
    }

    int nLength = strlen(fullPath) + 1;
    LPVOID lpRemoteString = VirtualAllocEx(hProcess, NULL, nLength, MEM_COMMIT, PAGE_READWRITE);

    if (!lpRemoteString) {
        printf("Erro ao alocar memoria remota\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    if (!WriteProcessMemory(hProcess, lpRemoteString, fullPath, nLength, NULL)) {
        printf("Erro ao escrever na memoria remota\n");
        VirtualFreeEx(hProcess, lpRemoteString, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    LPVOID lpLoadLibraryA = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
        (LPTHREAD_START_ROUTINE)lpLoadLibraryA, lpRemoteString, 0, NULL);
    
    if (!hThread) {
        printf("Erro ao criar thread remota\n");
        VirtualFreeEx(hProcess, lpRemoteString, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[!] Aguardando LoadLibraryA concluir...\n");
    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    if (exitCode == 0) {
        printf("[!!] LoadLibraryA falhou dentro do alvo\n");
    } else {
        printf("[*] DLL carregada no endereco: 0x%lX\n", exitCode);
    }
        
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, lpRemoteString, 0, MEM_RELEASE);
    return TRUE;
}

void Cleanup() {
    DWORD exit_code;
    GetExitCodeProcess(hProcess, &exit_code);
    TerminateProcess(hProcess, exit_code);
}

BOOL EjectDLL() {
    HMODULE hMod = NULL;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, MAX_PATH)) {
                if (strstr(szModName, dllName)) {
                    hMod = hMods[i];
                    break;
                }
            }
        }
    }

    if (!hMod) {
        printf("DLL nao encontrada no processo alvo.\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    LPVOID lpFreeLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
        (LPTHREAD_START_ROUTINE)lpFreeLibrary, (LPVOID)hMod, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        printf("DLL descarregada com sucesso!\n");
    }

    CloseHandle(hProcess);
    return TRUE;
}

rprocess_t* GetRunningProcecess(int *c) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot() failed with error %lu\n", GetLastError());
        return NULL;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    BOOL ok = Process32First(hSnap, &pe);
    if (!ok) {
        printf("Process32First() failed with error %lu\n", GetLastError());
        return NULL;
    }

    rprocess_t *processes = NULL;
    int count = 0;
    int capacity = 10; 

    processes = (rprocess_t*)malloc(capacity * sizeof(rprocess_t));

    while (ok) {
        if (count >= capacity) {
            capacity *= 2;
            rprocess_t *temp = (rprocess_t*)realloc(processes, capacity * sizeof(rprocess_t));
            if (temp == NULL) {
                printf("Error in realloc\n");
                free(processes);
                return NULL;
            }
            processes = temp;
        }
        
        strncpy(processes[count].name, pe.szExeFile, MAX_PATH - 1);
        processes[count].pid = pe.th32ProcessID;
        count++;

        ok = Process32Next(hSnap, &pe);
    }

    processes = (rprocess_t*)realloc(processes, count * sizeof(rprocess_t));
    CloseHandle(hSnap);
    
    *c = count;
    return processes;
}

BOOL OpenDebugProcess(PROCESS_INFORMATION *processInfo) {
    LPCWSTR fullPath = L"C:\\Program Files\\Notepad++\\notepad++.exe";
    // LPCWSTR fullPath = L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
    
    STARTUPINFOW startupInfo;
    
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    if (CreateProcessW(fullPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, processInfo)) {
        printf("[*] Processo de debug criado!\n");
    } else {
        printf("Erro ao abrir processo de debug: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL GetRemotePEB(HANDLE hProcess, mPEB *pPeb) {
    if (hProcess) {
        PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLength;

        pNtQueryInformationProcess NtQueryInfo = (pNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        
        if (NtQueryInfo(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength) == 0) {
            if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, pPeb, sizeof(PEB), NULL)) {
                printf("PEB Remoto lido com sucesso!\n");
                return TRUE;
            }
        }
    }
    return FALSE;
}

BOOL GetRemoteLDR(HANDLE hProcess, mPEB *pPeb, PEB_LDR_DATA *pLdr) {
    if (ReadProcessMemory(hProcess, pPeb->Ldr, pLdr, sizeof(PEB_LDR_DATA), NULL)) {
        printf("LDR Remoto lido com sucesso!\n");
        return TRUE;
    } 
    return FALSE;
}

BOOL PopulateDLLExports(HANDLE hProcess, DLL_ENTRY *dll) {
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    IMAGE_EXPORT_DIRECTORY exportDir;

    if (!ReadProcessMemory(hProcess, dll->DllBase, &dosHeader, sizeof(dosHeader), NULL))
        return FALSE;
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PVOID ntHeadersPtr = (BYTE*)dll->DllBase + dosHeader.e_lfanew;
    if (!ReadProcessMemory(hProcess, ntHeadersPtr, &ntHeaders, sizeof(ntHeaders), NULL))
        return FALSE;
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir.VirtualAddress == 0)
        return TRUE;

    PVOID exportDirPtr = (BYTE*)dll->DllBase + exportDataDir.VirtualAddress;
    if (!ReadProcessMemory(hProcess, exportDirPtr, &exportDir, sizeof(exportDir), NULL))
        return FALSE;

    DWORD *funcRVAs     = (DWORD*)calloc(exportDir.NumberOfFunctions, sizeof(DWORD));
    DWORD *nameRVAs     = (DWORD*)calloc(exportDir.NumberOfNames,     sizeof(DWORD));
    WORD  *nameOrdinals = (WORD*) calloc(exportDir.NumberOfNames,     sizeof(WORD));

    ReadProcessMemory(hProcess, (BYTE*)dll->DllBase + exportDir.AddressOfFunctions,
        funcRVAs, exportDir.NumberOfFunctions * sizeof(DWORD), NULL);
    ReadProcessMemory(hProcess, (BYTE*)dll->DllBase + exportDir.AddressOfNames,
        nameRVAs, exportDir.NumberOfNames * sizeof(DWORD), NULL);
    ReadProcessMemory(hProcess, (BYTE*)dll->DllBase + exportDir.AddressOfNameOrdinals,
        nameOrdinals, exportDir.NumberOfNames * sizeof(WORD), NULL);

    PE_EXPORT *tail = NULL;
    for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
        char funcName[256] = {0};
        PVOID namePtr = (BYTE*)dll->DllBase + nameRVAs[i];
        ReadProcessMemory(hProcess, namePtr, funcName, sizeof(funcName) - 1, NULL);

        WORD  ordinal  = nameOrdinals[i];
        DWORD funcRVA  = funcRVAs[ordinal];
        PVOID funcAddr = (BYTE*)dll->DllBase + funcRVA;

        PE_EXPORT *node = (PE_EXPORT*)calloc(1, sizeof(PE_EXPORT));
        strncpy(node->FuncName, funcName, sizeof(node->FuncName) - 1);
        node->FuncAddress = funcAddr;

        if (dll->exports == NULL) {
            dll->exports = node;
            tail = node;
        } else {
            tail->next = node;
            tail = node;
        }
    }

    free(funcRVAs);
    free(nameRVAs);
    free(nameOrdinals);

    return TRUE;
}