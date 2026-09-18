#include "../include/gancho.h"

DLL_ENTRY* FindDLL(DLL_ENTRY *head, const char *baseName) {
    DLL_ENTRY *current = head;
    while (current != NULL) {
        wchar_t *fileName = wcsrchr(current->FullName, L'\\');
        fileName = fileName ? fileName + 1 : current->FullName;

        wchar_t wBaseName[MAX_PATH] = {0};
        mbstowcs(wBaseName, baseName, MAX_PATH);

        if (_wcsicmp(fileName, wBaseName) == 0)
            return current;
        current = current->next;
    }
    return NULL;
}

PVOID FindFunction(DLL_ENTRY *dll, const char *funcName) {
    PE_EXPORT *exp = dll->exports;
    while (exp != NULL) {
        if (strcmp(exp->FuncName, funcName) == 0)
            return exp->FuncAddress;
        exp = exp->next;
    }
    return NULL;
}

BOOL GetLoadedDLLs(HANDLE hProcess, PEB_LDR_DATA *pLdr, DLL_ENTRY **pAllDlls) {
    DLL_ENTRY *head = NULL;
    DLL_ENTRY *tail = NULL;
    LIST_ENTRY currentEntry;
    PVOID currentPtr = pLdr->InMemoryOrderModuleList.Flink;
    PVOID headPtr    = pLdr->InMemoryOrderModuleList.Flink;

    do {
        ReadProcessMemory(hProcess, currentPtr, &currentEntry, sizeof(LIST_ENTRY), NULL);
        LDR_DATA_TABLE_ENTRY *entryPtr = CONTAINING_RECORD(currentPtr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        LDR_DATA_TABLE_ENTRY ldrEntry;
        ReadProcessMemory(hProcess, entryPtr, &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL);

        if (ldrEntry.DllBase == NULL || ldrEntry.FullDllName.Length == 0) {
            currentPtr = currentEntry.Flink;
            continue;
        }

        wchar_t dllName[MAX_PATH] = {0};
        ReadProcessMemory(hProcess, ldrEntry.FullDllName.Buffer, dllName, ldrEntry.FullDllName.Length, NULL);
        dllName[ldrEntry.FullDllName.Length / sizeof(wchar_t)] = L'\0';

        wchar_t *ext = wcsrchr(dllName, L'.');
        if (ext == NULL || _wcsicmp(ext, L".dll") != 0) {
            currentPtr = currentEntry.Flink;
            continue;
        }

        DLL_ENTRY *node = (DLL_ENTRY*)calloc(1, sizeof(DLL_ENTRY));
        node->DllBase = ldrEntry.DllBase;
        wcscpy(node->FullName, dllName);

        if (head == NULL) {
            head = node;
            tail = node;
        } else {
            tail->next = node;
            tail = node;
        }

        currentPtr = currentEntry.Flink;
    } while (currentPtr != headPtr);

    *pAllDlls = head; 
    return TRUE;
}

void FreeDLLList(DLL_ENTRY *head) {
    DLL_ENTRY *current = head;
    while (current != NULL) {
        DLL_ENTRY *next = current->next;
        free(current);
        current = next;
    }
}