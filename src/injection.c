#include <windows.h>
#include <stdio.h>

typedef struct lua_State lua_State;
typedef int (*lua_KFunction)(lua_State *L, int status, __int64 ctx);

typedef lua_State* (*pfn_luaL_newstate)(void);
typedef void       (*pfn_luaL_openlibs)(lua_State *L);
typedef void       (*pfn_lua_close)(lua_State *L);
typedef int        (*pfn_luaL_loadfilex)(lua_State *L, const char *filename, const char *mode);
typedef int        (*pfn_luaL_loadstring)(lua_State *L, const char *s);
typedef int        (*pfn_lua_pcallk)(lua_State *L, int nargs, int nresults, __int64 ctx, lua_KFunction k);
typedef const char*(*pfn_lua_tolstring)(lua_State *L, int idx, size_t *len);
typedef void       (*pfn_lua_pushstring)(lua_State *L, const char *s);
typedef void       (*pfn_lua_setglobal)(lua_State *L, const char *name);
typedef void       (*pfn_lua_pushnumber)(lua_State *L, double n);
typedef int        (*pfn_lua_getglobal)(lua_State *L, const char *name);
typedef void       (*pfn_lua_createtable)(lua_State *L, int narr, int nrec);
typedef void       (*pfn_lua_setfield)(lua_State *L, int idx, const char *k);
typedef double     (*pfn_lua_tonumberx)(lua_State *L, int idx, int *isnum);
typedef void       (*pfn_lua_settop)(lua_State *L, int idx);

static HMODULE hLua           = NULL;
static BOOL    consoleAlocado = FALSE;
static char    scriptPath[MAX_PATH];
static lua_State *L           = NULL;
static BOOL luaInicializado   = FALSE;

static pfn_luaL_newstate   fn_luaL_newstate;
static pfn_luaL_openlibs   fn_luaL_openlibs;
static pfn_lua_close       fn_lua_close;
static pfn_luaL_loadfilex  fn_luaL_loadfilex;
static pfn_luaL_loadstring fn_luaL_loadstring;
static pfn_lua_pcallk      fn_lua_pcallk;
static pfn_lua_tolstring   fn_lua_tolstring;
static pfn_lua_pushstring  fn_lua_pushstring;
static pfn_lua_setglobal   fn_lua_setglobal;
static pfn_lua_pushnumber  fn_lua_pushnumber;
static pfn_lua_getglobal   fn_lua_getglobal;
static pfn_lua_createtable fn_lua_createtable;
static pfn_lua_setfield    fn_lua_setfield;
static pfn_lua_tonumberx   fn_lua_tonumberx;
static pfn_lua_settop      fn_lua_settop;

#define LOAD_SYM(var, name) \
    var = (void*)GetProcAddress(hLua, name); \
    if (!var) { printf("[-] Simbolo nao encontrado: %s\n", name); ok = FALSE; }

static BOOL CarregarLua() {
    const char *candidates[] = { "lua54.dll", "lua53.dll", "lua52.dll", "lua51.dll", NULL };
    for (int i = 0; candidates[i]; i++) {
        hLua = GetModuleHandleA(candidates[i]);
        if (!hLua) hLua = LoadLibraryA(candidates[i]);
        if (hLua) { printf("[+] Lua encontrado: %s\n", candidates[i]); break; }
    }
    if (!hLua) { printf("[-] Nenhuma lua*.dll encontrada\n"); return FALSE; }

    BOOL ok = TRUE;
    LOAD_SYM(fn_luaL_newstate,   "luaL_newstate");
    LOAD_SYM(fn_luaL_openlibs,   "luaL_openlibs");
    LOAD_SYM(fn_lua_close,       "lua_close");
    LOAD_SYM(fn_luaL_loadfilex,  "luaL_loadfilex");
    LOAD_SYM(fn_luaL_loadstring, "luaL_loadstring");
    LOAD_SYM(fn_lua_pcallk,      "lua_pcallk");
    LOAD_SYM(fn_lua_tolstring,   "lua_tolstring");
    LOAD_SYM(fn_lua_pushstring,  "lua_pushstring");
    LOAD_SYM(fn_lua_setglobal,   "lua_setglobal");
    LOAD_SYM(fn_lua_pushnumber,  "lua_pushnumber");
    LOAD_SYM(fn_lua_getglobal,   "lua_getglobal");
    LOAD_SYM(fn_lua_createtable, "lua_createtable");
    LOAD_SYM(fn_lua_setfield,    "lua_setfield");
    LOAD_SYM(fn_lua_tonumberx,   "lua_tonumberx");
    LOAD_SYM(fn_lua_settop,      "lua_settop");
    return ok;
}

static BOOL InicializarPersistente() {
    if (!CarregarLua()) return FALSE;
    L = fn_luaL_newstate();
    if (!L) return FALSE;
    fn_luaL_openlibs(L);

    fn_luaL_loadstring(L, "io.stdout = io.open('CONOUT$', 'w'); io.stderr = io.stdout; if io.stdout then io.stdout:setvbuf('no') end");
    fn_lua_pcallk(L, 0, 0, 0, NULL);

    if (fn_luaL_loadfilex(L, scriptPath, NULL) != 0) {
        size_t len;
        const char *err = fn_lua_tolstring(L, -1, &len);
        printf("[-] Erro ao carregar %s: %s\n", scriptPath, err ? err : "?");
        return FALSE;
    }

    if (fn_lua_pcallk(L, 0, 0, 0, NULL) != 0) {
        size_t len;
        const char *err = fn_lua_tolstring(L, -1, &len);
        printf("[-] Erro na execucao inicial do script: %s\n", err ? err : "?");
        return FALSE;
    }

    printf("[+] G.A.N.C.H.O. Engine Lua Inicializada com Sucesso!\n");
    return TRUE;
}

// CreateFileW
__declspec(dllexport) HANDLE WINAPI HookCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    if (!consoleAlocado) { AllocConsole(); freopen_s((FILE**)stdout, "CONOUT$", "w", stdout); freopen_s((FILE**)stderr, "CONOUT$", "w", stderr); consoleAlocado = TRUE; }
    if (!luaInicializado) luaInicializado = InicializarPersistente();

    char nomeArquivo[MAX_PATH] = {0};
    if (lpFileName) WideCharToMultiByte(CP_UTF8, 0, lpFileName, -1, nomeArquivo, MAX_PATH, NULL, NULL);

    if (luaInicializado) {
        fn_lua_getglobal(L, "OnHookTrigger");
        fn_lua_pushstring(L, "CreateFileW");
        fn_lua_createtable(L, 0, 3);
        fn_lua_pushstring(L, nomeArquivo);
        fn_lua_setfield(L, -2, "filename");
        fn_lua_pushnumber(L, (double)dwDesiredAccess);
        fn_lua_setfield(L, -2, "desired_access");
        fn_lua_pushnumber(L, (double)dwCreationDisposition);
        fn_lua_setfield(L, -2, "creation_disposition");

        if (fn_lua_pcallk(L, 2, 0, 0, NULL) != 0) { fn_lua_settop(L, -2); }
    }
    return NULL;
}

// DispatchMessageW
__declspec(dllexport) LRESULT WINAPI HookDispatchMessageW(const MSG *lpMsg) {
    if (!consoleAlocado) { 
        AllocConsole(); 
        freopen_s((FILE**)stdout, "CONOUT$", "w", stdout); 
        freopen_s((FILE**)stderr, "CONOUT$", "w", stderr); 
        consoleAlocado = TRUE; 
    }
    if (!luaInicializado) luaInicializado = InicializarPersistente();

    if (luaInicializado && lpMsg) {
        fn_lua_getglobal(L, "OnHookTrigger");
        fn_lua_pushstring(L, "DispatchMessageW");
        
        fn_lua_createtable(L, 0, 2);
        fn_lua_pushnumber(L, (double)lpMsg->message);
        fn_lua_setfield(L, -2, "message");
        fn_lua_pushnumber(L, (double)lpMsg->wParam);
        fn_lua_setfield(L, -2, "wparam");

        if (fn_lua_pcallk(L, 2, 1, 0, NULL) != 0) { 
            fn_lua_settop(L, -2); 
        } else {
            int isNum = 0;
            double retVal = fn_lua_tonumberx(L, -1, &isNum);
            
            if (isNum) {
                ((MSG*)lpMsg)->wParam = (WPARAM)retVal;
            }
            
            fn_lua_settop(L, -2); 
        }
    } // <--- CORREÇÃO: Fechamento correto do bloco do 'if (luaInicializado && lpMsg)'

    return 0;
}

// WriteFile
__declspec(dllexport) BOOL WINAPI HookWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    if (!consoleAlocado) { AllocConsole(); freopen_s((FILE**)stdout, "CONOUT$", "w", stdout); freopen_s((FILE**)stderr, "CONOUT$", "w", stderr); consoleAlocado = TRUE; }
    if (!luaInicializado) luaInicializado = InicializarPersistente();

    if (luaInicializado && lpBuffer) {
        fn_lua_getglobal(L, "OnHookTrigger");
        fn_lua_pushstring(L, "WriteFile");
        
        fn_lua_createtable(L, 0, 2);
        fn_lua_pushnumber(L, (double)nNumberOfBytesToWrite);
        fn_lua_setfield(L, -2, "bytes_to_write");

        // PROTEÇÃO CONTRA CRASH: Aloca buffer estrito e garante terminação nula (\0)
        char safeBuffer[512] = {0};
        DWORD bytesParaCopiar = nNumberOfBytesToWrite > 511 ? 511 : nNumberOfBytesToWrite;
        memcpy(safeBuffer, lpBuffer, bytesParaCopiar);

        fn_lua_pushstring(L, safeBuffer);
        fn_lua_setfield(L, -2, "buffer_content");

        if (fn_lua_pcallk(L, 2, 0, 0, NULL) != 0) { fn_lua_settop(L, -2); }
    }
    return FALSE;
}

// SetWindowTextW
__declspec(dllexport) BOOL WINAPI HookSetWindowTextW(HWND hWnd, LPCWSTR lpString) {
    if (!consoleAlocado) { AllocConsole(); freopen_s((FILE**)stdout, "CONOUT$", "w", stdout); freopen_s((FILE**)stderr, "CONOUT$", "w", stderr); consoleAlocado = TRUE; }
    if (!luaInicializado) luaInicializado = InicializarPersistente();

    if (luaInicializado && lpString) {
        char tituloUtf8[MAX_PATH] = {0};
        WideCharToMultiByte(CP_UTF8, 0, lpString, -1, tituloUtf8, MAX_PATH, NULL, NULL);

        fn_lua_getglobal(L, "OnHookTrigger");
        fn_lua_pushstring(L, "SetWindowTextW");
        
        fn_lua_createtable(L, 0, 1);
        fn_lua_pushstring(L, tituloUtf8);
        fn_lua_setfield(L, -2, "title");

        if (fn_lua_pcallk(L, 2, 0, 0, NULL) != 0) { fn_lua_settop(L, -2); }
    }
    return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        char dllPath[MAX_PATH];
        GetModuleFileNameA(hinstDLL, dllPath, MAX_PATH);
        char *lastSlash = strrchr(dllPath, '\\');
        if (lastSlash) { 
            *(lastSlash + 1) = '\0'; 
            snprintf(scriptPath, MAX_PATH, "%shook.lua", dllPath); 
        }
        else { 
            snprintf(scriptPath, MAX_PATH, "hook.lua");
        }
    }
    return TRUE;
}
