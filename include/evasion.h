#pragma once
#include <windows.h>
#include <stdint.h>

typedef struct {
    float debug;
    float sandbox;
    float integrity;
    float user;
    float overall;
} envstats;

typedef enum {
    fullmode = 0,
    halfmode,
    slowmode,
    stopmode
} runmode;

void busywork();
unsigned long long cpuspeed();
void waittime(uint32_t ms, float variance);
float checkresources();
float watchmouse();
float checkapihooks();
float finddebugs();
float checkenv();
envstats getenvstats();
runmode pickmode(float score);
void runmode_action(runmode mode);
unsigned long __stdcall background_loop(void* unused);
void selfcheck();
int issafe();
void hideself(void* modulebase);
void startevasion();
