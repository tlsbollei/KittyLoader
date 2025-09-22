#pragma once
#include <windows.h>

unsigned long hashstr(const char* s);
void* findfunc(void* module, unsigned long hash);
