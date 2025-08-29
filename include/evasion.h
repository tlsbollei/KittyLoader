#pragma once

#include <windows.h>
#include <intrin.h>

void execute_junk_calculations();
BOOL is_safe_environment();
void advanced_anti_debug();
BOOL detect_sandbox();
void integrity_checks();
void hide_module(HMODULE hModule);