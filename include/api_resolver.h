#pragma once

#include <windows.h>

DWORD compute_custom_hash(const char* str);
PVOID get_function_by_hash(HMODULE module, DWORD hash);