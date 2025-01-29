#pragma once

#include <Windows.h>
#include "structs.h"

uintptr_t GetPebAddress(HANDLE hProcess);
DWORD GetMainThreadId(DWORD dwProcessId);
PVOID GetTebBaseAddressOfThread(HANDLE hThread);
uintptr_t GetModuleBaseAddy(DWORD procID, const std::wstring& moduleName);
DWORD GetProcessIdByName(const std::wstring& processName);
HWND FindMainWindow(DWORD pid);