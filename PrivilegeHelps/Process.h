#pragma once
#undef UNICODE
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

DWORD PsGetProcessId(const char* szProcessName);
