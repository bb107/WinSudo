#pragma once
#undef UNICODE
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include "bsdef.h"

DWORD BSAPI PsGetProcessId(const char* szProcessName);

