#include <Windows.h>
#include "Process.h"
#include "Native.h"
#include "Security.h"

const std::string Strupr(IN const char* buf) {
	int len = strlen(buf) + 1;
	std::string tmp(len, 0);
	for (int i = 0; i < len; i++)
		tmp[i] = buf[i] >= 'a'&&buf[i] <= 'z' ? buf[i] - 0x20 : buf[i];
	return tmp;
}
#define strupr Strupr

DWORD BSAPI PsGetProcessId(const char* szProcessName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	std::string pn = strupr((char*)szProcessName);
	if (hSnapshot == INVALID_HANDLE_VALUE)	return 0;
	PROCESSENTRY32 ps;
	if (!Process32First(hSnapshot, &ps))	return 0;
	do {
		if (!strcmp(strupr(ps.szExeFile).data(), pn.data())) {
			CloseHandle(hSnapshot);	return ps.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &ps));
	CloseHandle(hSnapshot);
	return 0;
}

DWORD BSAPI PsCurrentProcessId() {
	return GetCurrentProcessId();
}

DWORD BSAPI PsCurrentThreadId() {
	return GetCurrentThreadId();
}

BSTATUS BSAPI PsCreateUserProcessA(
	HANDLE hUserToken,
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation) {
	if (IsBadWritePtr(lpProcessInformation, sizeof(PROCESS_INFORMATION)) ||
		IsBadWritePtr(lpStartupInfo, sizeof(STARTUPINFOA)) ||
		IsBadReadPtr(lpStartupInfo, sizeof(STARTUPINFOA)))
		return BSTATUS_ACCESS_VIOLATION;

	HANDLE tmp = hElvToken; DWORD *dwSessionId;
	PRIVILEGE_VALUE privs =	SE_ASSIGNPRIMARYTOKEN_VALUE | SE_IMPERSONATE_VALUE | SE_TCB_VALUE | SE_DEBUG_VALUE;
	BSTATUS status = SeEnablePrivilegesToken(&tmp, privs);
	if (!BS_SUCCESS(status))return status;

	if (sizeof(DWORD) != SeQueryInformationToken(hUserToken, TokenSessionId, &dwSessionId)) {
		CloseHandle(tmp);
		return BSTATUS_UNSUCCESSFUL;
	}
	status = SeSetInformationToken(hUserToken, TokenSessionId, dwSessionId, sizeof(DWORD));
	SeFreeAllocate(dwSessionId);
	if (!BS_SUCCESS(status)) {
		CloseHandle(tmp);
		return BSTATUS_UNSUCCESSFUL;
	}
	RevertToSelf();
	ImpersonateLoggedOnUser(tmp);
	CloseHandle(tmp);

	BOOL ret = CreateProcessInternalA(
		hUserToken,
		lpApplicationName, lpCommandLine,
		nullptr, nullptr,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation,
		&tmp);
	dwSessionId = (PDWORD)GetLastError();

	RevertToSelf();
	if (reference_count)ImpersonateLoggedOnUser(hElvToken);
	SetLastError((DWORD)dwSessionId);
	return ret ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI PsCreateUserProcessW(
	HANDLE hUserToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation) {
	if (IsBadWritePtr(lpProcessInformation, sizeof(PROCESS_INFORMATION)) ||
		IsBadWritePtr(lpStartupInfo, sizeof(STARTUPINFOW)) ||
		IsBadReadPtr(lpStartupInfo, sizeof(STARTUPINFOW)))
		return BSTATUS_ACCESS_VIOLATION;

	HANDLE tmp = hElvToken; DWORD *dwSessionId;
	PRIVILEGE_VALUE privs = SE_ASSIGNPRIMARYTOKEN_VALUE | SE_IMPERSONATE_VALUE | SE_TCB_VALUE | SE_DEBUG_VALUE;
	BSTATUS status = SeEnablePrivilegesToken(&tmp, privs);
	if (!BS_SUCCESS(status))return status;
	if (sizeof(DWORD) != SeQueryInformationToken(hUserToken, TokenSessionId, &dwSessionId)) {
		CloseHandle(tmp);
		return BSTATUS_UNSUCCESSFUL;
	}
	status = SeSetInformationToken(hUserToken, TokenSessionId, dwSessionId, sizeof(DWORD));
	SeFreeAllocate(dwSessionId);
	if (!BS_SUCCESS(status)) {
		CloseHandle(tmp);
		return BSTATUS_UNSUCCESSFUL;
	}
	RevertToSelf();
	ImpersonateLoggedOnUser(tmp);
	CloseHandle(tmp);

	BOOL ret = CreateProcessInternalW(
		hUserToken,
		lpApplicationName, lpCommandLine,
		nullptr, nullptr,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation,
		&tmp);
	dwSessionId = (PDWORD)GetLastError();

	RevertToSelf();
	if (reference_count)ImpersonateLoggedOnUser(hElvToken);
	SetLastError((DWORD)dwSessionId);
	return ret ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
}
