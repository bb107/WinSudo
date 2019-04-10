#include <Windows.h>
#include <cstdio>
#include <ctime>
#include "../PrivilegeHelps/bsdef.h"
#define DUPLICATE_SAME_ATTRIBUTES 0x00000004
FARPROC WINAPI GetNtProcAddress(LPCSTR func_name) {
	return GetProcAddress(GetModuleHandleA("ntdll.dll"), func_name);
}
LPCSTR proc = "NtDuplicateObject";
NTSTATUS __declspec(naked) NTAPI NtDuplicateObject(
	IN HANDLE               SourceProcessHandle,
	IN HANDLE               SourceHandle,
	IN HANDLE               TargetProcessHandle,
	OUT PHANDLE             TargetHandle,
	IN ACCESS_MASK          DesiredAccess OPTIONAL,
	IN BOOLEAN              InheritHandle,
	IN ULONG                Options) {
	__asm {
		push proc;
		call GetNtProcAddress;
		jmp eax;
	}
}

int wmain(int argc, wchar_t *argv[]) {
	if (argc <= 1) {
		printf("usage: sudo [program] [parameters...]\n");
		return 0;
	}
	BSTATUS status = SeInitialDll();
	if (!BS_SUCCESS(status)) {
		printf("0x%08X|sudo: permission denied.\n", status);
		return 0; 
	}
	
	PRIVILEGE_VALUE priv = SE_ALL_PRIVILEGE_VALUE;
	TOKEN_GROUPS *tg; HANDLE hToken;
	status = SeReferenceProcessPrimaryToken(GetCurrentProcessId(), &hToken);
	if (!BS_SUCCESS(status)) {
		printf("0x%08X|sudo: failed.\n", status);
		return 0;
	}
	if (!SeQueryInformationToken(hToken, TokenGroups, &tg)) {
		printf("0x%08X|sudo: failed.\n", GetLastError());
		CloseHandle(hToken);
		return 0;
	}
	CloseHandle(hToken);
	status = SeCreateUserTokenExA(
		&hToken,
		SE_CREATE_USE_PRIVILEGES | SE_CREATE_USE_TOKEN_GROUPS | SE_CREATE_USE_DACL,
		TokenPrimary,
		System, { 0 },
		"system",
		tg,
		priv,
		//argv[1],
		"administrators",
		"system",
		nullptr, nullptr,
		SECURITY_MAX_IMPERSONATION_LEVEL);
	SeFreeAllocate(tg);
	if (!BS_SUCCESS(status)) {
		switch (status) {
		case BSTATUS_INVALID_USER_NAME:
			printf("0x%08X|sudo: invalid user name.\n", status);
			break;
		case BSTATUS_UNSUCCESSFUL:
			printf("0x%08X|sudo: failed.\n", GetLastError());
			break;
		}
		return 0;
	}

	STARTUPINFOW si = { 0 }; PROCESS_INFORMATION pi; DWORD e = 0;
	wchar_t *cmd, dir[1000]; int len = 0;
	GetCurrentDirectoryW(1000, dir);
	for (int i = 1; i < argc; i++) len += wcslen(argv[i]);
	len += 1000 + argc;
	cmd = new wchar_t[len];
	RtlZeroMemory(cmd, sizeof(wchar_t)*len);

	if (!NT_SUCCESS(NtDuplicateObject(GetCurrentProcess(), GetStdHandle(STD_OUTPUT_HANDLE),
		GetCurrentProcess(), &si.hStdError, 0, TRUE, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES)) ||
		!NT_SUCCESS(NtDuplicateObject(GetCurrentProcess(), GetStdHandle(STD_INPUT_HANDLE),
			GetCurrentProcess(), &si.hStdInput, 0, TRUE, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES))) {
		for (int i = 1; i < argc; i++) {
			bool add = false; int j = 0; wchar_t current;
			while (true) {
				current = *(argv[i] + j++);
				if (!current)break;
				if (current == L' ') {
					add = true; break;
				}
			}
			wsprintfW(cmd, add ? L"%s\"%s\" " : L"%s%s ", cmd, argv[i]);
		}
	}
	else {
		si.hStdOutput = si.hStdError; si.wShowWindow = 0; si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
		wsprintfW(cmd, L"%s\\cmder.exe %d ", dir, GetCurrentProcessId());
		for (int i = 1; i < argc; i++) {
			bool add = false; int j = 0; wchar_t current;
			while (true) {
				current = *(argv[i] + j++);
				if (!current)break;
				if (current == L' ') {
					add = true; break;
				}
			}
			wsprintfW(cmd, add ? L"%s\"%s\" " : L"%s%s ", cmd, argv[i]);
		}
	}
	if (CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE, nullptr, cmd, CREATE_UNICODE_ENVIRONMENT, GetEnvironmentStringsW(), dir, &si, &pi)) {
		if (si.dwFlags&STARTF_USESTDHANDLES) {
			do {
				WaitForSingleObject(pi.hProcess, 0xffff);
				GetExitCodeProcess(pi.hProcess, &e);
			} while (e == STILL_ACTIVE);
		}
	}
	else {
		printf("0x%08X|sudo: create process failed.\n", GetLastError());
	}
	delete[]cmd;
	CloseHandle(hToken);
	return 0;
}
