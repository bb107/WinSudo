#include <Windows.h>
#include <cstdio>
#include <ctime>
#include "../PrivilegeHelps/bsdef.h"
#include "../PrivilegeHelps/Native.h"

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
	
	//启用全部特权
	PRIVILEGE_VALUE priv = SE_ALL_PRIVILEGE_VALUE;

	TOKEN_GROUPS *tg, *tg2; HANDLE hToken; DWORD dwsize = 0;
	status = SeReferenceThreadToken(GetCurrentThreadId(), &hToken);
	if (!BS_SUCCESS(status)) {
		printf("0x%08X|sudo: failed.\n", status);
		return 0;
	}

	//以lsass.exe的组信息为基础,添加 TrustedInstaller 用户组
	if (!SeQueryInformationToken(hToken, TokenGroups, &tg)) {
		printf("0x%08X|sudo: failed.\n", GetLastError());
		CloseHandle(hToken);
		return 0;
	}
	CloseHandle(hToken);
	dwsize = (tg->GroupCount + 1) * sizeof(SID_AND_ATTRIBUTES) + sizeof(DWORD);
	tg2 = (PTOKEN_GROUPS)new char[dwsize];
	status = SeSingleTokenGroupsAddNameA(
		"nt service\\trustedinstaller",
		SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY | SE_GROUP_OWNER,
		tg, tg2, &dwsize);
	SeFreeAllocate(tg); tg = tg2;
	if (!BS_SUCCESS(status)) {
		delete[]tg;
		return 0;
	}

	//创建一个全新的高特权的访问令牌
	status = SeCreateUserTokenExA(
		&hToken,
		SE_CREATE_USE_PRIVILEGES | SE_CREATE_USE_TOKEN_GROUPS | SE_CREATE_USE_DACL,
		TokenPrimary,
		System, { 0 },
		"system",
		tg,
		priv,
		//argv[1],
		"system",
		"administrators",
		nullptr, nullptr,
		SECURITY_MAX_IMPERSONATION_LEVEL);
	delete[]tg;
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

	ProcessIdToSessionId(GetCurrentProcessId(), &e);
	status = SeSetInformationToken(hToken, TokenSessionId, &e, sizeof(DWORD));
	if (!BS_SUCCESS(status)) {
		CloseHandle(hToken);
		return 0;
	}
	ImpersonateLoggedOnUser(hToken);

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

	if (CreateProcessInternalW(hToken, nullptr, cmd, nullptr, nullptr, TRUE, CREATE_UNICODE_ENVIRONMENT, GetEnvironmentStringsW(), dir, &si, &pi, (PHANDLE)&e)) {
		do {
			WaitForSingleObject(pi.hProcess, 0xffff);
			GetExitCodeProcess(pi.hProcess, &e);
		} while (e == STILL_ACTIVE);
	}
	else {
		printf("0x%08X|sudo: create process failed.\n", GetLastError());
	}
	delete[]cmd;
	CloseHandle(hToken);
	RevertToSelf();
	return 0;
}
