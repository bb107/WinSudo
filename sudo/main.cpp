#undef UNICODE
#include <Windows.h>
#include <cstdio>
#include "../PrivilegeHelps/bsdef.h"

int main(int argc, char *argv[]) {
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
		&priv,
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

	STARTUPINFOA si = { 0 }; PROCESS_INFORMATION pi; DWORD e = 0;
	char *cmd, dir[1000]; size_t len = 0;
	GetCurrentDirectoryA(1000, dir);
	for (int i = 1; i < argc; i++) len += strlen(argv[i]);
	len += 1000 + argc;
	cmd = new char[len];
	RtlZeroMemory(cmd, sizeof(char)*len);

	ProcessIdToSessionId(GetCurrentProcessId(), &e);
	status = SeSetInformationToken(hToken, TokenSessionId, &e, sizeof(DWORD));
	if (!BS_SUCCESS(status)) {
		CloseHandle(hToken);
		return 0;
	}

	for (int i = 1; i < argc; i++) {
		bool add = false; int j = 0; char current;
		while (true) {
			current = *(argv[i] + j++);
			if (!current)break;
			if (current == ' ') {
				add = true; break;
			}
		}
		wsprintfA(cmd, add ? "%s\"%s\" " : "%s%s ", cmd, argv[i]);
	}

	status = PsCreateUserProcessA(hToken, nullptr, cmd, TRUE, 0, 0, dir, &si, &pi);
	if (BS_SUCCESS(status)) {
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
	return 0;
}
