#undef UNICODE
#include <Windows.h>
#include <cstdio>
#include <vector>
#include "../PrivilegeHelps/bsdef.h"
#pragma warning(disable:4996)

LPCSTR usage = "\
usage: su [switchs] [options] [-c (program) (argvs...)]\n\
       switchs:\n\
           [-n NewConsoleWindow] [-e exit without wait subprocess] [-h show this text and exit]\n\
       options:\n\
           [-u user_name] [-o token_owner] [-p token_primary_group] [-P privilege_value] [-g (member_name) (attributes) (0|1 IsStringSid)]\n\
       user_name default is system.\n\
       token_owner default is administrators.\n\
       token_primary_group default is system.\n\
       privilege_value and token_groups default is current token privileges and groups.\n\
       program and argvs default is cmd.exe.\n\
       -g option is group member information and can be added multiple.\n\
       examples:\n\
           su\n\
           su -u administrator -o administrators -c cmd.exe\n\
           su -u system -c reg query HKLM\\SAM\\SAM\n\
           su -g \"system mandatory level\" 0x67 0 -g administrators 0xf 0 -g everyone 0x1 0 -g \"authenticated users\" 0x1 0 -g S-0-123-456 0x1 1 -P 0xfffffffff\n\
";

int main(int argc, char*argv[]) {
	BSTATUS status = SeInitialDll();
	if (!BS_SUCCESS(status)) {
		printf("su: permission denied.\n");
		return 1;
	}

	bool CreateNewConsole = false,
		WaitSubProcess = true;
	WORD start_of_program = -1;
	LPCSTR user_name = "system",
		token_owner = "administrators",
		token_primary_group = "system";
	PRIVILEGE_VALUE privilege_value = -1;
	LUID session = SYSTEM_LUID;
	DWORD dwSessionId;
	ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId);

	PTOKEN_GROUPS token_groups = nullptr;
	std::vector<int> list(0);

	int i = 1;
	while (i < argc) {
		if (!strcmp(argv[i], "-h")) {
			printf("%s", usage);
			return 0;
		}
		if (!strcmp(argv[i], "-n")) {
			CreateNewConsole = true;
			i++;
			continue;
		}
		if (!strcmp(argv[i], "-e")) {
			WaitSubProcess = false;
			i++;
			continue;
		}
		if (!strcmp(argv[i], "-c")) {
			start_of_program = i + 1;
			if (argc <= start_of_program) {
				printf("su: inalid parameter.\n%s", usage);
				return 2;
			}
			break;
		}
		if (!strcmp(argv[i], "-u")) {
			user_name = argv[i + 1];
			i += 2;
			continue;
		}
		if (!strcmp(argv[i], "-o")) {
			token_owner = argv[i + 1];
			i += 2;
			continue;
		}
		if (!strcmp(argv[i], "-p")) {
			token_primary_group = argv[i + 1];
			i += 2;
			continue;
		}
		if (!strcmp(argv[i], "-P")) {
			LPSTR t;
			privilege_value = strtoll(argv[i + 1], &t, 16);
			if (t == argv[i + 1]) {
				privilege_value = -1;
			}
			i += 2;
			continue;
		}
		if (!strcmp(argv[i], "-g")) {
			list.push_back(i + 1);
			i += 4;
			continue;
		}

		printf("su: inalid parameter.\n%s", usage);
		return -2;
	}

	//TOKEN_GROUPS and PRIVILEGE_VALUE
	HANDLE hToken;
	status = SeReferenceProcessPrimaryToken(GetCurrentProcessId(), &hToken);
	if (!BS_SUCCESS(status)) {
		printf("0x%08X|su: permission denied.\n", status);
		return 1;
	}
	LPVOID lpTokenInfo;
	if (privilege_value == -1) {
		if (!SeQueryInformationToken(hToken, TokenPrivileges, &lpTokenInfo)) {
			printf("0x%08X|su: permission denied.\n", GetLastError());
			CloseHandle(hToken);
			return 1;
		}
		status = RtlTokenPrivilegesToPrivilegeValue((PTOKEN_PRIVILEGES)lpTokenInfo, FALSE, &privilege_value);
		SeFreeAllocate(lpTokenInfo);
		if (!BS_SUCCESS(status)) {
			printf("0x%08X|su: permission denied.\n", status);
			return 1;
		}
	}
	if (list.empty()) {
		if (!SeQueryInformationToken(hToken, TokenGroups, &lpTokenInfo)) {
			printf("0x%08X|su: permission denied.\n", GetLastError());
			CloseHandle(hToken);
			return 1;
		}
		token_groups = (PTOKEN_GROUPS)lpTokenInfo;
	}
	else {
		DWORD dwLength = list.size() * sizeof(USER_NAME_AND_ATTRIBUTESA) + sizeof(DWORD);
		PGROUPS groups = (PGROUPS)new char[dwLength]; LPSTR t;
		RtlZeroMemory(groups, dwLength);
		groups->dwUserNamesAndAttributesCount = list.size();
		for (DWORD i = 0; i < groups->dwUserNamesAndAttributesCount; i++) {
			dwLength = list[i];
			groups->NamesAndAttributes[i].UserName = argv[dwLength];
			groups->NamesAndAttributes[i].Attributes = strtoul(argv[dwLength + 1], &t, 16);
			groups->NamesAndAttributes[i].IsSid = strtoul(argv[dwLength + 2], &t, 16);
		}
		dwLength = 0;
		status = RtlGroupsToTokenGroupsA(groups, token_groups, &dwLength);
		if (!BS_SUCCESS(status)) {
			printf("0x%08X|su: failed.\n", status);
			CloseHandle(hToken);
			delete[]groups;
			return 3;
		}
		token_groups = (PTOKEN_GROUPS)new char[dwLength];
		status = RtlGroupsToTokenGroupsA(groups, token_groups, &dwLength);
		delete[]groups;
		if (!BS_SUCCESS(status)) {
			printf("0x%08X|su: failed.\n", status);
			CloseHandle(hToken);
			delete[]groups;
			delete[]token_groups;
			return 3;
		}
	}
	CloseHandle(hToken);

	try {
		PSID user = SeReferenceUserNameA(user_name);
		DWORD count = 0, dwLength = 0; PLUID luid_list = nullptr;
		if (!user) {
			printf("su: invalid user name.\n");
			throw;
		}

		status = SeEnumLogonSessionsLuid(&count, luid_list, &dwLength);
		if (!BS_SUCCESS(status)) {
			printf("0x%08X|su: failed.\n", status);
			SeFreeAllocate(user);
			throw;
		}
		luid_list = new LUID[count + 1];
		status = SeEnumLogonSessionsLuid(&count, luid_list, &dwLength);
		if (!BS_SUCCESS(status)) {
			printf("0x%08X|su: failed.\n", status);
			SeFreeAllocate(user);
			delete[]luid_list;
			throw;
		}

		for (DWORD i = 0; i < count; i++) {
			PLOGON_SESSION_DATA lsd = nullptr;
			status = SeQueryLogonSessionInformation(luid_list + i, &lsd);
			if (!BS_SUCCESS(status))continue;
			if (!lsd->Size || !lsd->Sid) {
				SeFreeLogonSessionData(lsd);
				continue;
			}
			if (EqualSid(user, lsd->Sid)) {
				session = lsd->LogonId;
				SeFreeLogonSessionData(lsd);
				break;
			}
			SeFreeLogonSessionData(lsd);
		}
		SeFreeAllocate(user);
		delete[]luid_list;		
	}
	catch (...) {
		if (list.empty())SeFreeAllocate(token_groups);
		else delete[]token_groups;
	}

	status = SeCreateUserTokenExA(
		&hToken,
		SE_CREATE_USE_PRIVILEGES | SE_CREATE_USE_TOKEN_GROUPS,
		TokenPrimary,
		Other, session,
		user_name,
		token_groups,
		privilege_value,
		token_owner,
		token_primary_group,
		nullptr, nullptr,
		SecurityDelegation);
	if (list.empty())SeFreeAllocate(token_groups);
	else delete[]token_groups;
	if (!BS_SUCCESS(status)) {
		printf("0x%08X|su: failed.\n", status);
		return 4;
	}

	status = SeSetInformationToken(hToken, TokenSessionId, &dwSessionId, sizeof(DWORD));
	if (!BS_SUCCESS(status)) {
		printf("0x%08X|su: failed.\n", status);
		CloseHandle(hToken);
		return 4;
	}

	STARTUPINFOA si = { 0 }; PROCESS_INFORMATION pi;
	char *cmd, dir[1000]; DWORD len = 0;
	GetCurrentDirectoryA(1000, dir);

	if (start_of_program == WORD(-1)) {
		cmd = new char[10];
		strcpy(cmd, "cmd.exe");
	}
	else {
		for (int i = start_of_program; i < argc; i++) len += strlen(argv[i]);
		len += 1000 + argc;
		cmd = new char[len];
		RtlZeroMemory(cmd, sizeof(char)*len);
		for (int i = start_of_program; i < argc; i++) {
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
	}

	status = PsCreateUserProcessA(hToken, nullptr, cmd, TRUE, CreateNewConsole ? CREATE_NEW_CONSOLE : 0, GetEnvironmentStrings(), dir, &si, &pi);
	delete[]cmd;
	CloseHandle(hToken);

	if (BS_SUCCESS(status)) {
		if (WaitSubProcess) {
			do {
				WaitForSingleObject(pi.hProcess, 0xffff);
				GetExitCodeProcess(pi.hProcess, &len);
			} while (len == STILL_ACTIVE);
		}
	}
	else {
		printf("0x%08X|su: create process failed.\n", GetLastError());
	}

	return 0;
}
