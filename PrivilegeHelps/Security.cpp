#include "Security.h"
#include "Native.h"
#include "Process.h"
#pragma warning(disable:4838)
#pragma warning(disable:4996)

HANDLE hElvToken = nullptr;
DWORD  reference_count = 0;
LPCSTR PrivilegeNames[] = {
	"SeCreateTokenPrivilege",
	"SeAssignPrimaryTokenPrivilege",
	"SeLockMemoryPrivilege",
	"SeIncreaseQuotaPrivilege",
	"SeUnsolicitedInputPrivilege",
	"SeMachineAccountPrivilege",
	"SeTcbPrivilege",
	"SeSecurityPrivilege",
	"SeTakeOwnershipPrivilege",
	"SeLoadDriverPrivilege",
	"SeSystemProfilePrivilege",
	"SeSystemtimePrivilege",
	"SeProfileSingleProcessPrivilege",
	"SeIncreaseBasePriorityPrivilege",
	"SeCreatePagefilePrivilege",
	"SeCreatePermanentPrivilege",
	"SeBackupPrivilege",
	"SeRestorePrivilege",
	"SeShutdownPrivilege",
	"SeDebugPrivilege",
	"SeAuditPrivilege",
	"SeSystemEnvironmentPrivilege",
	"SeChangeNotifyPrivilege",
	"SeRemoteShutdownPrivilege",
	"SeUndockPrivilege",
	"SeSyncAgentPrivilege",
	"SeEnableDelegationPrivilege",
	"SeManageVolumePrivilege",
	"SeImpersonatePrivilege",
	"SeCreateGlobalPrivilege",
	"SeTrustedCredManAccessPrivilege",
	"SeRelabelPrivilege",
	"SeIncreaseWorkingSetPrivilege",
	"SeTimeZonePrivilege",
	"SeCreateSymbolicLinkPrivilege",
	"SeDelegateSessionUserImpersonatePrivilege"
};

BSTATUS BSAPI SepElevateCurrentThread() {
	if (!hElvToken)return BSTATUS_NOT_INITED;
	if (!reference_count && !ImpersonateLoggedOnUser(hElvToken)) return BSTATUS_UNSUCCESSFUL;
	reference_count++;
	return BSTATUS_SUCCESS;
}

BSTATUS BSAPI SepRevertToSelf() {
	if (!reference_count || !hElvToken)return BSTATUS_UNSUCCESSFUL;
	if (!--reference_count)RevertToSelf();
	return BSTATUS_SUCCESS;
}

BSTATUS BSAPI SeInitialDll() {
	if (hElvToken)return BSTATUS_SUCCESS;
	PSID sid1 = SeReferenceUserNameA("high mandatory level"),
		sid2 = SeReferenceUserNameA("system mandatory level");
	HANDLE hProcess;
	if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hProcess)) {
		delete[]sid1; delete[]sid2; return BSTATUS_UNSUCCESSFUL;
	}
	TOKEN_GROUPS *tg = nullptr; SeQueryInformationToken(hProcess, TokenGroups, &tg); DWORD attr;
	CloseHandle(hProcess);
	if (tg) {
		for (DWORD i = 0; i < tg->GroupCount; i++) {
			if (EqualSid(tg->Groups[i].Sid, sid1) || EqualSid(tg->Groups[i].Sid, sid2)) {
				attr = tg->Groups[i].Attributes;
				delete[]sid1; delete[]sid2; delete[]tg;
				return (attr & SE_GROUP_USE_FOR_DENY_ONLY) ? BSTATUS_ACCESS_DENIED : SepPrivilegeEscalation(&hElvToken);
			}
		}
		delete[]sid1; delete[]sid2; delete[]tg;
	}
	else {
		delete[]sid1; delete[]sid2;
	}
	return BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SeReleaseDll() {
	if (!hElvToken)return BSTATUS_NOT_INITED;
	CloseHandle(hElvToken); hElvToken = nullptr;
	return BSTATUS_SUCCESS;
}

BSTATUS BSAPI SepPrivilegeEscalation(PHANDLE _hToken) {
	if (IsBadWritePtr(_hToken, sizeof(HANDLE)))return BSTATUS_ACCESS_VIOLATION;
	DWORD dwLsaId = PsGetProcessId("lsass.exe");

	//以尽可能多的访问权限打开本地安全机构进程
	HANDLE hLsa = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwLsaId), hToken, hDup; if (!hLsa)return BSTATUS_ACCESS_DENIED;
	if (!OpenProcessToken(hLsa, MAXIMUM_ALLOWED, &hToken)) {
		CloseHandle(hLsa); return BSTATUS_ACCESS_DENIED;
	}

	//获得本地安全机构基础特权
	ImpersonateLoggedOnUser(hToken); CloseHandle(hLsa); CloseHandle(hToken);

	//以全部访问权限重新打开本地安全机构进程
	hLsa = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwLsaId);
	if (!hLsa) { RevertToSelf(); return BSTATUS_ACCESS_DENIED; }
	if (!OpenProcessToken(hLsa, TOKEN_ALL_ACCESS, &hToken)) {
		CloseHandle(hLsa); RevertToSelf(); return BSTATUS_ACCESS_DENIED;
	}
	CloseHandle(hLsa);

	//复制特权令牌为安全代理
	if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityDelegation, TokenImpersonation, &hDup)) {
		CloseHandle(hToken); RevertToSelf(); return BSTATUS_ACCESS_DENIED;
	}
	CloseHandle(hToken); RevertToSelf();

	//获得本地安全机构所有特权
	*_hToken = hDup;
	return BSTATUS_SUCCESS;
}

DWORD BSAPI SeQueryInformationToken(HANDLE hToken, TOKEN_INFORMATION_CLASS info, LPVOID mem) {
	if (IsBadWritePtr(mem, sizeof(LPVOID)))return BSTATUS_ACCESS_VIOLATION;
	BSTATUS status = SepElevateCurrentThread();
	DWORD len = 0; LPVOID lpMemory = nullptr; BOOL ret;
	GetTokenInformation(hToken, info, lpMemory, len, &len);
	if (!len) {
		if (BS_SUCCESS(status))SepRevertToSelf();
		return 0;
	}
	lpMemory = new char[len];
	ret = GetTokenInformation(hToken, info, lpMemory, len, &len);
	if (BS_SUCCESS(status))SepRevertToSelf();
	if (!ret) {
		delete[]lpMemory;
		return 0;
	}
	*(LPVOID*)mem = lpMemory;
	return len;
}

BSTATUS BSAPI SeSetInformationToken(HANDLE hToken, TOKEN_INFORMATION_CLASS info, LPVOID mem, DWORD memlen) {
	if (IsBadReadPtr(mem, memlen))return BSTATUS_ACCESS_VIOLATION;
	BSTATUS status = SepElevateCurrentThread();
	BOOL ret = SetTokenInformation(hToken, info, mem, memlen);
	if (BS_SUCCESS(status))SepRevertToSelf();
	return ret ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
}

PSID BSAPI SepReferenceUserNameExA(LPCSTR user, PSID_NAME_USE snu) {
	LPVOID sid = nullptr; DWORD len = 0; LPSTR str = nullptr; DWORD str_len = 0;
	LookupAccountNameA(nullptr, user, sid, &len, str, &str_len, snu); if (!len)return nullptr;
	sid = new char[len]; str = new char[str_len];
	if (!LookupAccountNameA(nullptr, user, sid, &len, str, &str_len, snu)) {
		delete[]sid; delete[]str; return nullptr;
	}
	delete[]str; return sid;
}

PSID BSAPI SeReferenceUserNameA(LPCSTR user) {
	SID_NAME_USE snu;
	return SepReferenceUserNameExA(user, &snu);
}

LPSTR BSAPI SepReferenceSidExA(PSID sid, PSID_NAME_USE snu) {
	LPSTR user = nullptr; DWORD len1 = 0, len2 = 0;
	LookupAccountSidA(nullptr, sid, user + len2, &len1, user, &len2, snu);
	if (len1 == 0 || len2 == 0)return nullptr;
	user = new char[len1 + len2];
	if (!LookupAccountSidA(nullptr, sid, user + len2, &len1, user, &len2, snu)) {
		delete[]user; return nullptr;
	}
	user[len2] = '\\'; return user;
}

LPSTR BSAPI SeReferenceSidA(PSID sid) {
	SID_NAME_USE snu;
	return SepReferenceSidExA(sid, &snu);
}

BSTATUS BSAPI SeCreateUserTokenExA(
	PHANDLE			TokenHandle,
	DWORD			dwFlags,
	TOKEN_TYPE		TokenType,
	AUTH_TYPE		AuthType,
	LUID			AuthId					OPTIONAL,
	LPCSTR			TokenUser,
	LPVOID			TokenGroup,
	LPVOID			TokenPrivileges,
	LPCSTR			TokenOwner,
	LPCSTR			TokenPrimaryGroup,
	PTOKEN_SOURCE	TokenSource				OPTIONAL,
	PTOKEN_DEFAULT_DACL	TokenDefaultDacl	OPTIONAL,
	SECURITY_IMPERSONATION_LEVEL SecurityImpersonationLevel) {
	TOKEN_USER tu = { 0 }; TOKEN_GROUPS *tg = nullptr; TOKEN_PRIVILEGES *tp = nullptr;
	TOKEN_OWNER to = { 0 }; TOKEN_PRIMARY_GROUP tpg = { 0 }; TOKEN_SOURCE ts = { '*', 'B','o','r','i','n','g','*' };
	LUID auth_id; LARGE_INTEGER exp = { 0xefffffff,0xffffffff }; SECURITY_DESCRIPTOR sd;
	SECURITY_QUALITY_OF_SERVICE sqos = { 0 }; OBJECT_ATTRIBUTES obj; TOKEN_DEFAULT_DACL tdd = { 0 };

	
	if (((dwFlags&SE_CREATE_USE_GROUPS) && (dwFlags&SE_CREATE_USE_TOKEN_GROUPS)) ||
		(!(dwFlags&SE_CREATE_USE_GROUPS) && !(dwFlags&SE_CREATE_USE_TOKEN_GROUPS)) ||
		((dwFlags&SE_CREATE_USE_TOKEN_PRIVILEGES) && (dwFlags&SE_CREATE_USE_PRIVILEGES_VALUE)) ||
		(!(dwFlags&SE_CREATE_USE_TOKEN_PRIVILEGES) && !(dwFlags&SE_CREATE_USE_PRIVILEGES_VALUE)))
		return BSTATUS_INVALID_PARAMETER;
	//if (dwFlags&SE_CREATE_DISABLE_ALL_PRIVILEGES)TokenPrivileges |= SE_DISABLE_PRIVILEGE_VALUE;
	if (!BS_SUCCESS(SepElevateCurrentThread()))return BSTATUS_NOT_INITED;

	switch (AuthType) {
	case	System:auth_id = SYSTEM_LUID; break;
	case	LocalService:auth_id = LOCALSERVICE_LUID; break;
	case	AnonymousLogon:auth_id = ANONYMOUS_LOGON_LUID; break;
	case	Other:auth_id = AuthId; break;
	default:
		SepRevertToSelf();
		return BSTATUS_INVALID_PARAMETER;
	}
	if (IsBadWritePtr(TokenHandle, sizeof(HANDLE)) ||
		IsBadReadPtr(TokenUser, sizeof(LPCSTR)) ||
		IsBadReadPtr(TokenGroup, sizeof(LPVOID)) ||
		IsBadReadPtr(TokenGroup, (*(DWORD*)TokenGroup) * (dwFlags&SE_CREATE_USE_GROUPS ?
			sizeof(USER_NAME_AND_ATTRIBUTESA) : sizeof(SID_AND_ATTRIBUTES)) + sizeof(DWORD)) ||
		IsBadReadPtr(TokenOwner, sizeof(LPCSTR)) ||
		((dwFlags&SE_CREATE_USE_TOKEN_SOURCE) && IsBadReadPtr(TokenSource, sizeof(TOKEN_SOURCE))) ||
		IsBadReadPtr(TokenPrimaryGroup, sizeof(LPCSTR)) ||
		IsBadReadPtr(TokenPrivileges, dwFlags&SE_CREATE_USE_PRIVILEGES_VALUE ?
			sizeof(PRIVILEGE_VALUE) : *(DWORD*)TokenPrivileges * sizeof(LUID_AND_ATTRIBUTES) + sizeof(DWORD)) ||
		IsBadWritePtr(TokenPrivileges, dwFlags&SE_CREATE_USE_PRIVILEGES_VALUE ?
			sizeof(PRIVILEGE_VALUE) : *(DWORD*)TokenPrivileges * sizeof(LUID_AND_ATTRIBUTES) + sizeof(DWORD))) {
		SepRevertToSelf();
		return BSTATUS_ACCESS_VIOLATION;
	}

	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	sqos.ImpersonationLevel = SecurityImpersonationLevel;
	sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
	InitializeObjectAttributes(&obj, nullptr, OBJ_INHERIT, nullptr, nullptr);
	obj.SecurityQualityOfService = &sqos;
	obj.SecurityDescriptor = &sd;
	AllocateLocallyUniqueId(&ts.SourceIdentifier);

	try {
		tu.User.Attributes = SE_GROUP_ENABLED;
		tu.User.Sid = SeReferenceUserNameA(TokenUser);
		if (!tu.User.Sid)throw BSTATUS_INVALID_USER_NAME;
		to.Owner = SeReferenceUserNameA(TokenOwner);
		if (!to.Owner)throw BSTATUS_INVALID_USER_NAME;
		tpg.PrimaryGroup = SeReferenceUserNameA(TokenPrimaryGroup);
		if (!tpg.PrimaryGroup)throw BSTATUS_INVALID_USER_NAME;
		if (dwFlags&SE_CREATE_USE_GROUPS) {
			DWORD dwLength = PGROUPS(TokenGroup)->dwUserNamesAndAttributesCount * sizeof(SID_AND_ATTRIBUTES) + sizeof(DWORD);
			tg = (TOKEN_GROUPS*)new char[dwLength];
			tg->GroupCount = PGROUPS(TokenGroup)->dwUserNamesAndAttributesCount;
			BSTATUS status = RtlGroupsToTokenGroupsA(PGROUPS(TokenGroup), tg, &dwLength);
			if (!BS_SUCCESS(status))throw status;
		}
		else tg = (PTOKEN_GROUPS)TokenGroup;
		if (dwFlags&SE_CREATE_USE_PRIVILEGES_VALUE) {
			if (dwFlags&SE_CREATE_DISABLE_ALL_PRIVILEGES)*(PRIVILEGE_VALUE*)TokenPrivileges |= SE_DISABLE_PRIVILEGE_VALUE;
			BYTE list[PRIVILEGE_COUNT] = { 0 }; DWORD count = 0;
			for (LONGLONG i = 0x000000001, j = 0; i <= 0x800000000; i <<= 1, j++)
				if (*(PRIVILEGE_VALUE*)TokenPrivileges&i) { list[j] = 1; count++; }
			tp = (PTOKEN_PRIVILEGES)new char[(sizeof(DWORD) + sizeof(LUID_AND_ATTRIBUTES)*count)];
			tp->PrivilegeCount = count; count = *(PRIVILEGE_VALUE*)TokenPrivileges & SE_DISABLE_PRIVILEGE_VALUE ?
				SE_PRIVILEGE_REMOVED : SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED;
			for (DWORD i = 0, j = 0; i < PRIVILEGE_COUNT; i++) {
				if (list[i]) {
					if (!LookupPrivilegeValueA(nullptr, PrivilegeNames[i], &tp->Privileges[j].Luid)) { tp->PrivilegeCount--; continue; }
					tp->Privileges[j++].Attributes = count;
				}
			}
		}
		else {
			tp = (TOKEN_PRIVILEGES*)TokenPrivileges;
			if (dwFlags&SE_CREATE_DISABLE_ALL_PRIVILEGES) {
				for (DWORD i = 0; i < tp->PrivilegeCount; i++)
					tp->Privileges[i].Attributes = SE_PRIVILEGE_REMOVED;
			}
		}
		
		//SetSecurityDescriptorGroup(&sd, tpg.PrimaryGroup, TRUE);
		//SetSecurityDescriptorOwner(&sd, to.Owner, TRUE);
	}
	catch (BSTATUS Exception) {
		if (tu.User.Sid)delete[]tu.User.Sid;
		if (tg && (dwFlags&SE_CREATE_USE_GROUPS)) {
			for (DWORD i = 0; i < tg->GroupCount; i++)
				if (tg->Groups[i].Sid)delete[]tg->Groups[i].Sid;
			delete[]tg;
		}
		if (tp)delete[]tp;
		if (to.Owner)delete[]to.Owner;
		if (tpg.PrimaryGroup)delete[]tpg.PrimaryGroup;
		SepRevertToSelf();
		return Exception;
	}

	NTSTATUS status = NtCreateToken(
		TokenHandle, TOKEN_ALL_ACCESS, &obj, TokenType,
		&auth_id, &exp, &tu, tg, tp, &to, &tpg,
		(dwFlags&SE_CREATE_USE_DACL) ? TokenDefaultDacl : &tdd,
		(dwFlags&SE_CREATE_USE_TOKEN_SOURCE) ? TokenSource : &ts);

	if (tu.User.Sid)delete[]tu.User.Sid;
	if (tg && (dwFlags&SE_CREATE_USE_GROUPS)) {
		for (DWORD i = 0; i < tg->GroupCount; i++)
			if (tg->Groups[i].Sid)delete[]tg->Groups[i].Sid;
		delete[]tg;
	}
	if (tp && (dwFlags&SE_CREATE_USE_PRIVILEGES_VALUE))delete[]tp;
	if (to.Owner)delete[]to.Owner;
	if (tpg.PrimaryGroup)delete[]tpg.PrimaryGroup;

	//if (NT_SUCCESS(status)) {
	//	HANDLE hDup;
	//	status = NtDuplicateToken(*TokenHandle, TOKEN_ALL_ACCESS, nullptr, false, TokenType, &hDup);
	//	CloseHandle(*TokenHandle);
	//	*TokenHandle = hDup;
	//}

	SepRevertToSelf();
	if (NT_SUCCESS(status))return BSTATUS_SUCCESS;
	SetLastError(RtlNtStatusToDosError(status));
	return BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SeCreateUserTokenA(
	PHANDLE			TokenHandle,
	AUTH_TYPE		AuthType,
	LUID			AuthId, OPTIONAL
	LPCSTR			TokenUser,
	PGROUPS			TokenGroup,
	PRIVILEGE_VALUE TokenPrivileges,
	LPCSTR			TokenPrimaryGroup) {
	return SeCreateUserTokenExA(
		TokenHandle, SE_CREATE_DEFAULT, TokenPrimary, AuthType,
		AuthId, TokenUser, TokenGroup, &TokenPrivileges,
		TokenUser, TokenPrimaryGroup, nullptr, nullptr, SecurityDelegation);
}

BSTATUS BSAPI SeEnablePrivilegesToken(IN OUT PHANDLE hToken, IN PRIVILEGE_VALUE EnablePrivileges) {
	if (!BS_SUCCESS(SepElevateCurrentThread()))return BSTATUS_NOT_INITED;
	if (EnablePrivileges&SE_DISABLE_PRIVILEGE_VALUE || !EnablePrivileges) {
		SepRevertToSelf();
		return BSTATUS_INVALID_PARAMETER;
	}
	if (IsBadReadPtr(hToken, sizeof(PHANDLE)) || IsBadWritePtr(hToken, sizeof(PHANDLE))) {
		SepRevertToSelf();
		return BSTATUS_ACCESS_VIOLATION;
	}

	TOKEN_USER *tu = nullptr; TOKEN_GROUPS* tg = nullptr; TOKEN_PRIVILEGES* tp;
	TOKEN_OWNER *to = nullptr; TOKEN_PRIMARY_GROUP* tpg = nullptr; TOKEN_SOURCE *ts = nullptr;
	TOKEN_STATISTICS *tss = nullptr; OBJECT_ATTRIBUTES obj; SECURITY_DESCRIPTOR sd;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);

	SECURITY_QUALITY_OF_SERVICE sqos = { 0 };
	sqos.ImpersonationLevel = SecurityDelegation;
	sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);

	InitializeObjectAttributes(&obj, nullptr, OBJ_INHERIT, nullptr, nullptr);
	obj.SecurityQualityOfService = &sqos;
	obj.SecurityDescriptor = &sd;

	if (
		!SeQueryInformationToken(*hToken, TokenUser, &tu) ||
		!SeQueryInformationToken(*hToken, TokenGroups, &tg) ||
		!SeQueryInformationToken(*hToken, TokenOwner, &to) ||
		!SeQueryInformationToken(*hToken, TokenSource, &ts) ||
		!SeQueryInformationToken(*hToken, TokenStatistics, &tss) ||
		!SeQueryInformationToken(*hToken, TokenPrimaryGroup, &tpg)) {
		if (tu)delete[]tu;
		if (tg)delete[]tg;
		if (to)delete[]to;
		if (ts)delete[]ts;
		if (tss)delete[]tss;
		if (tpg)delete[]tpg;
		return BSTATUS_UNSUCCESSFUL;
	}

	SetSecurityDescriptorGroup(&sd, tu->User.Sid, TRUE);
	SetSecurityDescriptorOwner(&sd, tu->User.Sid, TRUE);

	BYTE list[PRIVILEGE_COUNT] = { 0 }; BYTE count = 0;
	for (LONGLONG i = 0x000000001, j = 0; i <= 0x800000000; i <<= 1, j++)
		if (EnablePrivileges&i) { list[j] = 1; count++; }
	tp = (PTOKEN_PRIVILEGES)new char[sizeof(DWORD) + sizeof(LUID_AND_ATTRIBUTES)*count];
	tp->PrivilegeCount = count;
	for (DWORD i = 0, j = 0; i < PRIVILEGE_COUNT; i++) {
		if (list[i]) {
			if (!LookupPrivilegeValueA(nullptr, PrivilegeNames[i], &tp->Privileges[j].Luid)) {
				tp->PrivilegeCount--; continue;
			}
			tp->Privileges[j++].Attributes = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED;
		}
	}
	NTSTATUS status = NtCreateToken(hToken, TOKEN_ALL_ACCESS, &obj, tss->TokenType,
		&tss->AuthenticationId, &tss->ExpirationTime, tu, tg, tp, to, tpg, nullptr, ts);
	delete[]tu; delete[]tp; delete[]tg; delete[]tpg; delete[]ts; delete[]tss; delete[]to;
	SepRevertToSelf();
	if (NT_SUCCESS(status))return BSTATUS_SUCCESS;
	SetLastError(RtlNtStatusToDosError(status));
	return BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SePrivilegeEscalationThread(DWORD dwThreadId, HANDLE hToken) {
	if (!BS_SUCCESS(SepElevateCurrentThread()))return BSTATUS_NOT_INITED;
	HANDLE hThread = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwThreadId);
	if (hThread <= 0) {
		SepRevertToSelf();
		return BSTATUS_UNSUCCESSFUL;
	}
	if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, SecurityDelegation, TokenPrimary, &hToken)) {
		CloseHandle(hThread);
		SepRevertToSelf();
		return BSTATUS_ACCESS_DENIED;
	}
	if (!DuplicateHandle(GetCurrentProcess(), hToken, hThread, nullptr, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES)) {
		CloseHandle(hToken); CloseHandle(hThread);
		SepRevertToSelf();
		return BSTATUS_ACCESS_DENIED;
	}
	CloseHandle(hToken); CloseHandle(hThread);
	SepRevertToSelf();
	return BSTATUS_SUCCESS;
}


BSTATUS BSAPI SeEnumLogonSessionsLuid(IN PDWORD count, OUT PLUID list, IN OUT PDWORD size) {
	if (IsBadWritePtr(count, sizeof(DWORD)) ||
		IsBadReadPtr(size, sizeof(DWORD)) || IsBadWritePtr(size, sizeof(DWORD)))
		return BSTATUS_ACCESS_VIOLATION;
	PLUID tmp; DWORD length;
	if (!NT_SUCCESS(LsaEnumerateLogonSessions(count, &tmp)))
		return BSTATUS_UNSUCCESSFUL;
	length = sizeof(LUID)*(*count);
	if (!*size) {
		LsaFreeReturnBuffer(tmp);
		*size = length; return BSTATUS_SUCCESS;
	}
	if (*size && (*size < length)) {
		LsaFreeReturnBuffer(tmp);
		*size = length; return BSTATUS_BUFFER_TOO_SMALL;
	}
	if (IsBadWritePtr(list, length)) {
		LsaFreeReturnBuffer(tmp);
		return BSTATUS_ACCESS_VIOLATION;
	}
	RtlCopyMemory(list, tmp, length);
	LsaFreeReturnBuffer(tmp);
	return BSTATUS_SUCCESS;
}

BSTATUS BSAPI SeQueryLogonSessionInformation(IN PLUID luid, OUT PLOGON_SESSION_DATA *_data) {
	if (IsBadReadPtr(luid, sizeof(LUID)) ||
		IsBadWritePtr(_data, sizeof(DWORD)))
		return BSTATUS_ACCESS_VIOLATION;
	PSECURITY_LOGON_SESSION_DATA data;
	if (!NT_SUCCESS(LsaGetLogonSessionData(luid, &data)))
		return BSTATUS_UNSUCCESSFUL;
	(*(PSECURITY_LOGON_SESSION_DATA*)_data) = data;
	return BSTATUS_SUCCESS;
}

BSTATUS BSAPI SeFreeLogonSessionData(PLOGON_SESSION_DATA block) {
	return NT_SUCCESS(LsaFreeReturnBuffer(block)) ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
}


BSTATUS BSAPI SeReferenceProcessPrimaryToken(IN DWORD dwProcessId, OUT PHANDLE hToken) {
	if (!BS_SUCCESS(SepElevateCurrentThread()))return BSTATUS_NOT_INITED;
	if (IsBadWritePtr(hToken, sizeof(HANDLE))) {
		SepRevertToSelf();
		return BSTATUS_ACCESS_VIOLATION;
	}
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (!hProcess) {
		SepRevertToSelf();
		return BSTATUS_UNSUCCESSFUL;
	}
	BOOL status = OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, hToken);
	CloseHandle(hProcess); SepRevertToSelf();
	return status ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SeReferenceThreadToken(IN DWORD dwThreadId, OUT PHANDLE hToken) {
	if (!BS_SUCCESS(SepElevateCurrentThread()))return BSTATUS_NOT_INITED;
	if (IsBadWritePtr(hToken, sizeof(HANDLE))) {
		SepRevertToSelf();
		return BSTATUS_ACCESS_VIOLATION;
	}
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
	if (!hThread) {
		SepRevertToSelf();
		return BSTATUS_UNSUCCESSFUL;
	}
	BOOL status = OpenThreadToken(hThread, TOKEN_ALL_ACCESS, FALSE, hToken);
	CloseHandle(hThread); SepRevertToSelf();
	return status ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SeReferenceProcess(IN DWORD dwProcessId, OUT PHANDLE hProcess) {
	if (!BS_SUCCESS(SepElevateCurrentThread()))return BSTATUS_NOT_INITED;
	if (IsBadWritePtr(hProcess, sizeof(HANDLE))) {
		SepRevertToSelf();
		return BSTATUS_ACCESS_VIOLATION;
	}
	*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	SepRevertToSelf();
	return *hProcess ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SeReferenceThread(IN DWORD dwThreadId, OUT PHANDLE hThread) {
	if (!BS_SUCCESS(SepElevateCurrentThread()))return BSTATUS_NOT_INITED;
	if (IsBadWritePtr(hThread, sizeof(HANDLE))) {
		SepRevertToSelf();
		return BSTATUS_ACCESS_VIOLATION;
	}
	*hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
	SepRevertToSelf();
	return *hThread ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SeReferenceEscalationToken(OUT PHANDLE hToken) {
	if (!hElvToken)return BSTATUS_NOT_INITED;
	if (IsBadWritePtr(hToken, sizeof(HANDLE)))return BSTATUS_ACCESS_VIOLATION;
	NTSTATUS status = NtDuplicateObject(GetCurrentProcess(), hElvToken, GetCurrentProcess(), hToken, 0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES);
	if (NT_SUCCESS(status)) return BSTATUS_SUCCESS;
	SetLastError(RtlNtStatusToDosError(status));
	return BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SeDereferenceEscalationToken(IN HANDLE hToken) {
	return CloseHandle(hToken) ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SeFreeAllocate(LPVOID _block) {
	delete[]_block;
	return BSTATUS_SUCCESS;
}

BSTATUS BSAPI SeSingleGroupsAddNameA(
	IN LPCSTR MemberName,
	IN DWORD Attributes,
	IN PGROUPS Source,
	OUT PGROUPS Destination,
	IN OUT PDWORD BufferSize) {
	PSID sid = SeReferenceUserNameA(MemberName);
	if (!sid)return BSTATUS_INVALID_USER_NAME;
	BSTATUS status = SeSingleGroupsAddSid(sid, Attributes, Source, Destination, BufferSize);
	delete[]sid;
	return status;
}

BSTATUS BSAPI SeSingleGroupsAddSid(
	IN PSID MemberSid,
	IN DWORD Attributes,
	IN PGROUPS Source,
	OUT PGROUPS Destination,
	IN OUT PDWORD BufferSize) {
#define TG_CURRENT_USER Source->NamesAndAttributes[i]
#define TG_DEST_END_USER Destination->NamesAndAttributes[dwGroupsCount - 1]
	if (IsBadReadPtr(Source, sizeof(DWORD)) ||
		IsBadReadPtr(Source, Source->dwUserNamesAndAttributesCount * sizeof(USER_NAME_AND_ATTRIBUTESA) + sizeof(DWORD)) ||
		IsBadReadPtr(BufferSize, sizeof(DWORD)) || IsBadWritePtr(BufferSize, sizeof(DWORD)))
		return BSTATUS_ACCESS_VIOLATION;
	
	DWORD dwGroupsCount = Source->dwUserNamesAndAttributesCount + 1,
		dwBufferSize = dwGroupsCount * sizeof(USER_NAME_AND_ATTRIBUTESA) + sizeof(DWORD),
		dwSamePoint = -1;
	for (DWORD i = 0; i < Source->dwUserNamesAndAttributesCount; i++) {
		PSID sid = nullptr;
		if (TG_CURRENT_USER.IsSid) {
			PSID tmp; DWORD len;
			if (ConvertStringSidToSidA(TG_CURRENT_USER.UserName, &tmp)) {
				len = GetLengthSid(tmp);
				sid = (PSID)new char[len];
				RtlCopyMemory(sid, tmp, len);
				LocalFree(tmp);
			}
			else continue;
		}
		else {
			sid = SeReferenceUserNameA(Source->NamesAndAttributes[i].UserName);
			if (!sid)continue;
		}

		if (EqualSid(MemberSid, sid)) {
			dwBufferSize -= sizeof(USER_NAME_AND_ATTRIBUTESA);
			dwGroupsCount--;
			dwSamePoint = i;
			delete[]sid;
			break;
		}
		delete[]sid;
	}
	if (!*BufferSize) {
		*BufferSize = dwBufferSize;
		return BSTATUS_SUCCESS;
	}
	if (*BufferSize < dwBufferSize) {
		*BufferSize = dwBufferSize;
		return BSTATUS_BUFFER_TOO_SMALL;
	}
	if (IsBadWritePtr(Destination, dwBufferSize)) {
		return BSTATUS_ACCESS_VIOLATION;
	}

	if (dwSamePoint != -1) {
		if ((DWORD64)Source == (DWORD64)Destination) {
			Source->NamesAndAttributes[dwSamePoint].Attributes = Attributes;
			return BSTATUS_SUCCESS;
		}
		RtlCopyMemory(Destination, Source, dwBufferSize);
		Destination->NamesAndAttributes[dwSamePoint].Attributes = Attributes;
		return BSTATUS_SUCCESS;
	}

	LPSTR tmp; SID_NAME_USE snu;
	RtlCopyMemory(Destination, Source, dwBufferSize - sizeof(USER_NAME_AND_ATTRIBUTESA));
	Destination->dwUserNamesAndAttributesCount = dwGroupsCount;
	TG_DEST_END_USER.Attributes = Attributes;
	TG_DEST_END_USER.UserName = SepReferenceSidExA(MemberSid, &snu);
	TG_DEST_END_USER.IsSid = (snu == SidTypeLogonSession ? 1 : 0);

	if (TG_DEST_END_USER.IsSid || !TG_DEST_END_USER.UserName) {

		if (!TG_DEST_END_USER.IsSid)
			TG_DEST_END_USER.IsSid = 1;
		if (TG_DEST_END_USER.UserName)
			delete[]TG_DEST_END_USER.UserName;

		if (!ConvertSidToStringSidA(MemberSid, &tmp)) {
			RtlZeroMemory(Destination, dwBufferSize);
			return BSTATUS_INVALID_SID;
		}

		TG_DEST_END_USER.UserName = new char[strlen(tmp)];
		strcpy(TG_DEST_END_USER.UserName, tmp);
		LocalFree(tmp);
	}
	return BSTATUS_SUCCESS;

#undef TG_CURRENT_USER
#undef TG_DEST_END_USER
}

BSTATUS BSAPI SeSingleTokenGroupsAddNameA(
	IN LPCSTR MemberName,
	IN DWORD Attributes,
	IN PTOKEN_GROUPS Source,
	OUT PTOKEN_GROUPS Destination,
	IN OUT PDWORD BufferSize) {
	PSID sid = SeReferenceUserNameA(MemberName);
	if (!sid)return BSTATUS_INVALID_USER_NAME;
	BSTATUS status = SeSingleTokenGroupsAddSid(sid, Attributes, Source, Destination, BufferSize);
	delete[]sid;
	return status;
}

BSTATUS BSAPI SeSingleTokenGroupsAddSid(
	IN PSID MemberSid,
	IN DWORD Attributes,
	IN PTOKEN_GROUPS Source,
	OUT PTOKEN_GROUPS Destination,
	IN OUT PDWORD BufferSize) {
	PGROUPS t_groups = nullptr, t_result = nullptr; DWORD dwBufferSize = 0;
	BSTATUS status = RtlTokenGroupsToGroupsA(Source, t_groups, &dwBufferSize);
	if (!BS_SUCCESS(status))return status;
	t_groups = (PGROUPS)new char[dwBufferSize];
	status = RtlTokenGroupsToGroupsA(Source, t_groups, &dwBufferSize);
	if (!BS_SUCCESS(status)){
		delete[]t_groups;
		return status;
	}
	dwBufferSize = 0;
	status = SeSingleGroupsAddSid(MemberSid, Attributes, t_groups, t_result, &dwBufferSize);
	if (!BS_SUCCESS(status)) {
		delete[]t_groups;
		return status;
	}
	t_result = (PGROUPS)new char[dwBufferSize];
	status = SeSingleGroupsAddSid(MemberSid, Attributes, t_groups, t_result, &dwBufferSize);
	if (!BS_SUCCESS(status)) {
		delete[]t_groups;
		delete[]t_result;
		return status;
	}
	delete[]t_groups;
	status = RtlGroupsToTokenGroupsA(t_result, Destination, BufferSize);
	delete[]t_result;
	return status;
}
