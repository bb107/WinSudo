#include "Security.h"
#include "Native.h"
#include "Process.h"
#pragma warning(disable:4838)

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

BSTATUS BSAPI SeInitialDll() {
	if (hElvToken)return BSTATUS_SUCCESS;
	PSID sid1 = SeReferenceUserNameA("high mandatory level"),
		sid2 = SeReferenceUserNameA("system mandatory level");
	HANDLE hProcess;
	if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hProcess)) {
		delete[]sid1; delete[]sid2; return BSTATUS_UNSUCCESSFUL;
	}
	TOKEN_GROUPS *tg; SeQueryInformationToken(hProcess, TokenGroups, &tg); DWORD attr;
	CloseHandle(hProcess);
	for (DWORD i = 0; i < tg->GroupCount; i++) {
		if (EqualSid(tg->Groups[i].Sid, sid1) || EqualSid(tg->Groups[i].Sid, sid2)) {
			attr = tg->Groups[i].Attributes;
			delete[]sid1; delete[]sid2; delete[]tg;
			return (attr & SE_GROUP_USE_FOR_DENY_ONLY) ? BSTATUS_ACCESS_DENIED : SePrivilegeEscalation(&hElvToken);
		}
	}
	delete[]sid1; delete[]sid2; delete[]tg;
	return BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SeReleaseDll() {
	if (!hElvToken)return BSTATUS_NOT_INITED;
	CloseHandle(hElvToken); hElvToken = nullptr;
	return BSTATUS_SUCCESS;
}

BSTATUS SePrivilegeEscalation(PHANDLE _hToken) {
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
	DWORD len = 0; LPVOID lpMemory = nullptr;
	GetTokenInformation(hToken, info, lpMemory, len, &len); if (!len)return 0;
	lpMemory = new char[len];
	if (!GetTokenInformation(hToken, info, lpMemory, len, &len)) {
		delete[]lpMemory; return 0;
	}
	*(LPVOID*)mem = lpMemory; return len;
}

BSTATUS BSAPI SeSetInformationToken(HANDLE hToken, TOKEN_INFORMATION_CLASS info, LPVOID mem, DWORD memlen) {
	if (IsBadReadPtr(mem, memlen))return BSTATUS_ACCESS_VIOLATION;
	return SetTokenInformation(hToken, info, mem, memlen) ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
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
	PRIVILEGE_VALUE TokenPrivileges,
	LPCSTR			TokenOwner,
	LPCSTR			TokenPrimaryGroup,
	PTOKEN_SOURCE	TokenSource				OPTIONAL,
	PTOKEN_DEFAULT_DACL	TokenDefaultDacl	OPTIONAL,
	SECURITY_IMPERSONATION_LEVEL SecurityImpersonationLevel) {
	TOKEN_USER tu = { 0 }; TOKEN_GROUPS *tg = nullptr; TOKEN_PRIVILEGES *tp = nullptr;
	TOKEN_OWNER to = { 0 }; TOKEN_PRIMARY_GROUP tpg = { 0 }; TOKEN_SOURCE ts = { '*', 'B','o','r','i','n','g','*' };
	LUID auth_id; LARGE_INTEGER exp = { 0xefffffff,0xffffffff }; SECURITY_DESCRIPTOR sd;
	SECURITY_QUALITY_OF_SERVICE sqos = { 0 }; OBJECT_ATTRIBUTES obj; TOKEN_DEFAULT_DACL tdd = { 0 };

	if (!hElvToken)return BSTATUS_NOT_INITED;
	if (((dwFlags&SE_CREATE_USE_GROUPS) && (dwFlags&SE_CREATE_USE_TOKEN_GROUPS)) ||
		(!(dwFlags&SE_CREATE_USE_GROUPS) && !(dwFlags&SE_CREATE_USE_TOKEN_GROUPS)))
		return BSTATUS_INVALID_PARAMETER;
	if (dwFlags&SE_CREATE_DISABLE_ALL_PRIVILEGES)TokenPrivileges |= SE_DISABLE_PRIVILEGE_VALUE;
	if (!reference_count && !ImpersonateLoggedOnUser(hElvToken)) return BSTATUS_UNSUCCESSFUL;
	reference_count++;

	switch (AuthType) {
	case	System:auth_id = SYSTEM_LUID; break;
	case	LocalService:auth_id = LOCALSERVICE_LUID; break;
	case	AnonymousLogon:auth_id = ANONYMOUS_LOGON_LUID; break;
	case	Other:auth_id = AuthId; break;
	default:
		if (!--reference_count)RevertToSelf();
		return BSTATUS_INVALID_PARAMETER;
	}
	if (IsBadWritePtr(TokenHandle, sizeof(HANDLE)) ||
		IsBadReadPtr(TokenUser, sizeof(LPCSTR)) ||
		IsBadReadPtr(TokenGroup, sizeof(LPVOID)) ||
		IsBadReadPtr(TokenGroup, (*(DWORD*)TokenGroup) * (dwFlags&SE_CREATE_USE_GROUPS ?
			sizeof(USER_NAME_AND_ATTRIBUTESA) : sizeof(SID_AND_ATTRIBUTES)) + sizeof(DWORD)) ||
		IsBadReadPtr(TokenOwner, sizeof(LPCSTR)) ||
		((dwFlags&SE_CREATE_USE_TOKEN_SOURCE) && IsBadReadPtr(TokenSource, sizeof(TOKEN_SOURCE))) ||
		IsBadReadPtr(TokenPrimaryGroup, sizeof(LPCSTR))) {
		if (!--reference_count)RevertToSelf();
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
		if (dwFlags&SE_CREATE_USE_PRIVILEGES) {
			BYTE list[PRIVILEGE_COUNT] = { 0 }; DWORD count = 0;
			for (LONGLONG i = 0x000000001, j = 0; i <= 0x800000000; i <<= 1, j++)
				if (TokenPrivileges&i) { list[j] = 1; count++; }
			tp = (PTOKEN_PRIVILEGES)new char[(sizeof(DWORD) + sizeof(LUID_AND_ATTRIBUTES)*count)];
			tp->PrivilegeCount = count; count = TokenPrivileges & SE_DISABLE_PRIVILEGE_VALUE ?
				SE_PRIVILEGE_REMOVED : SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED;
			for (DWORD i = 0, j = 0; i < PRIVILEGE_COUNT; i++) {
				if (list[i]) {
					if (!LookupPrivilegeValueA(nullptr, PrivilegeNames[i], &tp->Privileges[j].Luid)) { tp->PrivilegeCount--; continue; }
					tp->Privileges[j++].Attributes = count;
				}
			}
		}
		else {
			tp = new TOKEN_PRIVILEGES; RtlZeroMemory(tp, sizeof(TOKEN_PRIVILEGES));
		}
		SetSecurityDescriptorGroup(&sd, tpg.PrimaryGroup, TRUE);
		SetSecurityDescriptorOwner(&sd, tu.User.Sid, TRUE);
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
		if (!--reference_count)RevertToSelf();
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
	if (tp)delete[]tp;
	if (to.Owner)delete[]to.Owner;
	if (tpg.PrimaryGroup)delete[]tpg.PrimaryGroup;

	//if (NT_SUCCESS(status)) {
	//	HANDLE hDup;
	//	status = NtDuplicateToken(*TokenHandle, TOKEN_ALL_ACCESS, nullptr, false, TokenType, &hDup);
	//	CloseHandle(*TokenHandle);
	//	*TokenHandle = hDup;
	//}

	if (!--reference_count)RevertToSelf();
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
		AuthId, TokenUser, TokenGroup, TokenPrivileges,
		TokenUser, TokenPrimaryGroup, nullptr, nullptr, SecurityDelegation);
}

BSTATUS BSAPI SeEnablePrivilegesToken(IN OUT PHANDLE hToken, IN PRIVILEGE_VALUE EnablePrivileges) {
	if (!hElvToken)return BSTATUS_NOT_INITED;
	if (!reference_count && !ImpersonateLoggedOnUser(hElvToken)) return BSTATUS_UNSUCCESSFUL;
	reference_count++;
	if (EnablePrivileges&SE_DISABLE_PRIVILEGE_VALUE || !EnablePrivileges) {
		if (!--reference_count)RevertToSelf();
		return BSTATUS_INVALID_PARAMETER;
	}
	if (IsBadReadPtr(hToken, sizeof(PHANDLE)) || IsBadWritePtr(hToken, sizeof(PHANDLE))) {
		if (!--reference_count)RevertToSelf();
		return BSTATUS_ACCESS_VIOLATION;
	}

	TOKEN_USER *tu; TOKEN_GROUPS* tg; TOKEN_PRIVILEGES* tp;
	TOKEN_OWNER *to; TOKEN_PRIMARY_GROUP* tpg; TOKEN_SOURCE *ts;
	TOKEN_STATISTICS *tss; OBJECT_ATTRIBUTES obj; SECURITY_DESCRIPTOR sd;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);

	SECURITY_QUALITY_OF_SERVICE sqos = { 0 };
	sqos.ImpersonationLevel = SecurityDelegation;
	sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);

	InitializeObjectAttributes(&obj, nullptr, OBJ_INHERIT, nullptr, nullptr);
	obj.SecurityQualityOfService = &sqos;
	obj.SecurityDescriptor = &sd;
	SeQueryInformationToken(*hToken, TokenUser, &tu);
	SeQueryInformationToken(*hToken, TokenGroups, &tg);
	SeQueryInformationToken(*hToken, TokenOwner, &to);
	SeQueryInformationToken(*hToken, TokenSource, &ts);
	SeQueryInformationToken(*hToken, TokenStatistics, &tss);
	SeQueryInformationToken(*hToken, TokenPrimaryGroup, &tpg);
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
	TOKEN_ELEVATION_TYPE e = TokenElevationTypeFull;
	SetTokenInformation(*hToken, TokenElevationType, &e, sizeof(TOKEN_ELEVATION_TYPE));
	if (!--reference_count)RevertToSelf();
	if (NT_SUCCESS(status))return BSTATUS_SUCCESS;
	SetLastError(RtlNtStatusToDosError(status));
	return BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SePrivilegeEscalationThread(DWORD dwThreadId, HANDLE hToken) {
	if (!hElvToken)return BSTATUS_NOT_INITED;
	if (!reference_count && !ImpersonateLoggedOnUser(hElvToken)) return BSTATUS_UNSUCCESSFUL;
	reference_count++;
	HANDLE hThread = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwThreadId);
	if (hThread <= 0) {
		if (!--reference_count)RevertToSelf();
		return BSTATUS_UNSUCCESSFUL;
	}
	if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, SecurityDelegation, TokenPrimary, &hToken)) {
		CloseHandle(hThread);
		if (!--reference_count)RevertToSelf();
		return BSTATUS_ACCESS_DENIED;
	}
	if (!DuplicateHandle(GetCurrentProcess(), hToken, hThread, nullptr, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES)) {
		CloseHandle(hToken); CloseHandle(hThread);
		if (!--reference_count)RevertToSelf();
		return BSTATUS_ACCESS_DENIED;
	}
	CloseHandle(hToken); CloseHandle(hThread);
	if (!--reference_count)RevertToSelf();
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
	(*(DWORD*)_data) = (DWORD)data;
	return BSTATUS_SUCCESS;
}

BSTATUS BSAPI SeFreeLogonSessionData(PLOGON_SESSION_DATA block) {
	return NT_SUCCESS(LsaFreeReturnBuffer(block)) ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
}


BSTATUS BSAPI SeReferenceProcessPrimaryToken(IN DWORD dwProcessId, OUT PHANDLE hToken) {
	if (!hElvToken)return BSTATUS_NOT_INITED;
	if (!reference_count && !ImpersonateLoggedOnUser(hElvToken)) return BSTATUS_UNSUCCESSFUL;
	reference_count++;
	if (IsBadWritePtr(hToken, sizeof(HANDLE))) {
		if (!--reference_count)RevertToSelf();
		return BSTATUS_ACCESS_VIOLATION;
	}
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (!hProcess) {
		if (!--reference_count)RevertToSelf();
		return BSTATUS_UNSUCCESSFUL;
	}
	BOOL status = OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, hToken);
	CloseHandle(hProcess); if (!--reference_count)RevertToSelf();
	return status ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SeReferenceThreadToken(IN DWORD dwThreadId, OUT PHANDLE hToken) {
	if (!hElvToken)return BSTATUS_NOT_INITED;
	if (!reference_count && !ImpersonateLoggedOnUser(hElvToken)) return BSTATUS_UNSUCCESSFUL;
	reference_count++;
	if (IsBadWritePtr(hToken, sizeof(HANDLE))) {
		if (!--reference_count)RevertToSelf();
		return BSTATUS_ACCESS_VIOLATION;
	}
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
	if (!hThread) {
		if (!--reference_count)RevertToSelf();
		return BSTATUS_UNSUCCESSFUL;
	}
	BOOL status = OpenThreadToken(hThread, TOKEN_ALL_ACCESS, FALSE, hToken);
	CloseHandle(hThread); if (!--reference_count)RevertToSelf();
	return status ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SeReferenceProcess(IN DWORD dwProcessId, OUT PHANDLE hProcess) {
	if (!hElvToken)return BSTATUS_NOT_INITED;
	if (!reference_count && !ImpersonateLoggedOnUser(hElvToken)) return BSTATUS_UNSUCCESSFUL;
	reference_count++;
	if (IsBadWritePtr(hProcess, sizeof(HANDLE))) {
		if (!--reference_count)RevertToSelf();
		return BSTATUS_ACCESS_VIOLATION;
	}
	*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (!--reference_count)RevertToSelf();
	return *hProcess ? BSTATUS_SUCCESS : BSTATUS_UNSUCCESSFUL;
}

BSTATUS BSAPI SeReferenceThread(IN DWORD dwThreadId, OUT PHANDLE hThread) {
	if (!hElvToken)return BSTATUS_NOT_INITED;
	if (!reference_count && !ImpersonateLoggedOnUser(hElvToken)) return BSTATUS_UNSUCCESSFUL;
	reference_count++;
	if (IsBadWritePtr(hThread, sizeof(HANDLE))) {
		if (!--reference_count)RevertToSelf();
		return BSTATUS_ACCESS_VIOLATION;
	}
	*hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
	if (!--reference_count)RevertToSelf();
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
