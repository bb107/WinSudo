#include "Security.h"
#include <sddl.h>
#pragma warning(disable:4996)
#pragma warning(disable:4244)

bool operator==(LUID _left, LUID _right) {
	return (_left.HighPart == _right.HighPart) && (_left.LowPart == _right.LowPart);
}

BSTATUS BSAPI RtlTokenPrivilegesToPrivilegeValue(IN PTOKEN_PRIVILEGES tp, IN BOOL EnabledOnly, OUT PPRIVILEGE_VALUE privileges) {
	if (IsBadReadPtr(tp, sizeof(DWORD)) ||
		IsBadReadPtr(tp, sizeof(DWORD) + tp->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES))) {
		return BSTATUS_ACCESS_VIOLATION;
	}
	*privileges = SE_NO_PRIVILEGE_VALUE; DWORD count = 0;
	for (DWORD i = 0; i < PRIVILEGE_COUNT; i++) {
		LUID priv; LookupPrivilegeValueA(nullptr, PrivilegeNames[i], &priv);
		for (DWORD j = 0; j < tp->PrivilegeCount; j++) {
			if (priv == tp->Privileges[j].Luid) {
				count++;
				if (EnabledOnly ? tp->Privileges[j].Attributes&SE_PRIVILEGE_ENABLED : true)
					*privileges |= ((PRIVILEGE_VALUE)1 << i);
				break;
			}
		}
		if (count == tp->PrivilegeCount)break;
	}
	return BSTATUS_SUCCESS;
}

BSTATUS BSAPI RtlPrivilegeValueToTokenPrivileges(IN PRIVILEGE_VALUE privileges, OUT PTOKEN_PRIVILEGES tp, IN OUT PDWORD size) {
	if (IsBadReadPtr(size, sizeof(DWORD)))return BSTATUS_ACCESS_VIOLATION;
	BYTE list[PRIVILEGE_COUNT] = { 0 }; BYTE count = 0;
	for (LONGLONG i = 1, j = 0; i < 0x800000000; i <<= 1, j++) {
		if (privileges&i) { list[j] = 1; count++; }
	}
	DWORD dwBuffer = sizeof(DWORD) + count * sizeof(LUID_AND_ATTRIBUTES);
	if (*size && (*size < dwBuffer)) {
		*size = dwBuffer; return BSTATUS_BUFFER_TOO_SMALL;
	}
	if (!*size) {
		*size = dwBuffer; return BSTATUS_SUCCESS;
	}
	if (IsBadWritePtr(tp, dwBuffer)) {
		return BSTATUS_ACCESS_VIOLATION;
	}
	tp->PrivilegeCount = count;
	for (DWORD i = 0, j = 0; i < PRIVILEGE_COUNT; i++) {
		if (list[i]) {
			LUID luid; LookupPrivilegeValueA(nullptr, PrivilegeNames[i], &luid);
			tp->Privileges[j].Luid = luid;
			tp->Privileges[j++].Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
		}
	}
	*size = dwBuffer;
	return BSTATUS_SUCCESS;
}

BSTATUS BSAPI RtlTokenGroupsToGroupsA(IN PTOKEN_GROUPS tg, OUT PGROUPS groups, IN OUT PDWORD size) {
	if (IsBadReadPtr(tg, sizeof(DWORD)) ||
		IsBadReadPtr(tg, sizeof(DWORD) + tg->GroupCount * sizeof(SID_AND_ATTRIBUTES)) ||
		IsBadReadPtr(size, sizeof(DWORD)) || IsBadWritePtr(size, sizeof(DWORD)))
		return BSTATUS_ACCESS_VIOLATION;
	if ((LPVOID)tg == groups)return BSTATUS_INVALID_PARAMETER;
	DWORD dwLength = sizeof(DWORD) + tg->GroupCount * sizeof(USER_NAME_AND_ATTRIBUTESA);
	if (*size && (*size < dwLength)) {
		*size = dwLength; return BSTATUS_BUFFER_TOO_SMALL;
	}
	if (!*size) {
		*size = dwLength; return BSTATUS_SUCCESS;
	}
	if (IsBadWritePtr(groups, dwLength)) {
		return BSTATUS_ACCESS_VIOLATION;
	}
	*size = dwLength; RtlZeroMemory(groups, dwLength);
	groups->dwUserNamesAndAttributesCount = tg->GroupCount;
#define TG_CURRENT_USER groups->NamesAndAttributes[i]
	try {
		for (DWORD i = 0; i < tg->GroupCount; i++) {
			SID_NAME_USE snu; LPSTR sid;
			TG_CURRENT_USER.UserName = SepReferenceSidExA(tg->Groups[i].Sid, &snu);
			if (!TG_CURRENT_USER.UserName || snu == SidTypeLogonSession) {
				if (TG_CURRENT_USER.UserName) {
					delete[]TG_CURRENT_USER.UserName; TG_CURRENT_USER.UserName = nullptr;
				}
				if (!ConvertSidToStringSidA(tg->Groups[i].Sid, &sid)) throw 2;
				strcpy(TG_CURRENT_USER.UserName = new char[strlen(sid)], sid);
				LocalFree(sid); TG_CURRENT_USER.IsSid = 1;
			}
			TG_CURRENT_USER.Attributes = tg->Groups[i].Attributes;
		}
	}
	catch (...) {
		for (DWORD i = 0; i < tg->GroupCount; i++) {
			if (TG_CURRENT_USER.UserName)
				delete[]TG_CURRENT_USER.UserName;
		}
		return BSTATUS_INVALID_SID;
	}
#undef TG_CURRENT_USER
	return BSTATUS_SUCCESS;
}

BSTATUS BSAPI RtlGroupsToTokenGroupsA(IN PGROUPS groups, OUT PTOKEN_GROUPS tg, IN OUT PDWORD size) {
	if (IsBadReadPtr(groups, sizeof(DWORD)) ||
		IsBadReadPtr(groups, groups->dwUserNamesAndAttributesCount * sizeof(USER_NAME_AND_ATTRIBUTESA) + sizeof(DWORD)) ||
		IsBadReadPtr(size, sizeof(DWORD)) || IsBadWritePtr(size, sizeof(DWORD)))
		return BSTATUS_ACCESS_VIOLATION;
	if ((LPVOID)tg == groups)return BSTATUS_INVALID_PARAMETER;
	DWORD dwLength = sizeof(DWORD) + groups->dwUserNamesAndAttributesCount * sizeof(SID_AND_ATTRIBUTES);
	if (*size && (*size < dwLength)) {
		*size = dwLength; return BSTATUS_BUFFER_TOO_SMALL;
	}
	if (!*size) {
		*size = dwLength; return BSTATUS_SUCCESS;
	}
	if (IsBadWritePtr(tg, dwLength)) {
		return BSTATUS_ACCESS_VIOLATION;
	}
	*size = dwLength; RtlZeroMemory(tg, dwLength);
	tg->GroupCount = groups->dwUserNamesAndAttributesCount;
	try {
		for (DWORD i = 0; i < groups->dwUserNamesAndAttributesCount; i++) {
			if (groups->NamesAndAttributes[i].IsSid) {
				PSID sid; DWORD len = 0;
				if (!ConvertStringSidToSidA(groups->NamesAndAttributes[i].UserName, &sid))
					throw 1;
				len = GetLengthSid(sid);
				tg->Groups[i].Sid = (PSID)new char[len];
				RtlCopyMemory(tg->Groups[i].Sid, sid, len);
				LocalFree(sid);
			}
			else {
				tg->Groups[i].Sid = SeReferenceUserNameA(groups->NamesAndAttributes[i].UserName);
				if (!tg->Groups[i].Sid)throw 2;
			}
			tg->Groups[i].Attributes = groups->NamesAndAttributes[i].Attributes;
		}
	}
	catch (...) {
		for (DWORD i = 0; i < tg->GroupCount; i++) {
			if (tg->Groups[i].Sid)
				delete[]tg->Groups[i].Sid;
		}
		return BSTATUS_INVALID_USER_NAME;
	}
	return BSTATUS_SUCCESS;
}
