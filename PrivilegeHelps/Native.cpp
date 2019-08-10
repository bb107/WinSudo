#include "Native.h"

FARPROC WINAPI GetNtProcAddress(LPCSTR func_name) {
	return GetProcAddress(GetModuleHandleA("ntdll.dll"), func_name);
}

LPCSTR f_NtCreateToken = "NtCreateToken";
LPCSTR f_NtDuplicateObject = "NtDuplicateObject";
LPCSTR f_RtlNtStatusToDosError = "RtlNtStatusToDosError";
LPCSTR f_NtDuplicateToken = "NtDuplicateToken";

NTSTATUS NTAPI NtCreateToken(
	PHANDLE TokenHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	TOKEN_TYPE TokenType,
	PLUID AuthenticationId,
	PLARGE_INTEGER ExpirationTime,
	PTOKEN_USER TokenUser,
	PTOKEN_GROUPS TokenGroups,
	PTOKEN_PRIVILEGES TokenPrivileges,
	PTOKEN_OWNER TokenOwner,
	PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
	PTOKEN_DEFAULT_DACL TokenDefaultDacl,
	PTOKEN_SOURCE TokenSource) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, LPVOID, TOKEN_TYPE, PLUID,
		PLARGE_INTEGER, PTOKEN_USER, PTOKEN_GROUPS, PTOKEN_PRIVILEGES,
		PTOKEN_OWNER, PTOKEN_PRIMARY_GROUP, PTOKEN_DEFAULT_DACL, PTOKEN_SOURCE)>(GetNtProcAddress(f_NtCreateToken))(
			TokenHandle, DesiredAccess, ObjectAttributes, TokenType, AuthenticationId,
			ExpirationTime, TokenUser, TokenGroups, TokenPrivileges, TokenOwner,
			TokenPrimaryGroup, TokenDefaultDacl, TokenSource);
}

NTSTATUS NTAPI NtDuplicateObject(
	IN HANDLE               SourceProcessHandle,
	IN HANDLE               SourceHandle,
	IN HANDLE               TargetProcessHandle,
	OUT PHANDLE             TargetHandle,
	IN ACCESS_MASK          DesiredAccess OPTIONAL,
	IN BOOLEAN              InheritHandle,
	IN ULONG                Options) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, BOOLEAN, LONG)>(GetNtProcAddress(f_NtDuplicateObject))
		(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, InheritHandle, Options);
}

DWORD NTAPI RtlNtStatusToDosError(NTSTATUS status) {
	return reinterpret_cast<DWORD(NTAPI*)(NTSTATUS)>(GetNtProcAddress(f_RtlNtStatusToDosError))(status);
}

NTSTATUS NTAPI NtDuplicateToken(
	HANDLE ExistingTokenHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	BOOLEAN EffectiveOnly,
	TOKEN_TYPE TokenType,
	PHANDLE NewTokenHandle) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, TOKEN_TYPE, PHANDLE)>
		(GetNtProcAddress(f_NtDuplicateToken))(ExistingTokenHandle, DesiredAccess, ObjectAttributes, EffectiveOnly, TokenType, NewTokenHandle);
}


LPCSTR module = "kernel32.dll";
LPCSTR f_CreateProcessInternalW = "CreateProcessInternalW";
BOOL WINAPI CreateProcessInternalW(
	_In_opt_ HANDLE hUserToken,
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation,
	_Outptr_opt_ PHANDLE hRestrictedUserToken
) {
	return reinterpret_cast<BOOL(WINAPI*)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
		LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE)>
		(GetProcAddress(GetModuleHandleA(module), f_CreateProcessInternalW))(hUserToken, lpApplicationName,
			lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
			lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hRestrictedUserToken);
}

LPCSTR f_CreateProcessInternalA = "CreateProcessInternalA";
BOOL WINAPI CreateProcessInternalA(
	_In_opt_ HANDLE hUserToken,
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation,
	_Outptr_opt_ PHANDLE hRestrictedUserToken
) {
	return reinterpret_cast<BOOL(WINAPI*)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
		LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION, PHANDLE)>
		(GetProcAddress(GetModuleHandleA(module), f_CreateProcessInternalA))(hUserToken, lpApplicationName,
			lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
			lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hRestrictedUserToken);
}
