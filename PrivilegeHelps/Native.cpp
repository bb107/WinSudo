#include "Native.h"

FARPROC WINAPI GetNtProcAddress(LPCSTR func_name) {
	return GetProcAddress(GetModuleHandleA("ntdll.dll"), func_name);
}

LPCSTR f_NtCreateToken = "NtCreateToken";
LPCSTR f_NtDuplicateObject = "NtDuplicateObject";
LPCSTR f_RtlNtStatusToDosError = "RtlNtStatusToDosError";
LPCSTR f_NtDuplicateToken = "NtDuplicateToken";

NTSTATUS __declspec(naked) NTAPI NtCreateToken(
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
	__asm {
		push f_NtCreateToken;
		call GetNtProcAddress;
		jmp eax;
	}
}

NTSTATUS __declspec(naked) NTAPI NtDuplicateObject(
	IN HANDLE               SourceProcessHandle,
	IN HANDLE               SourceHandle,
	IN HANDLE               TargetProcessHandle,
	OUT PHANDLE             TargetHandle,
	IN ACCESS_MASK          DesiredAccess OPTIONAL,
	IN BOOLEAN              InheritHandle,
	IN ULONG                Options) {
	__asm {
		push f_NtDuplicateObject;
		call GetNtProcAddress;
		jmp eax;
	}
}

DWORD __declspec(naked) NTAPI RtlNtStatusToDosError(NTSTATUS status) {
	__asm {
		push f_RtlNtStatusToDosError;
		call GetNtProcAddress;
		jmp eax;
	}
}

NTSTATUS __declspec(naked) NTAPI NtDuplicateToken(
	HANDLE ExistingTokenHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	BOOLEAN EffectiveOnly,
	TOKEN_TYPE TokenType,
	PHANDLE NewTokenHandle) {
	__asm {
		push f_NtDuplicateToken;
		call GetNtProcAddress;
		jmp eax;
	}
}


LPCSTR module = "kernelbase.dll";
LPCSTR f_CreateProcessInternalW = "CreateProcessInternalW";
BOOL __declspec(naked) WINAPI CreateProcessInternalW(
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
	__asm {
		push module;
		call GetModuleHandleA;
		push f_CreateProcessInternalW;
		push eax;
		call GetProcAddress;
		jmp eax;
	}
}

LPCSTR f_CreateProcessInternalA = "CreateProcessInternalA";
BOOL __declspec(naked) WINAPI CreateProcessInternalA(
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
	__asm {
		push module;
		call GetModuleHandleA;
		push f_CreateProcessInternalA;
		push eax;
		call GetProcAddress;
		jmp eax;
	}
}
