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
