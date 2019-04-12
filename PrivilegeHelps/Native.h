#pragma once
#include <Windows.h>
#include <ntsecapi.h>
#pragma comment(lib,"Secur32.lib")

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef const OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;
#define InitializeObjectAttributes(p, n, a, r, s) { \
(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
(p)->RootDirectory = r; \
(p)->Attributes = a; \
(p)->ObjectName = n; \
(p)->SecurityDescriptor = s; \
(p)->SecurityQualityOfService = NULL; \
}

#define OBJ_INHERIT 0x00000002
#define OBJ_PERMANENT 0x00000010
#define OBJ_EXCLUSIVE 0x00000020
#define OBJ_CASE_INSENSITIVE 0x00000040
#define OBJ_OPENIF 0x00000080
#define OBJ_OPENLINK 0x00000100
#define OBJ_KERNEL_HANDLE 0x00000200
#define OBJ_FORCE_ACCESS_CHECK 0x00000400
#define OBJ_VALID_ATTRIBUTES 0x000007f2

#define DUPLICATE_SAME_ATTRIBUTES 0x00000004

FARPROC WINAPI GetNtProcAddress(LPCSTR func_name);

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
	PTOKEN_SOURCE TokenSource);

NTSTATUS NTAPI NtDuplicateObject(
	IN HANDLE               SourceProcessHandle,
	IN HANDLE               SourceHandle,
	IN HANDLE               TargetProcessHandle,
	OUT PHANDLE             TargetHandle,
	IN ACCESS_MASK          DesiredAccess OPTIONAL,
	IN BOOLEAN              InheritHandle,
	IN ULONG                Options);

DWORD NTAPI RtlNtStatusToDosError(NTSTATUS status);

NTSTATUS NTAPI NtDuplicateToken(
	HANDLE ExistingTokenHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	BOOLEAN EffectiveOnly,
	TOKEN_TYPE TokenType,
	PHANDLE NewTokenHandle);

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
);

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
);
