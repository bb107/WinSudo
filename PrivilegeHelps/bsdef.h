#pragma once
#include <Windows.h>
#include "bstatus.h"
#include <ntsecapi.h>
#define BSAPI __stdcall

enum AUTH_TYPE {
	System,
	LocalService,
	AnonymousLogon,
	Other
};

typedef struct _USER_NAME_AND_ATTRIBUTESA {
	LPSTR UserName;
	DWORD Attributes;
	DWORD IsSid;
}USER_NAME_AND_ATTRIBUTESA, *PUSER_NAME_AND_ATTRIBUTESA;
typedef struct _GROUPS {
	DWORD dwUserNamesAndAttributesCount;
	USER_NAME_AND_ATTRIBUTESA NamesAndAttributes[ANYSIZE_ARRAY];
}GROUPS, *PGROUPS;

typedef struct _LOGON_SESSION_DATA {
	ULONG               Size;
	LUID                LogonId;
	LSA_UNICODE_STRING  UserName;
	LSA_UNICODE_STRING  LogonDomain;
	LSA_UNICODE_STRING  AuthenticationPackage;
	ULONG               LogonType;
	ULONG               Session;
	PSID                Sid;
	LARGE_INTEGER       LogonTime;

	LSA_UNICODE_STRING  LogonServer;
	LSA_UNICODE_STRING  DnsDomainName;
	LSA_UNICODE_STRING  Upn;

	ULONG UserFlags;

	LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
	LSA_UNICODE_STRING LogonScript;
	LSA_UNICODE_STRING ProfilePath;
	LSA_UNICODE_STRING HomeDirectory;
	LSA_UNICODE_STRING HomeDirectoryDrive;

	LARGE_INTEGER LogoffTime;
	LARGE_INTEGER KickOffTime;
	LARGE_INTEGER PasswordLastSet;
	LARGE_INTEGER PasswordCanChange;
	LARGE_INTEGER PasswordMustChange;
}LOGON_SESSION_DATA, *PLOGON_SESSION_DATA;

//特权常数, 可以使用或运算结合
typedef LONGLONG PRIVILEGE_VALUE, *PPRIVILEGE_VALUE;
#define SE_CREATE_TOKEN_VALUE							0x0000000000000001
#define SE_ASSIGNPRIMARYTOKEN_VALUE						0x0000000000000002
#define SE_LOCK_MEMORY_VALUE							0x0000000000000004
#define SE_INCREASE_QUOTA_VALUE							0x0000000000000008
#define SE_UNSOLICITED_INPUT_VALUE						0x0000000000000010
#define SE_MACHINE_ACCOUNT_VALUE						0x0000000000000020
#define SE_TCB_VALUE									0x0000000000000040
#define SE_SECURITY_VALUE								0x0000000000000080
#define SE_TAKE_OWNERSHIP_VALUE							0x0000000000000100
#define SE_LOAD_DRIVER_VALUE							0x0000000000000200
#define SE_SYSTEM_PROFILE_VALUE							0x0000000000000400
#define SE_SYSTEMTIME_VALUE								0x0000000000000800
#define SE_PROF_SINGLE_PROCESS_VALUE					0x0000000000001000
#define SE_INC_BASE_PRIORITY_VALUE						0x0000000000002000
#define SE_CREATE_PAGEFILE_VALUE						0x0000000000004000
#define SE_CREATE_PERMANENT_VALUE						0x0000000000008000
#define SE_BACKUP_VALUE									0x0000000000010000
#define SE_RESTORE_VALUE								0x0000000000020000
#define SE_SHUTDOWN_VALUE								0x0000000000040000
#define SE_DEBUG_VALUE									0x0000000000080000
#define SE_AUDIT_VALUE									0x0000000000100000
#define SE_SYSTEM_ENVIRONMENT_VALUE						0x0000000000200000
#define SE_CHANGE_NOTIFY_VALUE							0x0000000000400000
#define SE_REMOTE_SHUTDOWN_VALUE						0x0000000000800000
#define SE_UNDOCK_VALUE									0x0000000001000000
#define SE_SYNC_AGENT_VALUE								0x0000000002000000
#define SE_ENABLE_DELEGATION_VALUE						0x0000000004000000
#define SE_MANAGE_VOLUME_VALUE							0x0000000008000000
#define SE_IMPERSONATE_VALUE							0x0000000010000000
#define SE_CREATE_GLOBAL_VALUE							0x0000000020000000
#define SE_TRUSTED_CREDMAN_ACCESS_VALUE					0x0000000040000000
#define SE_RELABEL_VALUE								0x0000000080000000
#define SE_INC_WORKING_SET_VALUE						0x0000000100000000
#define SE_TIME_ZONE_VALUE								0x0000000200000000
#define SE_CREATE_SYMBOLIC_LINK_VALUE					0x0000000400000000
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_VALUE		0x0000000800000000

#define SE_ALL_PRIVILEGE_VALUE							0x0000000FFFFFFFFF		//所有特权
#define SE_NO_PRIVILEGE_VALUE							0x0000000000000000		//无特权

#define SE_DISABLE_PRIVILEGE_VALUE						0x1000000000000000		//禁用所有特权, 但是可以启用



//SeCreateUserTokenEx dwFlags:

//特权标识:(表示添加指定的特权, 互不兼容, 必选)
#define SE_CREATE_USE_PRIVILEGES_VALUE					0x00000001	//表示 TokenPrivileges 参数是指向 PRIVILEGE_VALUE 的指针
#define SE_CREATE_USE_TOKEN_PRIVILEGES					0x20000000	//表示 TokenPrivileges 参数是指向 TOKEN_PRIVILEGES 的指针
#define SE_CREATE_USE_PRIVILEGES	SE_CREATE_USE_PRIVILEGES_VALUE

//下面的标识二选一, 否则返回 BSTATUS_INVALID_PARAMETER
#define SE_CREATE_USE_GROUPS							0x00000002	//表示 TokenGroup 参数类型是 PGROUPS
#define SE_CREATE_USE_TOKEN_GROUPS						0x00000004	//表示 TokenGroup 参数类型是 PTOKEN_GROUPS, 与 SE_CREATE_USE_GROUPS 不兼容

#define SE_CREATE_USE_DACL								0x00000008	//表示使用可选参数 TokenDefaultDacl, 否则将忽略 TokenDefaultDacl 参数
#define SE_CREATE_USE_TOKEN_SOURCE						0x00000010	//表示使用可选参数 TokenSource, 否则将忽略 TokenSource 参数

#define SE_CREATE_DISABLE_ALL_PRIVILEGES				0x10000000	//与 TokenPrivileges |= SE_DISABLE_PRIVILEGE_VALUE; 相同

//默认的标识组合
#define SE_CREATE_DEFAULT								SE_CREATE_USE_PRIVILEGES|SE_CREATE_USE_GROUPS


//特权计数
#define PRIVILEGE_COUNT	36




//初始化dll, 在调用任何功能前需要成功调用一次
BSTATUS BSAPI SeInitialDll();
//释放dll, 卸载dll前调用
BSTATUS BSAPI SeReleaseDll();

//创建一个访问令牌
BSTATUS BSAPI SeCreateUserTokenExA(
	PHANDLE			TokenHandle,						//接收返回句柄的指针
	DWORD			dwFlags,							//标识参数
	TOKEN_TYPE		TokenType,							//令牌的类型
	AUTH_TYPE		AuthType,							//认证ID类型,指定为其他时需要提供下一个参数,否则将忽略
	LUID			AuthId					OPTIONAL,	//AuthType 为 Other 时需要此参数
	LPCSTR			TokenUser,							//令牌的用户名
	LPVOID			TokenGroup,							//指针类型由dwFlags决定
	LPVOID			TokenPrivileges,					//指针类型由dwFlags决定
	LPCSTR			TokenOwner,							//令牌所有者用户名
	LPCSTR			TokenPrimaryGroup,					//令牌主用户组名
	PTOKEN_SOURCE	TokenSource				OPTIONAL,	//令牌来源
	PTOKEN_DEFAULT_DACL	TokenDefaultDacl	OPTIONAL,	//令牌默认自由访问控制列表
	SECURITY_IMPERSONATION_LEVEL SecurityImpersonationLevel //安全模拟级别
);

BSTATUS BSAPI SeCreateUserTokenA(
	PHANDLE			TokenHandle,
	AUTH_TYPE		AuthType,
	LUID			AuthId,			OPTIONAL
	LPCSTR			TokenUser,
	PGROUPS			TokenGroup,
	PRIVILEGE_VALUE TokenPrivileges,
	LPCSTR			TokenPrimaryGroup
);

//根据提供的令牌创建一个具有所述特权的令牌副本
BSTATUS BSAPI SeEnablePrivilegesToken(IN OUT PHANDLE hToken, IN PRIVILEGE_VALUE EnablePrivileges);

//给指定的线程设置指定的访问令牌
BSTATUS BSAPI SePrivilegeEscalationThread(DWORD dwThreadId, HANDLE hToken);

//特权常数与 TOKEN_PRIVILEGES 结构的互换
BSTATUS BSAPI RtlTokenPrivilegesToPrivilegeValue(IN PTOKEN_PRIVILEGES tp, IN BOOL EnabledOnly, OUT PPRIVILEGE_VALUE privileges);
BSTATUS BSAPI RtlPrivilegeValueToTokenPrivileges(IN PRIVILEGE_VALUE privileges, OUT PTOKEN_PRIVILEGES tp, IN OUT PDWORD size);

//GROUPS 与 TOKEN_GROUPS 结构的无损转换
BSTATUS BSAPI RtlTokenGroupsToGroupsA(IN PTOKEN_GROUPS tg, OUT PGROUPS groups, IN OUT PDWORD size);
BSTATUS BSAPI RtlGroupsToTokenGroupsA(IN PGROUPS groups, OUT PTOKEN_GROUPS tg, IN OUT PDWORD size);

//打开指定的进程/线程
BSTATUS BSAPI SeReferenceProcess(IN DWORD dwProcessId, OUT PHANDLE hProcess);
BSTATUS BSAPI SeReferenceThread(IN DWORD dwThreadId, OUT PHANDLE hThread);

//打开指定进程/线程的访问令牌
BSTATUS BSAPI SeReferenceProcessPrimaryToken(IN DWORD dwProcessId, OUT PHANDLE hToken);
BSTATUS BSAPI SeReferenceThreadToken(IN DWORD dwThreadId, OUT PHANDLE hToken);

//获取/设置令牌信息
DWORD BSAPI SeQueryInformationToken(HANDLE hToken, TOKEN_INFORMATION_CLASS info, LPVOID mem);
BSTATUS BSAPI SeSetInformationToken(HANDLE hToken, TOKEN_INFORMATION_CLASS info, LPVOID mem, DWORD memlen);

//登录回话枚举
BSTATUS BSAPI SeEnumLogonSessionsLuid(IN PDWORD count, OUT PLUID list, IN OUT PDWORD size);
BSTATUS BSAPI SeQueryLogonSessionInformation(IN PLUID luid, OUT PLOGON_SESSION_DATA *_data);
BSTATUS BSAPI SeFreeLogonSessionData(PLOGON_SESSION_DATA block);

//用户名与PSID互换
PSID BSAPI SeReferenceUserNameA(LPCSTR user);
LPSTR BSAPI SeReferenceSidA(PSID sid);

//获取一个提升的令牌副本
BSTATUS BSAPI SeReferenceEscalationToken(OUT PHANDLE hToken);
//关闭令牌副本
BSTATUS BSAPI SeDereferenceEscalationToken(IN HANDLE hToken);

//释放使用API分配的内存
BSTATUS BSAPI SeFreeAllocate(LPVOID _block);


BSTATUS BSAPI SeSingleGroupsAddNameA(
	IN LPCSTR MemberName,
	IN DWORD Attributes,
	IN PGROUPS Source,
	OUT PGROUPS Destination,
	IN OUT PDWORD BufferSize);

BSTATUS BSAPI SeSingleGroupsAddSid(
	IN PSID MemberSid,
	IN DWORD Attributes,
	IN PGROUPS Source,
	OUT PGROUPS Destination,
	IN OUT PDWORD BufferSize);

BSTATUS BSAPI SeSingleTokenGroupsAddNameA(
	IN LPCSTR MemberName,
	IN DWORD Attributes,
	IN PTOKEN_GROUPS Source,
	OUT PTOKEN_GROUPS Destination,
	IN OUT PDWORD BufferSize);

BSTATUS BSAPI SeSingleTokenGroupsAddSid(
	IN PSID MemberSid,
	IN DWORD Attributes,
	IN PTOKEN_GROUPS Source,
	OUT PTOKEN_GROUPS Destination,
	IN OUT PDWORD BufferSize);


BSTATUS BSAPI PsCreateUserProcessW(
	HANDLE hUserToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation);

BSTATUS BSAPI PsCreateUserProcessA(
	HANDLE hUserToken,
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation);

#define PsCreateProcessWithTokenA	PsCreateUserProcessA
#define PsCreateProcessWithTokenW	PsCreateUserProcessW
#define PsCreateProcessAsUserA		PsCreateProcessWithTokenA
#define PsCreateProcessAsUserW		PsCreateProcessWithTokenW
