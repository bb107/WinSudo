#pragma once
#include "Security.h"

BSTATUS BSAPI RtlTokenPrivilegesToPrivilegeValue(IN PTOKEN_PRIVILEGES tp, IN BOOL EnabledOnly, OUT PPRIVILEGE_VALUE privileges);

BSTATUS BSAPI RtlPrivilegeValueToTokenPrivileges(IN PRIVILEGE_VALUE privileges, OUT PTOKEN_PRIVILEGES tp, IN OUT PDWORD size);

BSTATUS BSAPI RtlTokenGroupsToGroupsA(IN PTOKEN_GROUPS tg, OUT PGROUPS groups, IN OUT PDWORD size);

BSTATUS BSAPI RtlGroupsToTokenGroupsA(IN PGROUPS groups, OUT PTOKEN_GROUPS tg, IN OUT PDWORD size);
