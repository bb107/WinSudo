#pragma once
#include <Windows.h>
#include "bsdef.h"

extern HANDLE hElvToken;
extern DWORD  reference_count;
extern LPCSTR PrivilegeNames[];


BSTATUS SePrivilegeEscalation(PHANDLE _hToken);

PSID BSAPI SepReferenceUserNameExA(LPCSTR user, PSID_NAME_USE snu);

LPSTR BSAPI SepReferenceSidExA(PSID sid, PSID_NAME_USE snu);
