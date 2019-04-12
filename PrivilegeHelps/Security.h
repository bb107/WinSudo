#pragma once
#include <Windows.h>
#include <sddl.h>
#include "bsdef.h"

extern HANDLE hElvToken;
extern DWORD  reference_count;
extern LPCSTR PrivilegeNames[];

BSTATUS BSAPI SepElevateCurrentThread();

BSTATUS BSAPI SepRevertToSelf();

BSTATUS BSAPI SepPrivilegeEscalation(PHANDLE _hToken);

PSID BSAPI SepReferenceUserNameExA(LPCSTR user, PSID_NAME_USE snu);

LPSTR BSAPI SepReferenceSidExA(PSID sid, PSID_NAME_USE snu);
