#include <Windows.h>
#include "Process.h"

const std::string Strupr(IN const char* buf) {
	int len = strlen(buf) + 1;
	std::string tmp(len, 0);
	for (int i = 0; i < len; i++)
		tmp[i] = buf[i] >= 'a'&&buf[i] <= 'z' ? buf[i] - 0x20 : buf[i];
	return tmp;
}
#define strupr Strupr

DWORD PsGetProcessId(const char* szProcessName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	std::string pn = strupr((char*)szProcessName);
	if (hSnapshot == INVALID_HANDLE_VALUE)	return 0;
	PROCESSENTRY32 ps;
	if (!Process32First(hSnapshot, &ps))	return 0;
	do {
		if (!strcmp(strupr(ps.szExeFile).data(), pn.data())) {
			CloseHandle(hSnapshot);	return ps.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &ps));
	CloseHandle(hSnapshot);
	return 0;
}
