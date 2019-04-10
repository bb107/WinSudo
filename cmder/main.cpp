#include <Windows.h>
#include <cstdio>
#pragma warning(disable:4996)

int main(int argc, char*argv[]) {
	if (argc <= 1)return -1;
	FreeConsole();
	if (!AttachConsole(atoi(argv[1])))
		return -2;
	if (argc == 2) system("cmd");
	else {
		char *cmd; int len = 0;
		for (int i = 2; i < argc; i++) {
			len += strlen(argv[i]);
		}
		len += argc;
		cmd = new char[len];
		RtlZeroMemory(cmd, len);
		for (int i = 2; i < argc; i++) {
			bool add = false; int j = 0; char current;
			while (true) {
				current = *(argv[i] + j++);
				if (!current)break;
				if (current == ' ') {
					add = true; break;
				}
			}
			sprintf(cmd, add ? "%s\"%s\" " : "%s%s ", cmd, argv[i]);
		}
		system(cmd);
		delete[]cmd;
	}
	return 0;
}
