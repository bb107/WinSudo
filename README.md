# WinSudo
Execute commands as local system.</br>
以本地系统上下文执行命令.

**This code is for learning communication only and may not be used to create malware.**</br>
**此代码仅用于学习交流,不得用于制作恶意软件.**

[![LICENSE](https://img.shields.io/badge/license-Anti%20996-blue.svg)](https://github.com/996icu/996.ICU/blob/master/LICENSE)
[![HitCount](http://hits.dwyl.io/bb107/WinSudo.svg)](http://hits.dwyl.io/bb107/WinSudo)

**Warning: Please use this program with caution, especially calling the PrivilegeHelps library.**</br>
**警告:请谨慎使用本程序,尤其是调用PrivilegeHelps库.**

## Usage  (用法)
```
sudo.exe program args...
sudo.exe 程序名 参数...

usage: su [switchs] [options] [-c (program) (argvs...)]
       switchs:
           [-n NewConsoleWindow] [-e exit without wait subprocess] [-h show this text and exit]
       options:
           [-u user_name] [-o token_owner] [-p token_primary_group] [-P privilege_value] [-g (member_name) (attributes) (0|1 IsStringSid)]
       user_name default is system.
       token_owner default is administrators.
       token_primary_group default is system.
       privilege_value and token_groups default is current token privileges and groups.
       program and argvs default is cmd.exe.
       -g option is group member information and can be added multiple.
       examples:
           su
           su -u administrator -o administrators -c cmd.exe
           su -u system -c reg query HKLM\SAM\SAM
           su -g "system mandatory level" 0x67 0 -g administrators 0xf 0 -g everyone 0x1 0 -g "authenticated users" 0x1 0 -g S-0-123-456 0x1 1 -P 0xfffffffff

Note: S-0-123-456 in Example 4 is an invalid SID. Here is just a way to add a string SID to the demo. Adding this sid may cause the program to fail.

用法: su [开关] [选项] [-c (程序名) (参数...)]
       开关:
           [-n 新建命令行窗口] [-e 不等待进程结束就退出] [-h 显示信息并退出]
       选项:
           [-u 用户名] [-o 所有者名] [-p 主用户组名称] [-P 特权常数] [-g (成员名) (属性) (0|1 是否为sid)]
       用户名默认是 system.
       所有者名默认是 administrators.
       主用户组名称默认是 system.
       特权常数和组信息默认使用当前进程的信息.
       运行的程序默认是 cmd.exe
       -g 参数指定组成员信息,可以重复使用
       例子:
           su
           su -u administrator -o administrators -c cmd.exe
           su -u system -c reg query HKLM\SAM\SAM
           su -g "system mandatory level" 0x67 0 -g administrators 0xf 0 -g everyone 0x1 0 -g "authenticated users" 0x1 0 -g S-0-123-456 0x1 1 -P 0xfffffffff

注意:例子4中的 S-0-123-456 是无效SID,在此仅为演示添加字符串SID的方法,添加此sid可能导致程序执行失败.
           
```

## defects  (缺陷)
* ~~**Cannot inherit the current console window under Windows7 (issue #1)**~~
* ~~**Windows7 下无法继承当前控制台窗口 (issue #1)**~~
* **Process need to be elevated**
* **进程需要提升**

## Project Features (项目特点)
* **Can inherit the current console window. Thanks for the help @Mattiwatti**
* **感谢@Mattiwatti 提供的帮助,控制台不能继承的问题已经修复.**

* All enabled privileges are enabled by default
* 默认开启所有能启用的特权

* Can create an access token just like calling winapi, which can contain any privileges and any attributes for any user group.
* 可以像调用winapi一样创建访问令牌,可以包含任意特权和任意用户组任意属性

* User name and group name are submitted using LPCSTR, which is convenient to call.
* 用户名和组名使用LPCSTR提交,方便调用

* Strict parameter checking to avoid memory violations
* 严格的参数检查,尽量避免内存违规

## Project list (项目列表)
* PrivilegeHelps</br>
Provide APIs such as creating access tokens.</br>
提供创建访问令牌等API
* sudo</br>
Create a process with local system permissions using the PrivilegeHelps library.</br>
使用PrivilegeHelps库创建具有本地系统权限的进程
* cmder</br>
~~The process created by the `CreateProcessWithTokenW` function assigns a new console by default, and the cmder will reattach the original console to achieve in-place promotion.</br>
`CreateProcessWithTokenW`函数创建的进程默认分配新控制台,cmder将重新附加原来的控制台,以实现原地提升.</br></br>
However, the standard output handle cannot be copied under Windows 7, and the additional source console cannot be implemented.</br>
但是,在Windows7下无法复制标准输出句柄,不能实现附加源控制台.~~</br>
Removed.</br>
已移除
* su</br>
Create tokens based on user-specified information and create processes without a password.</br>
根据用户指定的信息创建令牌并创建进程,无需密码.

## Important function description (重要函数说明)
```
SeCreateUserTokenExA
Create a user access token based on user-defined information.
创建一个用户访问令牌,根据用户自定义的信息.

SeCreateUserTokenA
A simplified version of SeCreateUserTokenExA that is called internally.
SeCreateUserTokenExA的简化版,在内部调用了它

SeEnablePrivilegesToken
Create a new token with the specified privilege, the other information is consistent with the source token.
创建一个指定特权的新令牌,其他信息与源令牌一致.

RtlTokenPrivilegesToPrivilegeValue
Convert the TOKEN_PRIVILEGES structure to a PRIVILEGE_VALUE 64-bit value.
将TOKEN_PRIVILEGES结构转换为PRIVILEGE_VALUE 64位值.

RtlGroupsToTokenGroupsA
Convert the GROUPS structure to the TOKEN_GROUPS structure.
将GROUPS结构转换为TOKEN_GROUPS结构.

SeReferenceEscalationToken
You will get a copy of the elevated token, which you need to call SeDereferenceEscalationToken or NtClose or CloseHandle to close.
将获取一个提升的令牌副本,使用完毕需要调用SeDereferenceEscalationToken或者NtClose或者CloseHandle关闭.

SeDereferenceEscalationToken
Close a handle with the Win32 CloseHandle and NT NtClose functions.
关闭一个句柄,同Win32 CloseHandle 和 NT NtClose函数.

SeSingleGroupsAddNameA
SeSingleGroupsAddSid
Modify the properties of a single group member in the GROUPS structure or add new member to the structure.
修改GROUPS结构中单个组成员的属性或添加新成员到结构中.

SeSingleTokenGroupsAddNameA
SeSingleTokenGroupsAddSid
Modify the properties of a single group member in the TOKEN_GROUPS structure or add new members to the structure.
修改TOKEN_GROUPS结构中单个组成员的属性或添加新成员到结构中.

PsCreateUserProcessA
PsCreateUserProcessW
Create a new process with the specified token, the new process will inherit the current console, and the new console can be assigned via dwFlags.
使用指定令牌创建新进程,新的进程将继承当前控制台,可以通过dwFlags分配新控制台.

SeFreeAllocate
Frees the memory returned by the SeQueryInformationToken, SeReferenceUserNameA, SeReferenceSidA functions.
释放由 SeQueryInformationToken, SeReferenceUserNameA, SeReferenceSidA 函数返回的内存.
```

## Screenshot of the program running (程序运行的截图)
![alt text](screenshots/sudo.png?raw=true "sudo")

* Add TrustedInstaller Permission
![alt text](screenshots/sudo2.png?raw=true "sudo2")
* Example of running su
![alt text](screenshots/su1.png?raw=true "su1")
