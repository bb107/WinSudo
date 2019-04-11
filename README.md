# WinSudo
Execute commands as local system.</br>
以本地系统上下文执行命令.

[![LICENSE](https://img.shields.io/badge/license-Anti%20996-blue.svg)](https://github.com/996icu/996.ICU/blob/master/LICENSE)

**Warning: Please use this program with caution, especially calling the PrivilegeHelps library.**</br>
**警告:请谨慎使用本程序,尤其是调用PrivilegeHelps库.**

## Usage  (用法)
```
sudo.exe program args...
sudo.exe 程序名 参数...
```

## defects  (缺陷)
* **Cannot inherit the current console window under Windows7**
* **Windows7 下无法继承当前控制台窗口**

## Project Features (项目特点)
* **process need to be elevated**
* **进程需要提升**

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
The process created by the `CreateProcessWithTokenW` function assigns a new console by default, and the cmder will reattach the original console to achieve in-place promotion.</br>
`CreateProcessWithTokenW`函数创建的进程默认分配新控制台,cmder将重新附加原来的控制台,以实现原地提升.</br></br>

However, the standard output handle cannot be copied under Windows 7, and the additional source console cannot be implemented.</br>
但是,在Windows7下无法复制标准输出句柄,不能实现附加源控制台.

## Screenshot of the program running (程序运行的截图)
![alt text](screenshots/sudo.png?raw=true "sudo")
