import winim/inc/windef
import winim/inc/winbase
import winim/inc/psapi
import winim/lean

const bufferSize = 128;
var buffer : wstring = newWString(bufferSize);
var luid : LUID
var tp : TOKEN_PRIVILEGES

var privilegeName = L"SeDebugPrivilege";
var x = LookupPrivilegeValue(NULL, &privilegeName, &luid)

if not x == True:
    echo "Failed to get privilege name: ", GetLastError(), luid
    system.quit(1)

tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

var h = GetCurrentProcess()
# var h = OpenProcess(WRITE_DAC, True, 6488)

var accessToken : HANDLE


OpenProcessToken(h, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, &accessToken)
# var pid = GetProcessId(h);
# GetModuleBaseName(h, 0, &buffer, bufferSize);
# echo buffer;

var cb : DWORD = (DWORD) sizeof(TOKEN_PRIVILEGES)
x = AdjustTokenPrivileges(accessToken, FALSE, &tp, cb, NULL, NULL)

if not x == True:
    echo "Failed to adjust token privilege: ", GetLastError()
    system.quit(1)

if (GetLastError() == ERROR_NOT_ALL_ASSIGNED):
    echo "The token does not have the specified privilege"
