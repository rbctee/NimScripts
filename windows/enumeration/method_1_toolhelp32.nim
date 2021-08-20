import winim/inc/windef
import winim/inc/winbase
import winim/inc/tlhelp32
import winim/inc/winerror
import strformat

# God forgive me for I don't know how to convert a WCHAR array to string without this hack
# if you know please open an Issue/Pull request
proc ConvertWCharArrayToString(wchar_array: openarray[WCHAR]): string =
    var ProcessNameSeq: seq[char]

    for wc in wchar_array:
        # avoid null byte, otherwise the string will be long (~260 chars) and it will print null characters
        if wc != 0:
            ProcessNameSeq.add(cast[char](wc))

    return cast[string](ProcessNameSeq)    

var
    ProcessStructure: PROCESSENTRY32
    HandleSnapshot: HANDLE
    ReturnBooleanValue: bool
    ProcessId: DWORD
    ParentProcessId: DWORD
    NumThreads: DWORD
    ThreadPriority: LONG
    ProcessName: string


template doWhile(condition, code: untyped): untyped =
  code
  while condition:
    code


when isMainModule:
    echo "### Process Enumeration Program ###"

    HandleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if HandleSnapshot == INVALID_HANDLE_VALUE:
        echo "[!] Function 'CreateToolhelp32Snapshot' failed to return an open handle"
        echo "\tError: %i\n", GetLastError()
        system.quit(1)
    else:
        echo "[+] Got an open handle from 'CreateToolhelp32Snapshot'"
    
    ProcessStructure.dwSize = cast[DWORD](sizeof(PROCESSENTRY32));
    
    ReturnBooleanValue = cast[bool](Process32First(HandleSnapshot, ProcessStructure.addr));

    if not ReturnBooleanValue:
        if GetLastError() == ERROR_NO_MORE_FILES:
            echo "[!] The function 'Process32First' failed to enumerate to first process."
            echo "\tNo processes exist or the snapshot does not contain process information"
            system.quit(1)
        else:
            echo "[!] The function 'Process32First' failed to enumerate to first process."
            echo "\tError code: %i", GetLastError()
            system.quit(1)
    else:
        echo "[+] The function 'Process32First' successfully enumerated the first process in the snapshot."


    doWhile cast[bool](Process32Next(HandleSnapshot, ProcessStructure.addr)):
        ProcessId = ProcessStructure.th32ProcessID
        NumThreads = ProcessStructure.cntThreads
        ParentProcessId = ProcessStructure.th32ParentProcessID
        ThreadPriority = ProcessStructure.pcPriClassBase
        ProcessName = ConvertWCharArrayToString(ProcessStructure.szExeFile)

        echo fmt("PID: {ProcessId:<8}\tNum. of Threads: {NumThreads:<4}\tParent PID (PPID): {ParentProcessId:<8}\tThread Priority: {ThreadPriority:<3}\tName: {ProcessName}")


    echo "[+] Finished enumerating the processes."