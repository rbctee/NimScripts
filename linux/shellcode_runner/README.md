# Nim Shellcode Runner

## Compilation

The program contains shellcode for `x86-64` platforms.

To compile it:

```bash
nim c -l='-fno-stack-protector -z execstack' shellcode_runner.nim
```

The compiler options are needed as the shellcode is stored on the stack, which is set as NX (Non-Executable) by default by the `GCC` compiler.

Type of executable generated on `x86-64` systems:

```bash
file shellcode_runner

# shellcode_runner:
#     ELF 64-bit LSB pie executable
#     x86-64
#     version 1 (SYSV)
#     dynamically linked
#     interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a2c9a039e5144c90794d27f05a62c90fce21b88e
#     for GNU/Linux 3.2.0
#     not stripped
```
