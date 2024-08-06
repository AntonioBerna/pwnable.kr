# flag

## Instructions

Papa brought me a packed present! let's open it.

- Download: http://pwnable.kr/bin/flag

This is reversing task. all you need is binary.

## step-by-step

Following the game instructions, you need to download the `flag` file using the following command:

```
┌──(kali㉿kali)-[~/pwnable.kr/flag]
└─$ wget http://pwnable.kr/bin/flag 
```

Once the file have been downloaded you need to modify the permissions of the ELF file called `flag` by adding execute permissions with the following command:

```
┌──(kali㉿kali)-[~/pwnable.kr/flag]
└─$ chmod 700 flag
```

Since there are no further instructions, we can try running the following command:

```
┌──(kali㉿kali)-[~/pwnable.kr/flag]
└─$ ./flag         
I will malloc() and strcpy the flag there. take it.
```

The string `I will malloc() and strcpy the flag there. take it.` obtained in output "invites" us to search inside the source code of the `flag` file and to do this we can use the `gdb` tool. Before proceeding let's try to get some useful information from the `flag` file using the `file` command:

```
┌──(kali㉿kali)-[~/pwnable.kr/flag]
└─$ file flag
flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
```

Since we got `no section header` this means that the `flag` file is not a clean executable but may have been modified to not allow direct access to the source code. This means that the `gdb` tool becomes useless for the moment. The only way forward is to try searching for the file `flag` in the printable characters using the `strings flag` command:

```
┌──(kali㉿kali)-[~/pwnable.kr/flag]
└─$ strings flag
```

we get a very long series of characters that I cannot report for reasons of space and readability. However, among the last lines printed by the command we note:

```
...
UPX!
UPX!
```

for those who don't know, UPX (Ultimate Packer for eXecutables) is a tool for packaging executables by performing compression. This could mean that the `flag` file may have been compressed using the UPX tool itself. Let's try running the following command to carry out a more in-depth search:

```
┌──(kali㉿kali)-[~/pwnable.kr/flag]
└─$ strings flag | grep UPX
UPX!
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.08 Copyright (C) 1996-2011 the UPX Team. All Rights Reserved. $
UPX!
UPX!
```

therefore, noticing the string `This file is packed with the UPX executable packer http://upx.sf.net` we are sure that the `flag` file has actually been packed with the UPX tool.

> [!WARNING]
> This means that we should install the UPX tool inside our `Kali Linux` machine (or any other distribution) in order to unpacked the `flag` file. For more information regarding installation, please visit the [official UPX website](https://upx.github.io/).

Once you have installed UPX, it is best to consult the Linux manual (I report an excerpt for simplicity):

```
UPX(1)                                                                                                                                                UPX(1)

NAME
       upx - compress or expand executable files

SYNOPSIS
       upx [ command ] [ options ] filename...

...

COMMANDS
   ...

   Decompress
       All UPX supported file formats can be unpacked using the -d switch, eg. upx -d yourfile.exe will uncompress the file you've just compressed.

   ...

OPTIONS
    ...

    -o file: write output to file
```

Then we can use the following command to unpack the `flag` file and generate the `unpacked_flag` file:

```
┌──(kali㉿kali)-[~/pwnable.kr/flag]
└─$ upx -d flag -o unpacked_flag
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 3rd 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    887219 <-    335288   37.79%   linux/amd64   unpacked_flag

Unpacked 1 file.
```

At this point we try to use the `file` command again but on the new `unpacked_flag` file:

```
┌──(kali㉿kali)-[~/pwnable.kr/flag]
└─$ file unpacked_flag 
unpacked_flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=96ec4cc272aeb383bd9ed26c0d4ac0eb5db41b16, not stripped
```

in particular the wording `not stripped` indicates that the `unpacked_flag` file contains debug information and symbols. We are ready to run `gdb` and in particular:

```
┌──(kali㉿kali)-[~/pwnable.kr/flag]
└─$ gdb ./unpacked_flag 
GNU gdb (Debian 13.2-1+b2) 13.2
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./unpacked_flag...
(No debugging symbols found in ./unpacked_flag)
(gdb)
```

let's try to use the `disassemble main` command to obtain the Assembly code relating to the `main()` function of the source code:

```
(gdb) disassemble main
Dump of assembler code for function main:
   0x0000000000401164 <+0>:     push   %rbp
   0x0000000000401165 <+1>:     mov    %rsp,%rbp
   0x0000000000401168 <+4>:     sub    $0x10,%rsp
   0x000000000040116c <+8>:     mov    $0x496658,%edi
   0x0000000000401171 <+13>:    call   0x402080 <puts>
   0x0000000000401176 <+18>:    mov    $0x64,%edi
   0x000000000040117b <+23>:    call   0x4099d0 <malloc>
   0x0000000000401180 <+28>:    mov    %rax,-0x8(%rbp)
   0x0000000000401184 <+32>:    mov    0x2c0ee5(%rip),%rdx        # 0x6c2070 <flag>
   0x000000000040118b <+39>:    mov    -0x8(%rbp),%rax
   0x000000000040118f <+43>:    mov    %rdx,%rsi
   0x0000000000401192 <+46>:    mov    %rax,%rdi
   0x0000000000401195 <+49>:    call   0x400320
   0x000000000040119a <+54>:    mov    $0x0,%eax
   0x000000000040119f <+59>:    leave
   0x00000000004011a0 <+60>:    ret
End of assembler dump.
(gdb)
```

As you can see by noting the following line:

```
0x0000000000401184 <+32>:    mov    0x2c0ee5(%rip),%rdx        # 0x6c2070 <flag>
```

the address to be examined to obtain the flag we are looking for has been written in plain text. In particular we can use the command `x/s *0x6c2070`, where `x` is the command to examine a specific address, i.e. `0x6c2070`, the latter must be dereferenced with `*` and finally the format specifier must be specified , in this case the flag we are looking for is a string and therefore we specify `s`:

```
(gdb) x/s *0x6c2070
0x496628:       "UPX...? sounds like a delivery service :)"
```

> [!NOTE]
> To exit `gdb` you can use the `q` command.

Perfect, everything went according to plan! So as you can imagine the flag you are looking for is the following sentence:

```
UPX...? sounds like a delivery service :)
```

## Exploitation

Finally, we can use the following exploit, written in `Python`, to replicate the vulnerability in a fully automated way:

```python
from pwn import *
import subprocess
import argparse
import os

def decompress_with_upx(flag, unpacked_flag):
    if os.path.exists(unpacked_flag): os.remove(unpacked_flag)
    
    try:
        with open(os.devnull, "w") as devnull:
            subprocess.run(["upx", "-d", flag, "-o", unpacked_flag], check=True, stdout=devnull, stderr=devnull)
    except subprocess.CalledProcessError as e:
        print(f"Error in decompression with UPX: {e}")
        exit(1)

def print_flag_from_output(output: str):
    for line in output.split("\n"):
        start_index = line.find("\"")
        end_index = line.rfind("\"")
        if start_index != -1 and end_index != -1 and start_index < end_index:
            flag = line[start_index + 1:end_index]
            log.success(f"Flag: \"{flag}\"")
            break

def extract_flag_from_gdb(unpacked_flag):
    # WARNING: I'm not add the `disassemble main` command because is useless in this automation code.
    # NOTE: The 0x6c2070 is the address of the flag.
    gdb_commands = b"""
    x/s *0x6c2070
    quit
    """
    
    gdb_process = process(["gdb", "-q", unpacked_flag])
    gdb_process.sendline(gdb_commands)
    gdb_process.wait_for_close()

    output: str = gdb_process.recvall().decode()
    print_flag_from_output(output)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(dest="flag", help="The UPX compressed file.")
    
    args = parser.parse_args()
    # print(args)

    unpacked_flag = "unpacked_" + args.flag

    decompress_with_upx(args.flag, unpacked_flag)
    extract_flag_from_gdb(unpacked_flag)

if __name__ == "__main__":
    main()
```

then using the `python exploit.py flag` command we get:

```
[+] Starting local process '/usr/bin/gdb': pid 54796
[*] Process '/usr/bin/gdb' stopped with exit code 0 (pid 54796)
[+] Receiving all data: Done (180B)
[+] Flag: "UPX...? sounds like a delivery service :)"
```

