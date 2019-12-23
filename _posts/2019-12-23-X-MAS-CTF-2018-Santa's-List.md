---
title: "X-MAS CTF 2018 / Santa's List"
date: 2019-12-23 15:41:00 +0000
categories: CTF
---

keyword: Chosen Ciphertext Attack 

## Solution

```python
#!/usr/bin/python3
from Crypto.PublicKey import RSA
from Crypto.Util.number import *

FLAG = open('flag.txt', 'r').read().strip()

def menu():
    print()
    print('[1] Encrypt')
    print('[2] Decrypt')
    print('[3] Exit')
    return input()

def encrypt(m):
    return pow(m, rsa.e, rsa.n)

def decrypt(c):
    return pow(c, rsa.d, rsa.n)

rsa = RSA.generate(1024)
flag_encrypted = pow(bytes_to_long(FLAG.encode()), rsa.e, rsa.n)
used = [bytes_to_long(FLAG.encode())]

print('Ho, ho, ho and welcome back!')
print('Your list for this year:\n')
print('Sarah - Nice')
print('Bob - Nice')
print('Eve - Naughty')
print('Galf - ' + hex(flag_encrypted)[2:])
print('Alice - Nice')
print('Johnny - Naughty')

while True:
    choice = menu()

    if choice == '1':
        m = bytes_to_long(input('\nPlaintext > ').strip().encode())
        used.append(m)

        print('\nEncrypted: ' + str(encrypt(m)))

    elif choice == '2':
        c = int(input('\nCiphertext > ').strip())

        if c == flag_encrypted:
            print('Ho, ho, no...')

        else:
            m = decrypt(c)
            
            for no in used:
                if m % no == 0:
                    print('Ho, ho, no...')
                    break
            else:
                print('\nDecrypted: ' + str(m))

    elif choice == '3':
        print('Till next time.\nMerry Christmas!')
        break
```

문제의 코드는 위와 같다.



RSA 클래스의 generate 메소드 관련 문서를 찾아보면 e의 기본값은 65537인 것을 확인할 수 있다. 



문제에서 encryption, decryption 기능을 제공해주기 때문에 n 값도 구할 수 있다. 

```
c = m**e (mod n)

n의 합동식 밖에서는 m**e를 다음과 같이 나타낼 수 있다.

m**e = k*n + c
k*n = m**e + c
```

m, e, c 값은 알고 있으므로 kn의 값을 구할 수 있는 것이다. Encryption 기능을 이용하여 각각 다른 m값을 넣어 각각 다른 kn 값을 구한다. 이것들의 최대 공약수를 구하면 n값이 나온다.

아래는 decryption 기능이다. `if m % no == 0:` 부분이 필터링 역할을 한다. 이 때문에 flag 값과 encryption 기능에 사용된 값은 decryption을 할 수 없다.

```python
    elif choice == '2':
        c = int(input('\nCiphertext > ').strip())


        if c == flag_encrypted:
            print('Ho, ho, no...')


        else:
            m = decrypt(c)
            
            for no in used:
                if m % no == 0:
                    print('Ho, ho, no...')
                    break
            else:
                print('\nDecrypted: ' + str(m))
```

하지만 modular n의 합동식에서는 얘기가 조금 달라진다. (매번 귀찮은 질문할 때마다 친절히 알려주시는 @zanywhale님 감사합니다. ^_^)

```
a*m % m == 0 (mod n)

a*m 값이 n보다 작거나 같다면 위 식이 성립하지만 n보다 큰 값이라면 성립하지 않을 수 있다.
```

위 특성을 이용하여 필터링 우회가 가능하므로 선택 암호문 공격을 해주면 된다. 적절한 a값을 정한 후 decryption 과정에서 다음 c값을 입력해주면 된다.

```
c = (a**e % n)*(flag_encrypted)
```

최종적으로 a*flag 값이 나오게 되는데 modular n에서 a의 역원을 구해서 곱해주면 flag 값이 나온다.

```python
from pwn import *
from Crypto.Util import number
import gmpy2

#context.log_level='debug'

e = 65537

cmd = "python3 ./xmas.py"
p = process(cmd.split(" "))

p.recvuntil("Galf - ")
flag_encrypted = int(p.recvline()[:-1], 16)

c = []
m = [2,3,4]

for m_ in m:
  p.sendlineafter("Exit\n", "1")
  p.sendlineafter("> ", number.long_to_bytes(m_))
  p.recvuntil('nEncrypted: ')
  c.append(int(p.recvline()[:-1]))

kn = []

for i in xrange(3):
  kn.append(m[i]**e - c[i])

tmp = gmpy2.gcd(kn[0], kn[1])
n = gmpy2.gcd(tmp, kn[2])

assert( gmpy2.powmod(m[0], e, n) == c[0] )

val = 2123123
inv = number.inverse(val, n)

c_ = flag_encrypted * gmpy2.powmod(inv,e,n)
p.sendlineafter("Exit\n", "2")
p.sendlineafter("> ", str(c_))

print("n   = 0x%x" % n)
print("val = 0x%x" % val)
print("inv = 0x%x" % inv)
p.interactive()
```

## Reference

<https://blog.encrypted.gg/720>

<https://pwnthemole.github.io/crypto/2018/12/22/xmasctfsantaslist.html>