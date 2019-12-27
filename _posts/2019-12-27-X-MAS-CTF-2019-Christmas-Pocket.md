---
title: "X-MAS CTF 2019 / Christmas Pocket"
date: 2019-12-27 14:50:00 +0000
categories: CTF
---

크립토 늅늅으로써 최근에 크립토를 공부하고 있는 중이다. 태어나서 처음으로 참가한 크리스마스 CTF에서 암호 문제가 2개 정도 나왔다. hide and seek 문제에 도전해봤지만 빠르게 포기하고, 잠시 뒤 나온 Christmas Pocket 문제에 도전해보았다.

처음에는 코드 분석을 대충 하고 수식 없이 감으로 대충해봤는데 역시.. 삽질만 하고 시간을 날렸다. 잠시 머리를 식힌 뒤 지하철에서 약 1시간 10분 동안 아이패드에 수식을 정리했더니 비밀키를 복구할만한 식이 몇개 나왔다. 집에 도착하자마자 코드를 짰더니 문제가 풀렸다. 최근에 크립토를 공부한게 너무 뿌듯했다 ㅎㅎ

(hide and seek 문제는 RSA였는데 대충 코드를 분석해보고 수식 없이 판단했을 때, 최대한 구해도 p의 상위 512비트만 구할 수 있을 것 같았다. 만약에 수식을 세워서 p의 512비트를 구한다고 하더라도 다음 시나리오가 생각나지 않아서 포기했다 ㅎㅎ..) 

# Solution

문제에서 제공해주는 소스코드는 다음과 같다.

```python
import binascii
from random import randint
from math import gcd
import gmpy

class pockets:
    def __init__(self):
        self.max_string_len = 28
    def gen_key(self):
        self.pocket = [randint(1,10)]

        for i in range(8 * self.max_string_len - 1):
            s = sum(self.pocket)
            self.pocket.append(s + randint(s, s*3))

        s = sum(self.pocket)
        self.mod = randint(s, s*3)

        self.mul = randint(1,self.mod)
        while gcd(self.mul,self.mod) != 1:
            self.mul = randint(1,self.mod)

        self.pubkey = list(map(lambda x : self.mul * x % self.mod, self.pocket))

    def encrypt(self,msg):
        if len(msg)  > 30:
            print("Message is too long!")
            return ''
        binary = bin(int(binascii.hexlify(msg),16))[2:]
        l = len(binary)
        if l % 8 != 0:
            binary = binary.rjust(l + (8-(l%8)),'0')
        c = 0
        for i in range(len(binary)):
            if binary[i] == '1':
                c += self.pubkey[i]
        return hex(c)[2:]

    def decrypt(self,enc):
        enc = int(enc,16)
        inv = int(gmpy.invert(self.mul, self.mod))
        m = inv * enc % self.mod
        s = ''
        for i in reversed(self.pocket):
            if m >= i:
                m -= i
                s += '1'
            else:
                s += '0'
        s = binascii.unhexlify(hex(int(s[::-1],2))[2:])
        return s

flag = open('flag','rb').read()[:28]
p = pockets()
p.gen_key()
print('public key: ' + str(p.pubkey))
print('encrypted: ' + p.encrypt(flag))
```

키를 생성하는 방식, 암호화, 복호화 방식을 분석해야 한다. 공개키와 비밀키는 다음과 같다.

```
Public  Key : pubkey
Private Key : mul, mod, pocket
```

공개키 값은 `output` 파일을 통해 제공해준다. 따라서 우리가 알고 있는 값이다. 암호화나 복호화의 취약성을 찾아내면, 공개키 값을 기반으로 계산하면 비밀키를 얻어낼 수 있다고 생각했다.

키 생성, 암호화, 복호화를 분석하여 각 변수에 대한 수식을 세워보면 다음과 같다.

```
p[i] = pocket[i]
1 <= p[0] <= 10 ----- A
3^i-3^(i-1) <= (3^i-3^(i-1))/p[i] <= p[i] <= (5^i - 5^(i-1))/p[i] <= (5^i - 5^(i-1))*10

s[i] = p[0] + p[1] + ... + p[i]
3^i <= s[i] <= 5^i * 10

n = mod
m = mul
1 <= m <= n
gcd(m, n) = 1
pubkey[i] = m * p[i] % n
m*p[i] = k*n + pubkey[i]

p[0] <= pubkey[0] = m * p[0] <= n * p[0] ----- B

2 * p[0] <= pubkey[1] = m * p[1] <= 4*n*p[0] ----- C

2 <= 2*p[0] <= p[1] <= 4*p[0] <= 40
m*p[1] = k*n + pubkey[1]
m*p[1] - pubkey[1] = k*n <= 40n - pubkey[1] ----- D
```

B 식을 통해 `pubkey[0] <= n*p[0]` 임을 알 수 있다. 따라서 `pubkey[0]` 을 소인수 분해하여 1이상 10이하의 값을 찾으면 그 값이 `pocket[0]` 의 값이다. 주어진 값을 소인수 분해해보면 1이하 10이하의 값은 3 또는 5이다. `mul=pubkey[0]/pocket[0]`이므로 `pocket[0]`이 3 또는 5인 `mul` 값 2개에 대해서만 생각해주면 된다.

A 식을 통해 C 식의 범위를 구할 수 있는데,  C식과 D 식을 같이 보면 k 값의 범위가 보인다. k는 1이상 40이하의 수이다. k 값에 대해 brute force 공격을 수행하면 n 값의 후보 값을 뽑아올 수 있다. 그러면 비밀키 값 3개 중 2개, `mul` 값과 `mod` 값을 알게 된다.

이제 나머지 비밀키 값인  `pocket` 값을 복구할 차례이다. `pubkey = mul*pokcet (mod mod)`이므로 `mul`, `mod`에 대한 `pubkey`의 역원인 `inv` 값을 구해주면 된다.  `pocket = inv * pubkey (mod mod)` 식을 통해 값을 복구할 수 있다.

위 과정을 통해 비밀키 값을 구한후 복호화를 해보면 플래그가 나온다

```python
import binascii
from random import randint, seed
from math import gcd
import gmpy, gmpy2

pubkey = [57547174720929319669417981787834313194612810663813495370531016263447357728731699157659796170432781491310583323984204686633067191303305, 7230019189526071368255992435183734432388646764251159135692547283856631509443555154580729756304347754554964777045318900566603425390798, ...skip...]
encrypted = '1304d3988965eceeb40dd91a7c97c0e04851d0a362d6b8b671ef8471568cf685df8f09ed8d55ca9a3383f846ac74fc4b7d468387154f4f6dc7'

def decrypt(enc, mul, mod, pocket):
    enc = int(enc,16)
    inv = int(gmpy.invert(mul, mod))
    m = inv * enc % mod
    s = ''
    for i in reversed(pocket):
        if m >= i:
            m -= i
            s += '1'
        else:
            s += '0'
    s = binascii.unhexlify(hex(int(s[::-1],2))[2:])
    return s

'''
m = mul
n = mod
'''

cnt = 0
p0 = 3 # 3 or 5
m = pubkey[0] // p0

nList = []

for p1 in range(2, 41):
  for k in range(1,41):
    n = (m*p1 - pubkey[1]) // k
    gcd = gmpy2.gcd(m,n)
    modulo = (m*p1 - pubkey[1]) % k
    if gcd == 1 and modulo == 0 and (n >= pow(3, 8*28) and n <= pow(5, 8*28)*3) and m <= n:
      cnt +=1
      nList.append(n)

for n in nList:
  pocket = [p0]
  for i in range(1, 8*28):
    inv = int(gmpy.invert(m, n))
    p = inv * pubkey[i] % n
    pocket.append(p)
  print(decrypt(encrypted, m, n, pocket))

# b'X-MAS{Pocket_o_Fukuramasete}'
```

