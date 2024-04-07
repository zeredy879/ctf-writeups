# pwnable.kr coin2
from pwn import *
context.log_level = 'debug'


def coin_strategy(N: int, C: int) -> bytes:
    res = ''
    for i in range(C):
        for idx in range(N):
            if idx & 2**i != 0:
                res += str(idx) + ' '
        res += '-'
    return res[:-1].encode()


def find_counterfeit(result: str) -> int:
    counterfeit = 0
    res = result.split('-')
    for i, v in enumerate(res):
        if v.endswith('9'):
            counterfeit += 2 ** i
    return counterfeit



r = remote('pwnable.kr', 9008)
time.sleep(4)
r.recvuntil(b'- Ready? starting in 3 sec ... -')
r.recvlinesS(2)
while True:
    N, C = map(int, re.findall(r'N=(\d+) C=(\d+)\n', r.recvline().decode())[0])
    r.sendline(coin_strategy(N, C))
    result = r.recvline().decode().strip()
    r.sendline(str(find_counterfeit(result)).encode())
    r.recvline()

