from pwn import *
import re

sh = remote("pwnable.kr", 9007)
sh.recvuntil("- Ready? starting in 3 sec... -\n\t\n")

for _ in range(100):
    N, C = map(int, re.findall(r"\d+", sh.recv().decode("utf-8")))
    print(N, C)
    left, right = 0, N - 1
    for _ in range(C):
        mid = (left + right) // 2
        sh.sendline(" ".join([str(i) for i in range(left, mid)]))
        sum = int(sh.recvline().decode("utf-8"))
        if sum % 10 == 0:
            left = mid
        else:
            right = mid
    sh.sendline(str(left))
    print(sh.recv())
print(sh.recvline())
print(sh.recvline())

