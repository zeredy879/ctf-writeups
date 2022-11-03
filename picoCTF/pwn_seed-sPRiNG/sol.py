from pwn import *
from ctypes import *
from time import time


# r = process("./seed_spring")
r = remote("jupiter.challenges.picoctf.org", 35856)

libc = CDLL("libc.so.6")
libc.srand(int(time()))
arr = [libc.rand() for _ in range(30)]
for i in range(30):
    r.recvuntil(b": ")
    r.sendline(str(arr[i] & 0xF))

# This challenge need low network delay, so I run the script on my webshell
# and it works. This challenge is similar to pwnable.kr's md5
r.interactive()
