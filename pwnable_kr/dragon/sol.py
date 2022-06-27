from pwn import *

r = process("./dragon")

r.recvuntil(b"Choose Your Hero\n[ 1 ] Priest\n[ 2 ] Knight\n")
r.sendline(b"2")
r.sendline(b"2")
r.recvuntil(b"Choose Your Hero\n[ 1 ] Priest\n[ 2 ] Knight\n")

r.recvuntil(b"Baby Dragon Has Appeared!\n")
