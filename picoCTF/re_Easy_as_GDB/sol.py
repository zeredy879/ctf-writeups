data = bytearray(b"z.nh\035e\026|mCo6cb\024GCc@cX\001X3b?S0m\027")

# for i in range(29, 0, -1):
#     for j in range(0, 30 - i + 1, i):
#         data[j], data[j + i - 1] = data[j + i - 1], data[j]
for i in range(29, 0, -1):
    for j in range(30 // i * i - i, -1, -i):
        data[j], data[j + i - 1] = data[j + i - 1], data[j]

xor = [0, 0, 0, 0]

for i in range(0xabcf00d, 0xdeadbeef, 0x1fab4d):
    xor[0] ^= (i >> 0x18) % 0x100
    xor[1] ^= (i >> 0x10) % 0x100
    xor[2] ^= (i >> 0x8) % 0x100
    xor[3] ^= i % 0x100

for i in range(30):
    data[i] ^= xor[i & 3]

# data = bytearray(b"z.nh\035e\026|mCo6cb\024GCc@cX\001X3b?S0m\027")
print(data)
length = len(data)
len_4 = (length >> 2) << 2 + 4
# print(hex(data[0]))