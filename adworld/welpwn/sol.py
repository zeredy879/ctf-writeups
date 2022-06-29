from pwn import *
from LibcSearcher import *

r = process("./welpwn")
elf = ELF("./welpwn")
