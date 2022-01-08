# coding:utf-8
from PwnContext import *
import os
import sys
import time
import struct
import requests


def clear(signum=None, stack=None):
    os.system('rm -f /tmp/gdb_symbols* /tmp/gdb_pid /tmp/gdb_script')
    info('Delete all debugging information')
    exit(0)

def gen_fmt_test(a,b):
    res = ''
    for i in range(a,b+1):
        res+= '%'+str(i)+'$x,'
    return res

def config(binary):
    global elf,rop,libc
    elf = ELF(binary)
    rop = ROP(binary)
    context.binary = binary

def connect(_mode,binary,ip,port,_qm_port):
    global r,libc
    context.log_level = 'debug'
    PROCESS_CONFIG = ["", "-L", "./" ,binary]



    # LIBC_CONFIG
    try:
        libc = elf.libc
    except:
        exit("[-] Unknow libc, Please manually specify") #delete me
        libc = ELF("Manually_specify_libc")

    # PROCESS_CONFIG
    if context.arch in ['amd64','i386']:
        PROCESS_CONFIG = binary
    else:
        if context.arch == 'mips':
            if context.endian == 'little':
                PROCESS_CONFIG[0] = "qemu-mipsel"
            if context.endian == 'big':
                PROCESS_CONFIG[0] = "qemu-mips"
        elif context.arch == 'arm':
            if context.endian == 'little':
                PROCESS_CONFIG[0] = "qemu-arm"
            if context.endian == 'big':
                PROCESS_CONFIG[0] = "qemu-armeb"
        else:
            exit("[-] Unknow Arch, Please manually specify") #delete me
            PROCESS_CONFIG[0] = "your_qemu_arch"
            
    # MODE_CONFIG
    if _mode not in ["local", "remote", "debug"]:
        exit("[-] Error Mode.")
    if _mode == "remote":
        r = remote(ip,port)
    if _mode == "local":
        r = process(PROCESS_CONFIG)
    if _mode == "debug":
        context.terminal = ['tmux','splitw','-h']
        try:
            PROCESS_CONFIG.insert(1,'-g')
            PROCESS_CONFIG.insert(2,str(_qm_port))
        except:
            pass
        r = process(PROCESS_CONFIG)


#################GLOBAL_CONFIG#################
_REMOTE_ADDR        = "IP"
_REMOTE_PORT        = "PORT"
_ELF_FILE           = "./ELF_FILE"
_QEMU_DEBUG_PORT    = "2233"
_MODE               = "debug" #[local, remote, debug]

###############################################



config(_ELF_FILE)
connect(_MODE,_ELF_FILE,_REMOTE_ADDR,_REMOTE_PORT,_QEMU_DEBUG_PORT)
# functions for quick script
sd       = lambda data               :r.send(str(data))        #in case that data is an int
sa      = lambda delim,data         :r.sendafter(str(delim), str(data)) 
sl      = lambda data               :r.sendline(str(data)) 
sla     = lambda delim,data         :r.sendlineafter(str(delim), str(data)) 
rv       = lambda numb=4096          :r.recv(numb)
rud      = lambda delims, drop=True  :r.recvuntil(delims, drop)
ru      = lambda delims, drop=False  :r.recvuntil(delims, drop)
rl      = lambda                    :r.recvline()
irt     = lambda                    :r.interactive()
rs      = lambda *args, **kwargs    :r.start(*args, **kwargs)
dbg     = lambda gs='', **kwargs    :gdb.attach(r,gdbscript=gs, **kwargs)
# misc functions
uu32    = lambda data   :u32(data.ljust(4, '\0'))
uu64    = lambda data   :u64(data.ljust(8, '\0'))
# leak : uu64(ru('\x7f',drop=False)[-6:])
leak    = lambda name,addr :log.success('{} = {:#x}'.format(name, addr))
def lg(s,addr):
    success('\033[1;33;40m%s => \033[0m\033[1;32;40m0x%x\033[0m'%(s,addr))

try:
    one_gg = one_gadgets(libc,libc.address)
except:
    pass
###############################################




irt()
clear()
