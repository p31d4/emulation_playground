import unicorn
from unicorn.arm64_const import *
import capstone
import itertools
from elftools.elf.elffile import ELFFile
from pwn import *


# External functions
#------------------------------------------------------------------------------
def read_str(addr):
    str_bytes = b""
    while True:
        one_char = uc.mem_read(addr, 1)
        addr += 1
        if one_char == b"\x00":
            return str_bytes
        str_bytes += one_char


def strlen():
    _str = read_str(uc.reg_read(UC_ARM64_REG_X0))
    print(f"strlen({_str})")
    uc.reg_write(UC_ARM64_REG_X0, len(_str))
    uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))


def strcmp():
    _str1 = read_str(uc.reg_read(UC_ARM64_REG_X0))
    _str2 = read_str(uc.reg_read(UC_ARM64_REG_X1))
    print(f"strcmp({_str1}, {_str2})")
    if _str1 == _str2:
        uc.reg_write(UC_ARM64_REG_X0, 0)
    else:
        uc.reg_write(UC_ARM64_REG_X0, -1)
    uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))


def puts():
    _str = read_str(uc.reg_read(UC_ARM64_REG_X0))
    print("puts(" + _str.decode("utf-8") + ")")
    uc.reg_write(UC_ARM64_REG_X0, 1)
    uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
#------------------------------------------------------------------------------


# Elf segments
#------------------------------------------------------------------------------
elf = ELFFile(open("./guess_password_nopie", "rb"))

arch = unicorn.UC_ARCH_ARM64
mode = unicorn.UC_MODE_ARM | unicorn.UC_MODE_THUMB
uc = unicorn.Uc(arch, mode)

# This is normally done by the Operating System
for seg in elf.iter_segments():
    if "PT_LOAD" == seg.header.p_type:
        data = seg.data()
        page_size = seg.header.p_align
        mapsz = page_size * int((len(data) + page_size)/page_size)
        addr = seg.header.p_vaddr - (seg.header.p_vaddr % page_size)
        # Dirty hack to avoid (UC_ERR_WRITE_UNMAPPED)
        # it recognizes addresses up to 130432 and I don't know why
        if 0x0 < seg.header.p_offset:
            uc.mem_map(addr, mapsz + 1024)
        else:
            uc.mem_map(addr, mapsz)
        print(f"Segment created - Start 0x{addr:X} - Size 0x{mapsz:X}")
        uc.mem_write(seg.header.p_vaddr, data)
#------------------------------------------------------------------------------


# Stack initialization
#------------------------------------------------------------------------------
# arbitrary values
stack_addr = 0x4000000
stack_pointer = stack_addr + 0x100000
stack_size = 0x200000

uc.mem_map(stack_addr, stack_size)
print(f"Stack segment - Start 0x{stack_addr:X} - Size 0x{stack_size:X}")
uc.reg_write(UC_ARM64_REG_SP, stack_pointer)

start_addr = 0x400760  # found in Ghidra
end_addr   = 0x400804  # found in Ghidra

# Calling: ./guess_password_nopie bla
# register initialization
uc.reg_write(UC_ARM64_REG_X0, 2)  # number of args in argv

prog_name_addr = stack_pointer + 0x100
pass_addr = stack_pointer + 0x1000
argv_array_addr = stack_pointer + 0x200
# argv[0] and argv[1]
uc.mem_write(prog_name_addr, b'guess_password_nopie\x00')
uc.mem_write(pass_addr, b'bla\x00')

# argv to memory
uc.mem_write(argv_array_addr, p64(prog_name_addr))
uc.mem_write(argv_array_addr + 8, p64(pass_addr))
uc.reg_write(UC_ARM64_REG_X1, argv_array_addr)
#------------------------------------------------------------------------------

# Unicorn emulation
#------------------------------------------------------------------------------
def hook_block(uc, address, size, user_data):
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    data = bytes(uc.mem_read(address, size))
    for idx in md.disasm(data, address):
        instr = ("\t%s\t%s" %(idx.mnemonic, idx.op_str))
    print(f"-- Instruction at 0x{address:X}: {instr}")

    if uc.reg_read(UC_ARM64_REG_PC) == 0x40058C:
        strlen()

    if uc.reg_read(UC_ARM64_REG_PC) ==  0x4005DC:
        strcmp()

    if uc.reg_read(UC_ARM64_REG_PC) ==  0x4005CC:
        puts()


try:
    uc.hook_add(unicorn.UC_HOOK_CODE, hook_block)
    uc.emu_start(start_addr, until=end_addr)
except Exception as e:
    print(e)
#------------------------------------------------------------------------------
