#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# @Author: smartdone
# @Date:   2019-06-20 17:16


import idaapi
import idc
import idautils
import sys
from ida_loader import reload_file
import os

# 把系统python的库加进来
sys.path.append('/usr/local/lib/python2.7/site-packages/')

from ida_nalt import get_input_file_path, get_imagebase
from keystone import *
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *

# 获取输入文件
INPUT_FILE = str(get_input_file_path())
# 获取image base
IMAGE_BASE = get_imagebase()

INPUT_PATH = os.path.dirname(INPUT_FILE)

DEBUG = True

# # 将program rebase到0
# if IMAGE_BASE != 0:
#     idc.rebase_program(-IMAGE_BASE, idc.MSF_LDKEEP)

archs = [
    {
        "arch": UC_ARCH_X86,
        "mode": UC_MODE_64,
        "karch": KS_ARCH_X86,
        "kmode": KS_MODE_64,
        "sp": UC_X86_REG_RSP
    },
    {
        "arch": UC_ARCH_X86,
        "mode": UC_MODE_32,
        "karch": KS_ARCH_X86,
        "kmode": KS_MODE_32,
        "sp": UC_X86_REG_RSP
    },
    {
        "arch": UC_ARCH_ARM,
        "mode": UC_MODE_ARM,
        "karch": KS_ARCH_ARM,
        "kmode": KS_MODE_ARM,
        "sp": UC_ARM_REG_SP
    },
    {
        "arch": UC_ARCH_ARM,
        "mode": UC_MODE_THUMB,
        "karch": KS_ARCH_ARM,
        "kmode": KS_MODE_THUMB,
        "sp": UC_ARM_REG_SP
    }
]

data_div_decodes = []


# 获取指令集，不知道ida有什么api可以获取指令集。这里就用了keystone来判定了一下
def get_arch(_code, ea):
    bin_code = idc.GetManyBytes(ea, 16)
    bin_code = [ord(item) for item in list(bin_code)]

    for item in archs:
        try:
            ks = Ks(item['karch'], item['kmode'])
            encoding, _ = ks.asm(_code)
            is_this_arch = True
            for i in range(0, len(encoding)):
                if bin_code[i] != encoding[i]:
                    is_this_arch = False
            if is_this_arch:
                return item
        except:
            continue
    return None


# 获取字符串混淆的函数起始地址
for func in idautils.Functions():
    func_name = idc.GetFunctionName(func)
    if "datadiv_decode" in func_name:
        func_data = idaapi.get_func(func)
        start = func_data.start_ea
        end = func_data.end_ea

        # 读取第一条指令，然后获取指令集
        code = idc.GetDisasm(start)
        arch = get_arch(code, start)
        if arch:
            data_div_decodes.append({"name": func_name, "start": start, "end": end, "arch": arch})
        else:
            print("Cannot get instruction set: `%x`" % start)


def hook_code(uc, address, size, user_data):
    instruction = uc.mem_read(address, size)
    if instruction == b'\xc3':
        uc.emu_stop()

    if address == 0:
        uc.emu_stop()

    if DEBUG:
        _code = idc.GetDisasm(address)
        print("0x%08x %s" % (address, _code))


class Emu(object):
    def __init__(self, _data, _data_base, _text, _text_base):
        self.data = bytearray(_data)
        self.data_base = _data_base
        self.data_len = len(_data)
        self.text = bytearray(_text)
        self.text_base = _text_base
        self.text_len = len(_text)

        self.mapped_mem = []

    @staticmethod
    def get_base_and_len(base, length):
        _base = base - (base % (1024 * 1024))
        _length = (length / (1024 * 1024) + 1) * 1024 * 1024
        return _base, _length

    def unmap_mem(self, mu):
        for item in self.mapped_mem:
            mu.mem_unmap(item['base'], item['size'])
            print("unmap memory: base = 0x%08x, size = 0x%x" % (item['base'], item['size']))

    def execute_function(self, function_data):
        print("execute `%s` on 0x%x" % (function_data['name'], function_data['start']))
        print(function_data)
        mu = Uc(function_data['arch']['arch'], function_data['arch']['mode'])

        stack_base = 0
        stack_size = 1024 * 1204 * 2
        sp = 0

        if abs(self.data_base - self.text_base) < (1024 * 1024 * 2):
            __base = 0
            # 分配到同一块内存
            if self.data_base < self.text_base:
                __base = self.data_base
            else:
                __base = self.text_base
            __len = self.data_len + self.text_len + 1024 * 1024 * 2
            alloc_base, alloc_len = Emu.get_base_and_len(__base, __len)
            mu.mem_map(alloc_base, alloc_len)
            self.mapped_mem.append({"base": alloc_base, "size": alloc_len})

            # 写text段
            mu.mem_write(self.text_base, bytes(self.text))

            # 写data段
            mu.mem_write(self.data_base, bytes(self.data))

            stack_base = alloc_base + alloc_len
            sp = stack_base + 1024 * 1024
            mu.mem_map(stack_base, stack_size)
            mu.reg_write(function_data['arch']['sp'], sp)
            self.mapped_mem.append({"base": stack_base, "size": stack_size})
        else:
            # 分配多块内存
            # 将data段映射到内存中
            __data_base, _data_len = Emu.get_base_and_len(self.data_base, self.data_len)
            # print hex(__data_base), hex(_data_len)
            mu.mem_map(__data_base, _data_len)
            self.mapped_mem.append({"base": __data_base, "size": _data_len})
            mu.mem_write(self.data_base, bytes(self.data))

            # 将text段映射到内存中
            __text_base, _text_len = Emu.get_base_and_len(self.text_base, self.text_len)
            # print hex(__text_base), hex(_text_len)
            mu.mem_map(__text_base, _text_len)
            self.mapped_mem.append({"base": __text_base, "size": _text_len})
            mu.mem_write(self.text_base, bytes(self.text))

            if __text_base > __data_base:
                stack_base = __text_base + _text_len
            else:
                stack_base = __data_base + _data_len

            mu.mem_map(stack_base, stack_size)
            self.mapped_mem.append({"base": stack_base, "size": stack_size})
            sp = stack_base + 1024 * 1024

            mu.reg_write(function_data['arch']['sp'], sp)

        mu.hook_add(UC_HOOK_CODE, hook_code)

        mu.emu_start(function_data['start'], function_data['end'])

        self.data = mu.mem_read(self.data_base, self.data_len)
        self.text = mu.mem_read(self.text_base, self.text_len)

        self.unmap_mem(mu)

        print("Simulation execution function %s ends" % function_data['name'])

    def get_data(self):
        return self.data


_data = None
_data_base = 0

_text = None
_text_base = 0
for seg in idautils.Segments():
    if idc.SegName(seg) == "__data" or idc.SegName(seg) == ".data":
        start = idc.SegStart(seg)
        end = idc.SegEnd(seg)
        length = end - start
        d = idc.GetManyBytes(start, length)
        d = [ord(item) for item in list(d)]
        _data = d
        _data_base = start
    if idc.SegName(seg) == "__text" or idc.SegName(seg) == ".text":
        start = idc.SegStart(seg)
        end = idc.SegEnd(seg)
        length = end - start
        d = idc.GetManyBytes(start, length)
        d = [ord(item) for item in list(d)]
        _text = d
        _text_base = start

print("data: 0x%08x, len: %d" % (_data_base, len(_data)))
print("text: 0x%08x, len: %d" % (_text_base, len(_text)))
emu = Emu(_data, _data_base, _text, _text_base)

for func in data_div_decodes:
    try:
        emu.execute_function(func)
    except Exception as e:
        print(e)
        print("Execution function `%s` failed.(The function address is 0x%x)" % (func['name'], func['start']))

# path data
decode_data = emu.get_data()
for i in range(len(decode_data)):
    idc.patch_byte(_data_base + i, decode_data[i])
