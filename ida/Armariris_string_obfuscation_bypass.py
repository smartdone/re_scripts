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

BINARY_DATA = None

INPUT_PATH = os.path.dirname(INPUT_FILE)

with open(INPUT_FILE, "rb") as f:
    BINARY_DATA = f.read()

BINARY_LENGTH = len(BINARY_DATA)

DEBUG = True

print("binary len %d" % BINARY_LENGTH)

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


# 获取指令集
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

    if address == 0 or address == IMAGE_BASE:
        uc.emu_stop()

    if DEBUG:
        _code = idc.GetDisasm(address)
        print("0x%08x 0x%x %s" % (address, uc.reg_read(UC_X86_REG_RSP), _code))
        print("dl = 0x%x" % uc.reg_read(UC_X86_REG_DL))


class Emu(object):
    def __init__(self, data):
        self.data = data

    def execute_function(self, function_data):
        print("execute `%s` on 0x%x" % (function_data['name'], function_data['start']))
        print(function_data)
        mu = Uc(function_data['arch']['arch'], function_data['arch']['mode'])
        mu.mem_map(IMAGE_BASE, 1024 * 1024 * 4)
        mu.mem_write(IMAGE_BASE, self.data)

        STACK = IMAGE_BASE + 1024 * 1024 * 3
        mu.reg_write(function_data['arch']['sp'], STACK)

        mu.hook_add(UC_HOOK_CODE, hook_code)

        mu.emu_start(function_data['start'], function_data['end'])

        self.data = mu.mem_read(IMAGE_BASE, BINARY_LENGTH)

        print("Simulation execution function %s ends" % function_data['name'])

    def get_data(self):
        return self.data


emu = Emu(BINARY_DATA)

for func in data_div_decodes:
    try:
        emu.execute_function(func)
        # 将模拟执行成功的代码改为ret或者bx lr
        if func['arch']['arch'] == UC_ARCH_X86:
            ks = Ks(func['arch']['karch'], func['arch']['kmode'])
            encoding, _ = ks.asm('ret')
            for i in range(0, len(encoding), 1):
                emu.data[func['start'] + i] = encoding[i]
        elif func['arch']['arch'] == UC_ARCH_ARM:
            ks = Ks(func['arch']['karch'], func['arch']['kmode'])
            encoding, _ = ks.asm('bx lr')
            for i in range(0, len(encoding), 1):
                emu.data[func['start'] + i] = encoding[i]
    except Exception as e:
        print("Execution function `%s` failed.(The function address is 0x%x)" % (func['name'], func['start']))

data = emu.get_data()
print "after", data[0x1030:0x1030 + 10]

# FIXED_FILE = os.path.join(INPUT_PATH, "%s.dec" % os.path.basename(INPUT_FILE))
# with open(FIXED_FILE, "wb+") as f:
#     f.write(BINARY_DATA[:0x34])
#     f.write(data[0x34:])
#     f.flush()
