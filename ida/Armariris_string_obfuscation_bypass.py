#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# @Author: smartdone
# @Date:   2019-06-20 17:16


import idaapi
import idc
import idautils
import sys

# 把系统python的库加进来
sys.path.append('/usr/local/lib/python2.7/site-packages/')

from ida_nalt import get_input_file_path, get_imagebase
from keystone import *
from unicorn import *

# 获取输入文件
INPUT_FILE = str(get_input_file_path())
# 获取image base
IMAGE_BASE = get_imagebase()

# 将program rebase到0
if IMAGE_BASE != 0:
    idc.rebase_program(-IMAGE_BASE, idc.MSF_LDKEEP)

archs = [
    {
        "arch": UC_ARCH_X86,
        "mode": UC_MODE_64,
        "karch": KS_ARCH_X86,
        "kmode": KS_MODE_64
    },
    {
        "arch": UC_ARCH_X86,
        "mode": UC_MODE_32,
        "karch": KS_ARCH_X86,
        "kmode": KS_MODE_32
    },
    {
        "arch": UC_ARCH_ARM,
        "mode": UC_MODE_ARM,
        "karch": KS_ARCH_ARM,
        "kmode": KS_MODE_ARM
    },
    {
        "arch": UC_ARCH_ARM,
        "mode": UC_MODE_THUMB,
        "karch": KS_ARCH_ARM,
        "kmode": KS_MODE_THUMB
    },
    {
        "arch": UC_ARCH_ARM64,
        "mode": UC_MODE_ARM,
        "karch": KS_ARCH_ARM64,
        "kmode": KS_MODE_ARM
    },
    {
        "arch": UC_ARCH_ARM64,
        "mode": UC_MODE_THUMB,
        "karch": KS_ARCH_ARM64,
        "kmode": KS_MODE_THUMB
    },
]

data_div_decodes = []


# 获取指令集
def get_arch(_code, ea):
    print hex(ea)
    bin_code = idc.GetManyBytes(ea, 16)
    bin_code = [ord(item) for item in list(bin_code)]
    print bin_code

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
        data_div_decodes.append({"name": func_name, "start": start, "end": end})
        # 读取第一条指令，然后获取指令集
        code = idc.GetDisasm(start)
        arch = get_arch(code, start)
        if arch:
            pass
        else:
            print("Cannot get instruction set: `%x`" % start)

        print(hex(start), hex(end))

# disa = idc.GetDisasm(idc.here())
