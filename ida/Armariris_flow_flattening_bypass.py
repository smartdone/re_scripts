#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# @Author: smartdone
# @Date:   2019-07-01 11:00

import idaapi
import idc
import idautils
import sys

sys.path.append('/usr/local/lib/python2.7/site-packages/')

from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from capstone import *

IMAGE_BASE = idaapi.get_imagebase()
DEBUG = True

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def hook_code(uc, address, size, user_data):
    instruction = uc.mem_read(address, size)
    if instruction == b'\xc3':
        uc.emu_stop()

    if address == 0:
        uc.emu_stop()

    if address != 0 and address != IMAGE_BASE:
        idc.set_color(address, idc.CIC_ITEM, 0xFFB6C1)

    if DEBUG:
        # _code = idc.GetDisasm(address)
        # print("0x%016x \t%s" % (address, _code))
        for i in md.disasm(instruction, address):
            print("0x%08x:\t%s\t\t%s" % (i.address, i.mnemonic, i.op_str))


class Simulator(object):
    def __init__(self):
        self.segments = []
        self.mem_map = []

        self.ph_flag = None
        self.ph_id = None

        self.arch = None
        self.mode = None

        self.sp = None
        self.bp = None

        self.stack_base = 0
        self.stack_length = 1024 * 1024 * 2

        self.get_segments()
        self.get_arch()
        self.get_unicorn_mem_pages()

    def get_segments(self):
        if len(self.segments) == 0:
            for seg in idautils.Segments():
                name = idc.SegName(seg)
                start = idc.SegStart(seg)
                end = idc.SegEnd(seg)
                d = idc.GetManyBytes(start, end - start)
                d = [ord(item) for item in list(d)]
                seg_data = {"name": name, "start": start, "end": end, "data": d}
                self.segments.append(seg_data)
        return self.segments

    def get_arch(self):
        self.ph_id = idaapi.ph.id
        self.ph_flag = idaapi.ph.flag

        if self.ph_id == idaapi.PLFM_386 and self.ph_flag & idaapi.PR_USE64:
            self.arch = UC_ARCH_X86
            self.mode = UC_MODE_64
            self.sp = UC_X86_REG_RSP
            self.bp = UC_X86_REG_RBP
        elif self.ph_id == idaapi.PLFM_386 and self.ph_flag & idaapi.PR_USE32:
            self.arch = UC_ARCH_X86
            self.mode = UC_MODE_32
            self.sp = UC_X86_REG_RSP
            self.bp = UC_X86_REG_RBP
        elif self.ph_id == idaapi.PLFM_ARM and self.ph_flag & idaapi.PR_USE32:
            self.arch = UC_ARCH_ARM
            self.mode = UC_MODE_ARM
            self.sp = UC_ARM_REG_SP
            self.bp = UC_ARM_REG_SP
        elif self.ph_id == idaapi.PLFM_ARM and self.ph_flag & idaapi.PR_USE64:
            self.arch = UC_ARCH_ARM64
            self.mode = UC_MODE_ARM
            self.sp = UC_ARM64_REG_SP
            self.bp = UC_ARM64_REG_SP

    def is_thumb_ea(self, ea):
        if self.ph_id == idaapi.PLFM_ARM and not self.ph_flag & idaapi.PR_USE64:
            if idaapi.IDA_SDK_VERSION >= 700:
                t = idaapi.get_sreg(ea, "T")
            else:
                t = idaapi.get_segreg(ea, 20)
            return t is not idaapi.BADSEL and t is not 0
        else:
            return False

    def emu_start(self, func_start, func_end):
        if self.arch == UC_ARCH_ARM:
            if self.is_thumb_ea(func_start):
                print("thumb mode")
                self.mode = UC_MODE_THUMB
        mu = Uc(self.arch, self.mode)

        for item in self.mem_map:
            Simulator.map_memory(mu, item['start'], item['length'])

        # 给栈分配内存
        Simulator.map_memory(mu, self.stack_base, self.stack_length)

        # 写入数据
        for item in self.segments:
            Simulator.write_memory(mu, item['start'], item['data'])

        # 配置寄存器
        mu.reg_write(self.sp, self.stack_base + 1024 * 1024)
        print hex(mu.reg_read(self.sp))
        print hex(mu.reg_read(self.bp))

        # mu.reg_write(self.bp, self.stack_base + 1024 * 1024)

        mu.hook_add(UC_HOOK_CODE, hook_code)

        try:
            # 开始执行
            if self.mode == UC_MODE_THUMB:
                mu.emu_start(func_start + 1, func_end)
            else:
                mu.emu_start(func_start, func_end)
        except Exception as e:
            print("Err: %s. Execution function failed.(The function address is 0x%x)" % (e, func_start))

        # 读取数据
        for item in self.segments:
            _data = Simulator.read_memory(mu, item['start'], item['end'])
            self.replace_data(item['start'], _data)

        # unmap memory
        for item in self.mem_map:
            Simulator.unmap_memory(mu, item['start'], item['length'])

        Simulator.unmap_memory(mu, self.stack_base, self.stack_length)

    def replace_data(self, start, data):
        for i in range(len(self.segments)):
            if self.segments[i]['start'] == start:
                self.segments[i]['data'] = data

    @staticmethod
    def write_memory(mu, start, data):
        if isinstance(data, list):
            data = bytearray(data)
        mu.mem_write(start, bytes(data))

    @staticmethod
    def read_memory(mu, start, end):
        _length = end - start
        _data = mu.mem_read(start, _length)
        return _data

    @staticmethod
    def map_memory(mu, start, _length):
        mu.mem_map(start, _length)
        print("map memory: offset 0x%x, size: 0x%x" % (start, _length))

    @staticmethod
    def unmap_memory(mu, start, _length):
        mu.mem_unmap(start, _length)
        print("unmap memory: offset 0x%x, size: 0x%x" % (start, _length))

    @staticmethod
    def get_base_and_len(base, length):
        _base = base - (base % (1024 * 1024))
        _length = (length / (1024 * 1024) + 1) * 1024 * 1024
        return _base, _length

    def get_unicorn_mem_pages(self):
        if len(self.segments) == 0:
            return None

        if len(self.mem_map) == 0:
            seg = None
            pages = []
            for item in self.segments:
                if not seg:
                    seg = {'start': item['start'], 'end': item['end']}
                else:
                    if item['start'] - seg['end'] > (1024 * 1024 * 2):
                        pages.append(seg)
                        seg = {'start': item['start'], 'end': item['end']}
                    else:
                        seg['end'] = item['end']
            pages.append(seg)

            for item in pages:
                start, length = Simulator.get_base_and_len(item['start'], item['end'] - item['start'])
                self.mem_map.append({"start": start, "length": length})

            for item in self.mem_map:
                if self.stack_base < item['start'] + item['length']:
                    self.stack_base = item['start'] + item['length']

        return self.mem_map


# # sim = Simulator()
# for func in idautils.Functions():
#     func_name = idc.GetFunctionName(func)
#     func_data = idaapi.get_func(func)
#     start = func_data.start_ea
#     end = func_data.end_ea
#     print(func_name, hex(start), hex(end))

sim = Simulator()
sim.emu_start(0x400530, 0x400726)
