#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# @Author: smartdone
# @Date:   2019-07-01 11:00

from Simulator import *
from capstone import *
from capstone.arm64_const import *
from capstone.x86_const import *
from capstone.arm_const import *

retaddr = 0


def hook_code(uc, address, size, user_data):
    global retaddr
    block_starts = [item['start'] for item in user_data]

    if address in block_starts:
        uc.emu_stop()
        retaddr = address
        return


class FLASimulator(Simulator):
    def __init__(self, basic_blocks):
        super(FLASimulator, self).__init__()
        self.context = None
        self.basic_blocks = basic_blocks

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

        mu.hook_add(htype=UC_HOOK_CODE, callback=hook_code, user_data=self.basic_blocks)

        self.set_context(mu, self.context)

        try:
            # 开始执行
            if self.mode == UC_MODE_THUMB:
                mu.emu_start(func_start + 1, func_end)
            else:
                mu.emu_start(func_start, func_end)
        except Exception as e:
            print("Err: %s. Execution function failed.(The function address is 0x%x)" % (e, func_start))

        self.get_context(mu)

        # 读取数据
        for item in self.segments:
            _data = Simulator.read_memory(mu, item['start'], item['end'])
            self.replace_data(item['start'], _data)

        # unmap memory
        for item in self.mem_map:
            Simulator.unmap_memory(mu, item['start'], item['length'])

        Simulator.unmap_memory(mu, self.stack_base, self.stack_length)

    def get_context(self, mu=None):
        if not mu:
            return self.context
        else:
            regs = []
            if self.arch == UC_ARCH_ARM:
                pass
            elif self.arch == UC_ARCH_ARM64:
                for idx in range(UC_ARM64_REG_X0, UC_ARM64_REG_X28 + 1):
                    regs.append((idx, mu.reg_read(idx)))
            elif self.arch == UC_ARCH_X86:
                pass

            self.context = regs

            return self.context

    def set_context(self, mu=None, _context=None):
        if not mu:
            self.context = _context
        else:
            if _context:
                self.context = _context
                for item in self.context:
                    mu.reg_write(item[0], item[1])


for func in idautils.Functions():
    func_name = idc.GetFunctionName(func)
    func_data = idaapi.get_func(func)
    start = func_data.start_ea
    end = func_data.end_ea
    # print func_name, hex(start), hex(end)
    if func_name == "_ZN5crazy5Error6AppendEPKc":
        print func_name, hex(start), hex(end)
        func_bytes = idc.GetManyBytes(start, end - start)
        func_bytes = [ord(item) for item in list(func_bytes)]
        func_bytes = bytearray(func_bytes)
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = True  # enable detail analyise

        basic_block = []
        bloc = {}
        isNewBlock = True

        for i in md.disasm(func_bytes, start):
            # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
            if isNewBlock:
                isNewBlock = False
                bloc['start'] = i.address
                bloc['ins'] = []
            bloc['ins'].append(i)

            if len(i.groups) > 0:
                isNewBlock = True
                bloc['end'] = i.address
                bloc['dead'] = False
                for op in i.operands:
                    if op.type == ARM64_OP_IMM:
                        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                        bloc['next'] = op.value.imm
                        # print("next: 0x%x" % op.value.imm)
                        if op.value.imm == i.address:
                            bloc['dead'] = True
                            idc.set_color(i.address, idc.CIC_ITEM, 0x0000ff)
                            idc.MakeComm(i.address, "Infinite loop")
                basic_block.append(bloc)
                bloc = {}

        # print(len(basic_block))
        # for item in basic_block:
        #     print("loc_%x" % item['start'])
        #     for i in item['ins']:
        #         print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        #     print("\n")

        queue = [(start, None)]
        flow = {}

        while len(queue) > 0:
            env = queue.pop()
            pc = env[0]
            context = env[1]
