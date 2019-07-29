#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# @Author: smartdone
# @Date:   2019-07-01 11:00

from Simulator import *
from capstone import *

ret_addr = None
start_addr = 0


def hook_mem_access(uc, type, address, size, value, userdata):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    print 'pc:%x type:%d addr:%x size:%x' % (pc, type, address, size)
    # uc.emu_stop()
    return False

md = Cs(CS_ARCH_ARM64,CS_MODE_ARM)
md.detail = True #enable detail analyise

def reg_ctou(regname):#
    # This function covert capstone reg name to unicorn reg const.
    type1 = regname[0]
    if type1 == 'w' or type1 =='x':
        idx = int(regname[1:])
        if type1 == 'w':
            return idx + UC_ARM64_REG_W0
        else:
            if idx == 29:
                return  1
            elif idx == 30:
                return 2
            else:
                return idx + UC_ARM64_REG_X0
    elif regname=='sp':
        return 4
    return None

branch_control = 1

def hook_code(uc, address, size, user_data):
    global ret_addr
    global start_addr
    global  branch_control
    # print user_data
    instruction = uc.mem_read(address, size)
    # print ["0x%x" % item for item in block_starts]
    idc.set_color(address, idc.CIC_ITEM, 0xFFB6C1)
    # print ["0x%x" % item for item in instruction]
    _code = idc.GetDisasm(address)

    # print(type(_code), _code.startswith("CMP"), _code)
    # print("0x%016x \t%s" % (address, _code))

    if address in user_data and address != start_addr:
        print("address 0x%x" % address)
        uc.emu_stop()
        ret_addr = address
        return

    if "RET" == _code:
        ret_addr = -1
        uc.emu_stop()

    for ins in md.disasm(instruction, address):
        if ins.mnemonic == 'csel':
            print("csel 0x%x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
            regs = [reg_ctou(x) for x in ins.op_str.split(', ')]
            assert len(regs) == 4
            v1 = uc.reg_read(regs[1])
            v2 = uc.reg_read(regs[2])
            if branch_control == 1:
                uc.reg_write(regs[0], v1)
            else:
                uc.reg_write(regs[0], v2)
            uc.reg_write(UC_ARM64_REG_PC, address + size)


class FLASimulator(Simulator):
    def __init__(self, basic_blocks):
        super(FLASimulator, self).__init__()
        self.context = None
        self.basic_blocks = basic_blocks

    def emu_start(self, func_start, func_end):
        global ret_addr
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
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_access)
        mu.hook_add(UC_ERR_WRITE_UNMAPPED, hook_mem_access)

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

        if ret_addr != 0:
            tmp_addr = ret_addr
            ret_addr = None
            return tmp_addr

        return None

    def get_context(self, mu=None):
        if not mu:
            return self.context
        else:
            regs = []
            if self.arch == UC_ARCH_ARM:
                print("arm")
            elif self.arch == UC_ARCH_ARM64:
                print("arm64")
                for idx in range(UC_ARM64_REG_X0, UC_ARM64_REG_X28 + 1):
                    regs.append((idx, mu.reg_read(idx)))
            elif self.arch == UC_ARCH_X86:
                print("x86")

            self.context = regs
            # print "regs", regs

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
    global start_addr
    func_name = idc.GetFunctionName(func)
    func_data = idaapi.get_func(func)
    start = func_data.start_ea
    end = func_data.end_ea
    # print func_name, hex(start), hex(end)
    if func_name == "JNI_OnLoad":
        print func_name, hex(start), hex(end)
        f = idaapi.FlowChart(idaapi.get_func(start))
        basic_blocs = []
        for block in f:
            print("%x - %x [%d]:" % (block.start_ea, block.end_ea, block.id))
            block_start = block.start_ea
            block_end = block.end_ea
            basic_blocs.append(block_start)
        sim = FLASimulator(basic_blocs)
        sim.sp = UC_ARM64_REG_SP
        sim.arch = UC_ARCH_ARM64
        sim.mode = UC_MODE_ARM

        flow = {}
        start_addr = start
        queue = [(start, None)]

        while len(queue) > 0:
            env = queue.pop()
            pc = env[0]
            context = env[1]

            sim.set_context(context)

            if pc in flow.keys():
                print("0x%x in flow" % pc)
                continue

            flow[pc] = []
            start_addr = pc

            p = sim.emu_start(pc, end)

            if p:
                print("0x%x --> 0x%x" % (pc, p))
                flow[pc].append(p)
                queue.append((p, sim.get_context()))




