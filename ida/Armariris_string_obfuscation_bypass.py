#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# @Author: smartdone
# @Date:   2019-07-01 11:00

import idaapi
import idautils
import idc
import time

from Simulator import Simulator

sim = Simulator()
for func in idautils.Functions():
    func_name = idc.GetFunctionName(func)
    func_data = idaapi.get_func(func)
    start = func_data.start_ea
    end = func_data.end_ea
    # print(func_name, hex(start), hex(end))
    if "datadiv_decode" in func_name:
        sim.emu_start(start, end)

sim.patch_segment('.data')
sim.patch_segment('__data')

for seg in sim.segments:
    if ".data" == seg['name'] or "__data" == seg['name']:
        # 把data段全部undefined
        idc.MakeUnknown(seg['start'], seg['end'] - seg['start'], idaapi.DELIT_DELNAMES)
        # 调用ida重新解析data段
        idaapi.analyze_area(seg['start'], seg['end'])
        time.sleep(2)
        idaapi.clear_strlist()
        time.sleep(2)
        idaapi.build_strlist()

# 查询string的交叉引用，在引用位置添加备注
num = idaapi.get_strlist_qty()
print num
for idx in range(num):
    str_info = idaapi.string_info_t()
    idaapi.get_strlist_item(str_info, idx)
    str_cont = idc.GetString(str_info.ea, str_info.length, str_info.type)
    str_cont = str_cont.strip()
    refs = idautils.DataRefsTo(str_info.ea)
    for ref in refs:
        idc.MakeComm(ref, str_cont)

