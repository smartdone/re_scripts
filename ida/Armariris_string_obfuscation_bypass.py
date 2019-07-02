#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# @Author: smartdone
# @Date:   2019-07-01 11:00

import idaapi
import idautils
import idc

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

sim.patch_segment('data')
# idaapi.analyze_area(sim.segments)
for seg in sim.segments:
    if "data" in seg['name']:
        # 把data段全部undefined
        idc.MakeUnknown(seg['start'], seg['end'] - seg['start'], idaapi.DELIT_DELNAMES)
        # 调用ida重新解析data段
        idaapi.analyze_area(seg['start'], seg['end'])
