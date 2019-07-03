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
    if "datadiv_decode" in func_name and not ("j_.datadiv_decode" in func_name):
        sim.emu_start(start, end)

sim.patch_segment('data')

for seg in sim.segments:
    if "data" in seg['name']:
        # 把data段全部undefined
        print("MakeUnknown %s" % seg['name'])
        idc.MakeUnknown(seg['start'], seg['end'] - seg['start'], idaapi.DELIT_DELNAMES)
        # 调用ida重新解析data段
        print("analyze area: 0x%x - 0x%x" % (seg['start'], seg['end']))
        idaapi.analyze_area(seg['start'], seg['end'])
        # idaapi.clear_strlist()
        # idaapi.build_strlist()

# 查询string的交叉引用，在引用位置添加备注
s = idautils.Strings(False)
s.setup()
for i, str_info in enumerate(s):
    if str_info:
        # print("%x: len=%d  index=%d-> '%s'" % (str_info.ea, str_info.length, i, str(str_info)))
        str_cont = str(str_info)
        refs = idautils.DataRefsTo(str_info.ea)
        for ref in refs:
            idc.MakeComm(ref, str_cont)
