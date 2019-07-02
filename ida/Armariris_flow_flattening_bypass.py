#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# @Author: smartdone
# @Date:   2019-07-01 11:00
import idaapi
import idautils
import idc

# from Simulator import Simulator
#
# sim = Simulator()
# for func in idautils.Functions():
#     func_name = idc.GetFunctionName(func)
#     func_data = idaapi.get_func(func)
#     start = func_data.start_ea
#     end = func_data.end_ea
#     if "func2" in func_name:
#         # chunks = idautils.Heads(start, end)
#         # for item in chunks:
#         #     print hex(item)
#         #     idaapi.isFlow()
#         #     print idaapi.isCode(idc.GetFlags(item))
#         for head in idautils.Heads(start, end):
#             if idaapi.isCode(idc.GetFlags(head)):
#                 refs = idautils.CodeRefsFrom(head, 0)
#                 refs = set(filter(lambda x: x >= start and x <= end, refs))
#                 if refs:
#                     next_head = idc.NextHead(head, end)
#                     if idaapi.isFlow(idc.GetFlags(next_head)):
#                         print "next head 0x%x" % next_head
#                 x = ["0x%x" % ref for ref in refs]
#
#     # print(func_name, hex(start), hex(end))
#     # if "func2" in func_name:
#     #     sim.emu_start(start, end)

for func in idautils.Functions():
    func_name = idc.GetFunctionName(func)
    func_data = idaapi.get_func(func)
    start = func_data.start_ea
    end = func_data.end_ea
    if "datadiv" in func_name:
        # refs = idautils.DataRefsFrom(start)
        # print ["0x%x" % ref for ref in refs]
        for item in idautils.FuncItems(start):

            refs = idautils.XrefsTo(start, 0)
            for ref in refs:
                print dir(ref)
                print "0x%x" % ref.to
                print "0x%x" % ref.frm
                print ref.iscode
            # refs = ["0x%x" % ref for ref in refs]
            # if refs:
            #     print "0x%x" % item
            #     print refs
