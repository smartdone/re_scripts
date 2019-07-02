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