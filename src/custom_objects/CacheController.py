from m5.params import *
from m5.proxy import *
from m5.objects import *
from m5.objects.ClockedObject import ClockedObject


class CacheController(ClockedObject):
    type = 'CacheController'
    cxx_header = "custom_objects/cache_controller.hh"
    cxx_class = 'gem5::CacheController'

#   inst_port = SlavePort("CPU side port, receives requests")
    data_port = ResponsePort("CPU side port, recieves requests")
#   mem_side_inst_port = MasterPort("Memory side port, sends requests, instr")
    mem_side_data_port_1 = MasterPort("Memory side port, sends requests, data")
    mem_side_data_port_2 = MasterPort("Memory side port, sends requests, data")
    active_port = Param.Int(0, "Active port")
