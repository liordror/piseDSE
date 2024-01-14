import logging

from pise import server
import pise.hooks_dynamic
import pise.monitoring_phase
from tritondse import callbacks, ProcessState

class ToySendCallSite(pise.hooks_dynamic.SendReceiveCallSite):
    
    def __init__(self) -> None:
        super().__init__()
    
    def set_hook(self, hooks_obj, callback_manager):
        callback_manager.register_pre_imported_routine_callback('recv', hooks_obj.RecvHook)
    
    def extract_arguments(self, pstate):
        length = pstate.cpu.edx
        buffer = pstate.memory.read(pstate.cpu.rsi, length)
        return buffer, length
    
    def get_return_value(self, buffer, length, pstate):
        pstate.cpu.rax = length
        return length
    
class ToyRecvCallSite(pise.hooks_dynamic.SendReceiveCallSite):
    
    def __init__(self) -> None:
        super().__init__()
    
    def set_hook(self, hooks_obj, callback_manager):
        callback_manager.register_pre_imported_routine_callback('send', hooks_obj.SendHook)
        
    def extract_arguments(self, pstate : ProcessState):
        length = pstate.cpu.edx
        buffer = pstate.cpu.rsi
        return buffer, length
    
    def get_return_value(self, buffer, length, pstate):
        pstate.cpu.rax = length
        return length
    
    



def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    # logging.getLogger('angr').setLevel(logging.INFO)
    query_runner = pise.monitoring_phase.QueryRunner('examples/toy_example/toy_example', [ToySendCallSite(), ToyRecvCallSite()])
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
    

