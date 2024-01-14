import logging
from tritondse import SymbolicExecutor, ProcessState
from pise.monitoring_phase import QueryRunner

logger = logging.getLogger(__name__)

# This interface describes a callsite that sends/receive messages in the binary, and therefore should be hooked
class SendReceiveCallSite:
    # This function should set the hook within the symbolic execution engine
    # In our case it gets the angr project with the executable loaded
    # Return value is ignored
    def set_hook(self, hooks_obj, callback_manager):
        raise NotImplementedError()

    # This function should extract the buffer pointer and the buffer length from the program state
    # It is given the call_context as angr's SimProcedure instance, which contains under call_context.state the program state
    # Should return: (buffer, length) tuple
    def extract_arguments(self, pstate): #should return msg addr + length
        raise NotImplementedError()

    # This function should return the suitable return value to simulate a successful send or receive from the callsite
    # It is given the buffer, the length and the call_context (which contains the state)
    # Should return: the return value that will be passed to the caller
    def get_return_value(self, buffer, pstate):
        raise NotImplementedError()


class AsyncHook:
    def resume(self):
        raise NotImplementedError()

    def emulate_recv(self):
        raise NotImplementedError()

class Hooks:
    def __init__(self, callsite_handlers) -> None:
        self.callsite_handlers = callsite_handlers
        #self.query_runner = query_runner
    
    def RecvHook(self, se : SymbolicExecutor, pstate : ProcessState, name : str, addr : int):
        msg_addr, length = self.callsite_handlers[1].extract_arguments(pstate)
        return pstate.query_runner.recvHook(pstate, se, msg_addr, length)
        
        ## TODO: check if this is the right place to skip instruction, i dont think so
        # pstate.cpu.program_counter = pstate.pop_stack_value()  # pop the return value
        # se.skip_instruction()
        
        return self.callsite_handlers[1].get_return_value(msg_addr, length, pstate)
    
    def SendHook(self, se : SymbolicExecutor, pstate : ProcessState, name : str, addr : int):
        msg, length = self.callsite_handlers[0].extract_arguments(pstate)
        # pstate.memory.read_string(msg_addr)
        return pstate.query_runner.sendHook(pstate, se, msg, length)
        
        ## TODO: check if this is the right place to skip instruction, i dont think so
        # pstate.cpu.program_counter = pstate.pop_stack_value()  # pop the return value
        # se.skip_instruction()
        
        return self.callsite_handlers[0].get_return_value(msg_addr, length, pstate)
