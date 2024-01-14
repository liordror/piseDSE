import logging
import sys
sys.path.insert(1, '/home/liordror/PISE_dynamic/PISEServer')
from pise import sym_execution, server, hooks, monitoring_phase, hooks_dynamic
import examples.toy_example.dynamic_toy_client_inference


class ToySendHook(hooks.SendReceiveCallSite):

    def get_return_value(self, buff, length, call_context):
        # Something messed up with angr return value handling, so we simply set rax with the desired return value
        call_context.state.regs.rax = length

    def set_hook(self, p):
        p.hook_symbol('send', hooks.SendHook(self))

    def extract_arguments(self, call_context):
        length = call_context.state.regs.edx
        buffer = call_context.state.regs.rsi
        return buffer, length


class ToyRecvHook(hooks.SendReceiveCallSite):

    def get_return_value(self, buff, length, call_context):
        # Something messed up with angr return value handling, so we simply set rax with the desired return value
        call_context.state.regs.rax = length

    def set_hook(self, p):
        p.hook_symbol('recv', hooks.RecvHook(self))

    def extract_arguments(self, call_context):
        length = call_context.state.regs.edx
        buffer = call_context.state.regs.rsi
        return buffer, length


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    logging.basicConfig(filename = 'output_logger.txt')
    # logging.getLogger('angr').setLevel(logging.INFO)
    query_runner = sym_execution.QueryRunner('/home/liordror/PISE_project/PISE_DSE/PISEServer/examples/toy_example/toy_example', [ToySendHook(), ToyRecvHook()])
    #query_runner = sym_execution.QueryRunner('/home/sahar_milg/PISE_DSE/PISEServer/examples/toy_example/toy_example', [ToySendHook(), ToyRecvHook()])
    send_callsite = examples.toy_example.dynamic_toy_client_inference.ToySendCallSite()
    recv_callsite = examples.toy_example.dynamic_toy_client_inference.ToyRecvCallSite()
    hooks_obj = hooks_dynamic.Hooks([send_callsite, recv_callsite])
    dynamic_query_runner = monitoring_phase.QueryRunner('/home/liordror/PISE_project/PISE_DSE/PISEServer/examples/toy_example/toy_example', 
                                                            [send_callsite, recv_callsite],
                                                             hooks_obj)
    #dynamic_query_runner = monitoring_phase.QueryRunner('/home/sahar_milg/PISE_DSE/PISEServer/examples/toy_example/toy_example', 
    #                                                         [send_callsite, recv_callsite],
    #                                                         hooks_obj)
    s = server.Server(query_runner, dynamic_query_runner)
    s.listen()


if __name__ == "__main__":
    main()
