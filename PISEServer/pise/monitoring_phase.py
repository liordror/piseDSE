import copy
import logging

import tritondse
from tritondse import SymbolicExecutor, ProcessState, callbacks
from tritondse import SymbolicExecutor, Config, Seed, CompositeData
from tritondse import Program, SeedFormat
import triton
from pise.entities import MessageTypeSymbol


NUM_SOLUTIONS = 10
logger = logging.getLogger(__name__)

class QueryRunner:
    def __init__(self, file, callsites_to_monitor, hooks_obj):
        self.file = file
        self.project  = Program(file)
        self.mode = None
        self.callsites_to_monitor = callsites_to_monitor
        self.hooks_obj = hooks_obj
        self.callback_manager = callbacks.CallbackManager()
        self.set_membership_hooks()
        #self.probing_cache = ProbingCache()
        self.state_stack = []
        self.inputs = None
        self.monitoring_result = False
        self.beforeHookPstate = None    
        self.probing_initial_pstates = []   
    
    def sendHook(self, pstate, se, msg, length):
        #we are in monitoring phase
        logger.debug("got to send hook")
        # logger.debug(len(self.inputs))
        # print(self.inputs)
        if pstate.monitoring_position < len(self.inputs):
            if self.inputs[pstate.monitoring_position].type == 'SEND':
                logger.debug(f"send msg: {msg}")
                logger.debug("predicates: " + str(self.inputs[pstate.monitoring_position].predicate.items()))
                for (byte, val) in self.inputs[pstate.monitoring_position].predicate.items():
                    if int(byte) >= length:
                        continue
                    if msg[int(byte)] != val:
                        se.abort()
                        #new path from stack
                pstate.monitoring_position += 1
                if pstate.monitoring_position == len(self.inputs):
                    print("updated")
                    self.monitoring_result = True
                    se.abort()
                    #save final state
            else:
                se.abort()
                #new path from stack
        return length
    
    def recvHook(self, pstate, se, msg_addr, length):
        logger.debug("got to recv hook")
        # logger.debug(len(self.inputs))
        # logger.debug(f"monitoring_pos: {pstate.monitoring_position}")
        if pstate.monitoring_position < len(self.inputs):
            if self.inputs[pstate.monitoring_position].type == 'RECEIVE':
                logger.debug("predicates: " + str(self.inputs[pstate.monitoring_position].predicate.items()))
                preds = self.inputs[pstate.monitoring_position].predicate.items()
                length = min(length, max([int(byte) for (byte, val) in preds]))
                # TODO: state_stack is empty: maybe add to symbolic path predicate??  
                
                msg = b' ' * length
                msg_l = list(msg)
                for (byte, val) in preds:
                    if int(byte) < length:
                        msg_l[int(byte)] = val
                logger.debug(msg_l)
                msg = bytes(msg_l)
                pstate.memory.write(msg_addr, msg)
                
                '''
                for (byte, val) in preds:
                    sym_byte = pstate.read_symbolic_memory_byte(msg_addr + int(byte))
                    constraint = sym_byte.getAst() == val
                    pstate.push_constraint(constraint)
                '''
                
                pstate.monitoring_position += 1
                if pstate.monitoring_position == len(self.inputs):
                    print("updated")
                    self.monitoring_result = True
                    se.abort()
                    #save final state
            else:
                se.abort()
                #new path from stack
        return length
    
    
    def beforeBranchHook(self, se : SymbolicExecutor, pstate: ProcessState, opcode: triton.OPCODE):
        new_pstate = copy.copy(pstate) ## TODO: change to deepcopy or something else
        logger.debug("got to before branch hook")
        if not self.beforeHookPstate: # save pstate before branch for other path
            self.beforeHookPstate = new_pstate
        else:
            logger.debug("before branch hook error - there is before branch pstate - some error in last afterBranchHook")
            exit()
        
    def afterBranchHook(self, se : SymbolicExecutor, pstate: ProcessState, opcode: triton.OPCODE):
        new_pstate = None
        logger.debug("got to after branch hook")
        logger.debug(self.state_stack)
        if self.beforeHookPstate:
            if pstate.second_path_flag == False:
            # if self.beforeHookPstate.second_path_stack.pop() == False:
                logger.debug("not second path!")
                new_pstate = self.beforeHookPstate
                if(pstate.is_path_predicate_updated()):
                    logger.debug("adding state to state_stack")
                    constraints = pstate.last_branch_constraint
                    new_pstate.push_constraint(not constraints)
                    # new_pstate.second_path_stack.append(True)
                    self.state_stack.append(new_pstate)
            pstate.second_path_flag == False
            self.beforeHookPstate = None
        else:
            logger.debug("after branch hook error - there is no before branch pstate")
            exit()
            
    ##########################
    def beforeBranchHook(self, se : SymbolicExecutor, pstate: ProcessState, opcode: triton.OPCODE):
        new_pstate = copy.copy(pstate) 
        if not self.beforeHookPstate: # save pstate before branch for other path
            self.beforeHookPstate = new_pstate
        else:
            exit()
        
    def afterBranchHook(self, se : SymbolicExecutor, pstate: ProcessState, opcode: triton.OPCODE):
        new_pstate = None
        if self.beforeHookPstate:
            if pstate.second_path_flag == False:
                new_pstate = self.beforeHookPstate
                if(pstate.is_path_predicate_updated()):
                    constraints = pstate.last_branch_constraint
                    new_pstate.push_constraint(not constraints)
                    self.state_stack.append(new_pstate)
            pstate.second_path_flag == False
            self.beforeHookPstate = None
        else:
            exit()
    
    #####################
      
         
    def socketHook(self, se : SymbolicExecutor, pstate : ProcessState, name : str, addr : int):
        logger.debug("in socket hook")
        pstate.write_register("rax", 3)
        # pstate.cpu.program_counter = pstate.pop_stack_value()  # pop the return value
        # se.skip_instruction()
    
    def inetPtonHook(self, se : SymbolicExecutor, pstate : ProcessState, name : str, addr : int):
        logger.debug("in inet_pton hook")
        pstate.write_register("rax", 1)
        # pstate.cpu.program_counter = pstate.pop_stack_value()  # pop the return value
        # se.skip_instruction()
    
    def connectHook(self, se : SymbolicExecutor, pstate : ProcessState, name : str, addr : int):
        logger.debug("in connect hook")
        pstate.write_register("rax", 0)
        # pstate.cpu.program_counter = pstate.pop_stack_value()  # pop the return value
        # se.skip_instruction()
    

    def executionEnded(self, se: SymbolicExecutor, pstate: ProcessState):
        logger.debug("got to end of exe path")
        # logger.debug(self.state_stack)
        if pstate.monitoring_position == len(self.inputs):
            self.probing_initial_pstates.append(pstate)
        if len(self.state_stack) > 0:
            print("loading a new pstate from state_stack")
            new_pstate = self.state_stack.pop()
            new_pstate.second_path_flag = True
            
            config = Config(seed_format=SeedFormat.COMPOSITE)
            seed = Seed(CompositeData())
            
            new_se = SymbolicExecutor(config, seed)
            new_se.cbm =self.callback_manager
            new_se.load_process(new_pstate)
            new_se.run()    
    
    def startHook(self, se: SymbolicExecutor, pstate: ProcessState):
        logger.debug("in start hook")
        pstate.second_path_flag = False
    
    def set_membership_hooks(self):
        logger.debug('entered membership:))')
        if self.mode == 'membership':
            logger.debug('exiting membership')
            return
        logger.debug('Setting hooks')
        for callsite in self.callsites_to_monitor:
            callsite.set_hook(self.hooks_obj, self.callback_manager)
        self.mode = 'membership'
        #setting hooks on all branch opcodes
        branch_opcodes = [triton.OPCODE.X86.JAE, triton.OPCODE.X86.JA, triton.OPCODE.X86.JBE, triton.OPCODE.X86.JB, 
                          triton.OPCODE.X86.JCXZ, triton.OPCODE.X86.JECXZ, triton.OPCODE.X86.JE, triton.OPCODE.X86.JGE, 
                          triton.OPCODE.X86.JG, triton.OPCODE.X86.JLE, triton.OPCODE.X86.JL, triton.OPCODE.X86.JNE, 
                          triton.OPCODE.X86.JNO, triton.OPCODE.X86.JNP, triton.OPCODE.X86.JNS, triton.OPCODE.X86.JO, 
                          triton.OPCODE.X86.JP, triton.OPCODE.X86.JRCXZ, triton.OPCODE.X86.JS]
        for mnemonic in branch_opcodes:
             self.callback_manager.register_mnemonic_callback(callbacks.CbPos.BEFORE, mnemonic, self.beforeBranchHook)
             self.callback_manager.register_mnemonic_callback(callbacks.CbPos.AFTER, mnemonic, self.afterBranchHook)
        self.callback_manager.register_post_execution_callback(self.executionEnded)
        
        # self.callback_manager.register_function_callback('socket', self.socketHook)
        self.callback_manager.register_pre_imported_routine_callback('socket', self.socketHook)
        self.callback_manager.register_pre_imported_routine_callback('inet_pton', self.inetPtonHook)
        self.callback_manager.register_pre_imported_routine_callback('connect', self.connectHook)
        
        self.callback_manager.register_pre_execution_callback(self.startHook)
        
        
        
    def membership_step_by_step(self, inputs):
        self.inputs = inputs
        
        logger.info('Performing membership, step by step!')
        logger.debug('Query: %s' % inputs)
        
        config = Config(seed_format=SeedFormat.COMPOSITE)
        seed = Seed(CompositeData()) 
        executor = SymbolicExecutor(config, seed)
        executor.load(self.project)
        executor.cbm = self.callback_manager
        executor.pstate.monitoring_position = 0
        executor.pstate.query_runner = self
        # executor.pstate.second_path_stack = [False]
        self.set_membership_hooks()
        executor.run()
        
        #monitoring success
        return self.monitoring_result, None

    
    
