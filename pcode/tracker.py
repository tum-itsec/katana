from collections import defaultdict, namedtuple, OrderedDict
import logging
import sys
import re

from maps import VarnodeMap, MemoryMap, ActualNode, Garbage, ReturnGarbage
from state import State
from tracknode import *

from ghidra.program.model.pcode import PcodeOp

from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SourceType


from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.listing import ParameterImpl

from ghidra.program.database.function import OverlappingFunctionException


from ghidra.program.model.pcode import Varnode

from ghidra.app.cmd.memory import AddByteMappedMemoryBlockCmd
from ghidra.app.util.bin import MemoryByteProvider
from ghidra.app.util import MemoryBlockUtils
from ghidra.program.database.mem import FileBytes

from java.lang import IllegalArgumentException
from java.math import BigInteger
from java.io import FileInputStream

MAX_REASONABLE_OFFSET = 0x8000
MAX_REASONABLE_SYMBOL_DELTA = 0x1000000

X86_INDIRECT_CALL_THUNK_REGEX = re.compile(r"__x86_indirect_thunk_(?P<register>\S+)")

PcodeLocation = namedtuple("PcodeLocation", "ins_addr, pcode_idx")

currentProgram = None
all_symbols = None
varnode_context = None
varnode_translator = None
stack_pointer_varnode = None
return_varnode = None

def twos_comp(val, byte_size):
    bits = byte_size * 8
    if (val & (1 << (bits - 1))) != 0:
        val = val - (1 << bits)
    return val

# helper function to create an Address object from an offset
def get_address(offset):
    return currentProgram.getImageBase().add(offset)

def to_bigint(val):
    return BigInteger(str(val))

def unsigned_long(val):
    return BigInteger(str(val)).longValue()

# helper function to create an Address object from an offset
def get_virt_address(offset):
    #return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(hex(offset)[2:].rstrip('L'))

def create_const_varnode(val, size):
    return varnode_context.createConstantVarnode(unsigned_long(val), size)

def get_parameter_varnodes(func, parameter_accesses):
    tracking_varnodes = set()
    for access in parameter_accesses:
        param_idx = int(access.symbol[1:])
        calling_convention = func.getCallingConvention()
        if calling_convention is None:
            logging.warn("No calling convention for function: %s", func.getName())
            return []

        storage = func.getCallingConvention().getArgLocation(param_idx, None, None, currentProgram)

        if storage.getVarnodeCount() < 1:
            logging.error("No varnode found for the desired parameter")
            return
        if storage.getVarnodeCount() > 1:
            logging.warn("More than one varnode found for the desired parameter")
        varnode = storage.getVarnodes()[0]

        tracking_varnodes.add((param_idx, varnode))

    return tracking_varnodes

def track_pcode_run(flat_program_api, func, parameter_accesses):
    if not flat_program_api.disassemble(func.getEntryPoint()):
        logging.warning("Disassembly of %s failed", func.getName())
        return

    listing = func.getProgram().getListing()
    addr_set = func.getBody()

    instructions = OrderedDict()
    instruction_it = listing.getInstructions(addr_set, True)
    while instruction_it.hasNext():
        instruction = instruction_it.next()
        if instruction.isInDelaySlot():
            logging.debug("Dismissing delayslot instruction: %s @ %s", instruction, instruction.getAddress().getOffsetAsBigInteger())
            continue
        instructions[instruction.getAddress().getOffsetAsBigInteger()] = instruction

    parameters_to_track = get_parameter_varnodes(func, parameter_accesses)
    state = State(parameters_to_track)

    # Too big functions generate OOM error
    if (len(instructions) > 10000):
        logging.warning("Skipping function %s because it contains too many instructions", func.getName())
        return state

    if not instructions:
        logging.warning("No instructions found for function: %s!", func.getName())
        return state

    if len(instructions) == 0:
        logging.warning("Instruction with no pcode ops discovered! Bug?")
        return state
    state = emulate_pcode_run(func, instructions, PcodeLocation(instructions.keys()[0], 0), [], state)

    return state

def get_current_parameters(func, varnode_map):
    parameters = []
    for idx in range(6):
        varnode_idx = func.getCallingConvention().getArgLocation(idx, None, None, currentProgram).getVarnodes()[0]
        param = varnode_map.get(varnode_idx)
        parameters.append(param)
    return parameters

def emulate_pcode_run(func, instructions, start, visited_addrs, state):

    if start[0] not in instructions.keys():
        logging.debug(instructions.keys())
        logging.debug(instructions)
        logging.error("Bug - a missing delay slot instruction at %s ?", start)

    for (_, varnode) in state.parameters_to_track:
        if 'stack' in str(varnode):
            off = varnode.getOffset()
            space_id = currentProgram.getCompilerSpec().getStackBaseSpace().getPhysicalSpace().getSpaceID()
            const_varnode = varnode_context.createConstantVarnode(space_id, stack_pointer_varnode.getSize())
            state.memory_map.set(const_varnode, ActualNode(stack_pointer_varnode, off), ActualNode(varnode, 0))

    def maybe_add_global_pointer(addr, state, node):
        # Must be a valid constant node to even be considered a pointer
        if isinstance(node, ActualNode):
            if not node.is_constant():
                return False
            if node.offset != 0:
                return False
            offset = node.get_varnode_offset()
        elif 'ram' in str(node):
            try:
                offset = node.getAddress().getOffsetAsBigInteger()
            except AttributeError:
                return False
        else:
            return False
        # On MIPS and ARM, loads are often split - if we are 16-bit-aligned, don't count the value
        if offset & 0xFFFF == 0:
            return False
        # Now check that it could actually be a pointer
        if symbol_range[0] - MAX_REASONABLE_SYMBOL_DELTA <= offset <= symbol_range[1] + MAX_REASONABLE_SYMBOL_DELTA:
            state.global_pointers.append(node)
            return True

        return False

    ins_skip = True
    done = False
    for (addr, ins) in instructions.items():

        if int(addr) == int(start.ins_addr):
            ins_skip = False
            ops = list(enumerate(ins.getPcode()))[start.pcode_idx:]
        else:
            ops = list(enumerate(ins.getPcode()))
        if ins_skip:
            continue

        # Address already visited
        if addr in [x[0] for x in visited_addrs]:
            return state
        else:
            visited_addrs.append(PcodeLocation(addr, 0))

        state.varnode_map.set_current_addr(addr)
        state.memory_map.set_current_addr(addr)

        logging.debug("Processing instruction: %s @ [%s]", ins, hex(addr))
        logging.debug("Operations of this instruction: %s", list(ops))
        for (op_idx, op) in ops:
            logging.debug("Processing operation: %s", op)
            inputs = list(op.getInputs())
            output = op.getOutput()

            logging.debug(state.varnode_map)
            logging.debug(state.memory_map)
            logging.debug("Global accesses: %s", state.global_accesses)

            opcode = op.getOpcode()
            if opcode == PcodeOp.COPY:
                inp0 = state.varnode_map.get(inputs[0])
                if 'ram' in str(inputs[0]): # NB: This is not inp0!
                    # Some constant loads are weird like this
                    maybe_add_global_pointer(addr, state, inputs[0])

                state.varnode_map.set(output, inp0)
            elif opcode == PcodeOp.SUBPIECE:
                inp0 = state.varnode_map.get(inputs[0])
                # inp1 has to be a const varnode - nothing to resolve
                inp1 = inputs[1]

                if isinstance(inp0, Garbage):
                    state.varnode_map.set(output, inp0.create_from_offset(inp0.offset))
                else:
                    new_varnode = Varnode(inp0.varnode.getAddress(), inp1.getSize())
                    state.varnode_map.set(output, ActualNode(new_varnode, inp0.offset))
            elif opcode == PcodeOp.POPCOUNT:
                inp0 = state.varnode_map.get(inputs[0])

                if inp0.is_constant():
                    value = inp0.get_varnode_offset()
                    num_one_bits = len(list(filter(lambda x: x == '1', bin(value))))
                    new_varnode = create_const_varnode(num_one_bits, output.getSize())
                    state.varnode_map.set(output, ActualNode(new_varnode))
                else:
                    state.varnode_map.set(output, Garbage("POPCOUNT_TRASH", 0))
            elif opcode == PcodeOp.INT_ZEXT:
                inp0 = state.varnode_map.get(inputs[0])

                if inp0.is_constant():
                    value = inp0.get_varnode_offset()

                    new_varnode = create_const_varnode(value, output.getSize())
                    state.varnode_map.set(output, ActualNode(new_varnode))
                else:
                    state.varnode_map.set(output, inp0)
            elif opcode == PcodeOp.INT_SEXT:
                inp0 = state.varnode_map.get(inputs[0])

                if inp0.is_constant():
                    value = inp0.get_varnode_offset()
                    bits = inp0.get_varnode_size() * 8
                    sign_bit = value >> (bits  - 1)

                    if sign_bit == 1:
                        additional_bytes = output.getSize() - inp0.get_varnode_size()
                        mask = 0x0
                        for i in range(0, additional_bytes):
                            mask <<= 8
                            mask |= 0xff
                        result_value = value | (mask << bits)
                    else:
                        result_value = value

                    new_varnode = create_const_varnode(result_value, output.getSize())
                    state.varnode_map.set(output, ActualNode(new_varnode))
                else:
                    state.varnode_map.set(output, inp0)
            elif opcode in [PcodeOp.INT_CARRY, PcodeOp.INT_SCARRY, PcodeOp.INT_SBORROW]:
                # we don't check for overflows
                state.varnode_map.set(output, Garbage("BOOL", 0))
            elif opcode in [PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_SLESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL]:
                maybe_add_global_pointer(addr, state, state.varnode_map.get(inputs[0]))
                maybe_add_global_pointer(addr, state, state.varnode_map.get(inputs[1]))
                # ignore input, result is trashed with "BOOL"
                state.varnode_map.set(output, Garbage("BOOL", 0))
            elif opcode == PcodeOp.INT_NEGATE:
                state.varnode_map.set(output, Garbage("INT_OP TRASH", 0))
            elif opcode == PcodeOp.INT_2COMP:
                inp0 = state.varnode_map.get(inputs[0])

                    # Mips hackery
                if inp0.is_constant() and inp0.get_varnode_offset() == 2:
                    state.varnode_map.set(output, Garbage("MIPS_CALL_ALIGN", 0))
                else:
                    state.varnode_map.set(output, Garbage("INT_OP_TRASH", 0))
            elif opcode == PcodeOp.INT_AND:
                inp0 = state.varnode_map.get(inputs[0])
                inp1 = state.varnode_map.get(inputs[1])

                # We only bother calculating this if it's affecting the stack pointer
                if inp0.intersects(stack_pointer_varnode):
                    if inp1.is_constant():
                        state.varnode_map.set(output, inp0.create_from_offset(inp1.get_varnode_offset() & inp0.offset))
                    else:
                        state.varnode_map.set(output, inp0.create_from_offset(inp0.offset))
                # Or treat as a copy for mips in case the value we are anding with would be "-2"
                elif inp0.is_mips_call_mask():
                    # Simply copy in this case
                    state.varnode_map.set(output, inp1)
                else:
                    state.varnode_map.set(output, Garbage("INT_OP TRASH"))
            elif opcode == PcodeOp.INT_LEFT:
                inp0 = state.varnode_map.get(inputs[0])
                inp1 = state.varnode_map.get(inputs[1])

                if inp0.is_constant() and inp1.is_constant():
                    value = inp0.get_varnode_offset()
                    shift = inp1.get_varnode_offset()

                    if shift == 0:
                        result = value
                    elif shift >= (output.getSize() * 8):
                        result = 0
                    else:
                        result = int(value << shift)

                    new_varnode = create_const_varnode(result, output.getSize())
                    state.varnode_map.set(output, ActualNode(new_varnode))
                else:
                    state.varnode_map.set(output, Garbage("INT_OP TRASH", 0))
            elif opcode == PcodeOp.INT_OR:
                inp0 = state.varnode_map.get(inputs[0])
                inp1 = state.varnode_map.get(inputs[1])

                if inp0.is_constant() and inp1.is_constant():
                    value0 = inp0.get_varnode_offset() + inp0.offset
                    value1 = inp1.get_varnode_offset() + inp1.offset

                    result = value0 | value1

                    new_varnode_size = max(inp0.get_varnode_size(), inp1.get_varnode_size())
                    new_varnode = create_const_varnode(result, new_varnode_size)

                    state.varnode_map.set(output, ActualNode(new_varnode), True)
                # Just do a copy in this case
                elif inp0.is_constant() and inp0.get_varnode_offset() == 0:
                    state.varnode_map.set(output, inp1)
                # Just do a copy in this case
                elif inp1.is_constant() and inp1.get_varnode_offset() == 0:
                    state.varnode_map.set(output, inp0)
                else:
                    state.varnode_map.set(output, Garbage("INT_OP TRASH", 0))

            elif opcode in [PcodeOp.INT_XOR, PcodeOp.INT_OR, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, PcodeOp.INT_MULT, PcodeOp.INT_DIV, PcodeOp.INT_REM, PcodeOp.INT_SDIV, PcodeOp.INT_SREM]:
                state.varnode_map.set(output, Garbage("INT_OP TRASH", 0))
            elif opcode == PcodeOp.BOOL_NEGATE:
                state.varnode_map.set(output, Garbage("BOOL", 0))
            elif opcode in [PcodeOp.BOOL_OR, PcodeOp.BOOL_AND, PcodeOp.BOOL_XOR]:
                state.varnode_map.set(output, Garbage("BOOL", 0))
            elif opcode == PcodeOp.CBRANCH:
                inp0 = inputs[0]

                # Constant input means we jump across pcode-instructions
                if inp0.isConstant():
                    pcode_offset = op_idx + twos_comp(inp0.getOffset(), inp0.getSize())

                    if pcode_offset < 0 or pcode_offset > len(ins.getPcode()):
                        logging.error("Bug on branch %s | %s | %s", inp0, pcode_offset, len(ins.getPcode()))
                        sys.exit(-1)
                    # Special case, branch to next instruction via pcode-op offset
                    if pcode_offset == len(ins.getPcode()):
                        branch_location = PcodeLocation(ins.getNext().getAddress().getUnsignedOffset(), 0)
                    else:
                        branch_location = PcodeLocation(addr, pcode_offset)
                else:
                    branch_addr = inp0.getAddress().getOffsetAsBigInteger()
                    branch_location = PcodeLocation(branch_addr, 0)


                if branch_location not in visited_addrs:
                    # Unfortunate ugly deepcopy
                    copy_raw_varnode_map = {}
                    for (k, v) in state.varnode_map.map.items():
                        copy_raw_varnode_map[k] = v
                    copy_raw_memory_map = {}
                    for (k1, v1) in state.memory_map.map.items():
                        if k1 not in copy_raw_memory_map:
                            copy_raw_memory_map[k1] = {}
                        for (k2, v2) in v1.items():
                            copy_raw_memory_map[k1][k2] = v2

                    new_tracked_accesses = defaultdict(list)
                    varnode_map_copy = VarnodeMap(state.parameters_to_track, new_tracked_accesses, state.global_accesses, state.return_value_accesses)
                    varnode_map_copy.map = copy_raw_varnode_map
                    memory_map_copy = MemoryMap(state.parameters_to_track, new_tracked_accesses, state.global_accesses, state.return_value_accesses)
                    memory_map_copy.map = copy_raw_memory_map

                    copied_state = State(state.parameters_to_track)
                    copied_state.varnode_map = varnode_map_copy
                    copied_state.memory_map = memory_map_copy
                    copied_state.parameter_accesses = new_tracked_accesses
                    copied_state.global_accesses = state.global_accesses
                    copied_state.global_pointers = state.global_pointers
                    copied_state.calls = state.calls
                    copied_state.indirect_calls = state.indirect_calls
                    copied_state.containerofs = state.containerofs
                    copied_state.return_values = state.return_values
                    copied_state.return_value_accesses = state.return_value_accesses

                    new_state = emulate_pcode_run(func, instructions, branch_location, visited_addrs, copied_state)
                    # only extend the tracked calls and global accesses, otherwise keep going with parameter tracking as usual
                    #state.global_accesses.extend(new_state.global_accesses)
                    #calls.extend(branch_calls)
            # We can technically follow this
            elif opcode == PcodeOp.BRANCHIND:
                logging.warning("BRANCHIND inputs: %s", inputs)
                inp0 = state.varnode_map.get(inputs[0])
                logging.warning("BRANCHIND resolved inputs: %s", inp0)
                logging.warning("BRANCHIND encountered, please implement ignore + register trashing")
                done = True
                break
            elif opcode == PcodeOp.BRANCH:
                inp0 = inputs[0]

                # Constant input means we jump across pcode-instructions
                if inp0.isConstant():
                    pcode_offset = op_idx + twos_comp(inp0.getOffset(), inp0.getSize())

                    if pcode_offset < 0 or pcode_offset > len(ins.getPcode()):
                        logging.error("Bug on branch %s | %s | %s", inp0, pcode_offset, len(ins.getPcode()))
                        sys.exit(-1)
                    # Special case, branch to next instruction via pcode-op offset
                    if pcode_offset == len(ins.getPcode()):
                        branch_location = PcodeLocation(ins.getNext().getAddress().getUnsignedOffset(), 0)
                    else:
                        branch_location = PcodeLocation(addr, pcode_offset)
                else:
                    branch_addr = inp0.getAddress().getOffsetAsBigInteger()
                    branch_location = PcodeLocation(branch_addr, 0)

                # Probably a tail call
                if branch_location.ins_addr not in range(instructions.keys()[0], instructions.keys()[-1]):
                    logging.debug("Tail call to: %s detected!", branch_location.ins_addr)
                    return state

                if branch_location not in visited_addrs:
                    return emulate_pcode_run(func, instructions, branch_location, visited_addrs, state)
            elif opcode == PcodeOp.CALLIND:
                inp0 = state.varnode_map.get(inputs[0])
                # We are interested in the case where it is not constant i.e. an offset from some varnode
                parameters = get_current_parameters(func, state.varnode_map)

                if inp0.is_address():
                    state.indirect_calls[hex(addr)] = ("ALREADY_GLOBAL_IDENTIFIED", parameters)
                else:
                    state.indirect_calls[hex(addr)] = (inp0, parameters)
            elif opcode == PcodeOp.CALL:
                # Be careful not to resolve as otherwise we track as a global, should be (ram, x, x) anyways
                inp0 = inputs[0]

                call_addr = int(inp0.getAddress().getOffsetAsBigInteger())
                if call_addr in all_symbols:
                    callee = all_symbols[call_addr]

                    # Check if indirect call via thunk - x86 only
                    m = X86_INDIRECT_CALL_THUNK_REGEX.match(callee)
                    if (m):
                        register_str = m.group('register').upper()

                        register = varnode_translator.getVarnode(varnode_context.getRegister(register_str))
                        mapped_varnode = state.varnode_map.get(register)
                        # We are interested in the case where it is not constant i.e. an offset from some varnode
                        parameters = get_current_parameters(func, state.varnode_map)

                        if mapped_varnode.is_address():
                            state.indirect_calls[hex(addr)] = ("ALREADY_GLOBAL_IDENTIFIED", parameters)
                        else:
                            state.indirect_calls[hex(addr)] = (mapped_varnode, parameters)

                        # Make sure this isn't treated as a regular call (although it probably shouldn't matter)
                        callee = None
                    else:
                        if callee != "__fentry__":
                            logging.debug("Call to function: %s detected!", callee)
                            parameters = get_current_parameters(func, state.varnode_map)
                            logging.debug("Parameters for this call: %s", parameters)
                            state.calls[hex(addr)] = (callee, parameters)

                        # Setup tracking of the returned value
                        state.varnode_map.set(return_varnode, ReturnGarbage(callee, addr))

                # increase stack pointer, or in general undo the saving of the return address
                resolved_stack_ptr = state.varnode_map.get(stack_pointer_varnode)
                # TODO: remove the saved return address, in addition to adjusting stack ptr?
                if currentProgram.getCompilerSpec().stackGrowsNegative():
                    state.varnode_map.set(stack_pointer_varnode, resolved_stack_ptr.create_from_offset(resolved_stack_ptr.offset + stack_pointer_varnode.getSize()))
                else:
                    state.varnode_map.set(stack_pointer_varnode, resolved_stack_ptr.create_from_offset(resolved_stack_ptr.offset - stack_pointer_varnode.getSize()))

            elif opcode == PcodeOp.CALLOTHER:
                # This opcode gets emitted on special CPU instructions e.g. IN / LOCK on x86

                # If this instruction has an output varnode, trash it
                if output:
                    state.varnode_map.set(output, Garbage("CALLOTHER TRASH", 0))
                else:
                    pass
            elif opcode == PcodeOp.RETURN:
                fun_result = state.varnode_map.get(return_varnode)

                state.return_values.append(fun_result)

                logging.debug("Return encountered, stopping tracking")
                done = True
                break
            elif opcode in [PcodeOp.INT_SUB, PcodeOp.INT_ADD]:
                inp0 = state.varnode_map.get(inputs[0])
                inp1 = state.varnode_map.get(inputs[1])

                inp0_global = maybe_add_global_pointer(addr, state, inp0)
                inp1_global = maybe_add_global_pointer(addr, state, inp1)

                if inp0.is_constant() and inp1.is_constant():
                    offset0 = inp0.get_varnode_offset() + inp0.offset
                    offset1 = inp1.get_varnode_offset() + inp1.offset

                    n = 2 ** (output.getSize() * 8)
                    if opcode == PcodeOp.INT_SUB:
                        new_offset = (offset0 - offset1) % n
                    else:
                        new_offset = (offset0 + offset1) % n

                    new_varnode = create_const_varnode(new_offset, output.getSize())
                    state.varnode_map.set(output, ActualNode(new_varnode), True)
                    if not inp0_global and not inp1_global:
                        maybe_add_global_pointer(addr, state, ActualNode(new_varnode))
                elif inp0.is_constant():
                    offset = twos_comp(inp0.get_varnode_offset(), inp0.get_varnode_size())
                    logging.debug("2s-comp(Offset) in INT_ADD/INT_SUB is: %s", offset)

                    if opcode == PcodeOp.INT_SUB:
                        new_offset = offset - inp1.offset

                        #if not var0.intersects(stack_pointer_varnode):
                        #    containerofs.append(new_offset)

                    elif opcode == PcodeOp.INT_ADD:
                        new_offset = offset + inp1.offset

                        if offset < 0 and not inp1.intersects(stack_pointer_varnode) and (-1 * offset) < MAX_REASONABLE_OFFSET:
                            if not any(op[1].getOpcode() in [PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_SLESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL] for op in ops):
                                if hex(addr) not in state.containerofs:
                                    state.containerofs[hex(addr)] = (-offset)


                    new_node = inp1.create_from_offset(new_offset)
                    new_node.latest_offset = offset
                    state.varnode_map.set(output, new_node, True)
                elif inp1.is_constant():
                    offset = twos_comp(inp1.get_varnode_offset(), inp1.get_varnode_size())
                    logging.debug("2s-comp(Offset) in INT_ADD/INT_SUB is: %s", offset)

                    if opcode == PcodeOp.INT_SUB:
                        new_offset = inp0.offset - offset

                        if offset > 0 and offset < MAX_REASONABLE_OFFSET and not inp0.intersects(stack_pointer_varnode):
                            if not any(op[1].getOpcode() in [PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_SLESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL] for op in ops):
                                if hex(addr) not in state.containerofs:
                                    state.containerofs[hex(addr)] = offset

                    elif opcode == PcodeOp.INT_ADD:
                        new_offset = inp0.offset + offset

                        if offset < 0 and not inp0.intersects(stack_pointer_varnode) and (-1 * offset) < MAX_REASONABLE_OFFSET:
                            if not any(op[1].getOpcode() in [PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_SLESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL] for op in ops):
                                if hex(addr) not in state.containerofs:
                                    state.containerofs[hex(addr)] = -offset


                    new_node = inp0.create_from_offset(new_offset)
                    new_node.latest_offset = offset
                    state.varnode_map.set(output, new_node, True)
                else:
                    # Trash non-constant additions
                    state.varnode_map.set(output, Garbage("INT_ADD/INT_SUB TRASH", 0))
                maybe_add_global_pointer(addr, state, inp0)
            elif opcode == PcodeOp.STORE:
                inp0 = inputs[0]
                inp1 = state.varnode_map.get(inputs[1])
                inp2 = state.varnode_map.get(inputs[2])

                maybe_add_global_pointer(addr, state, inp2)

                if isinstance(inp1, ActualNode):
                    if 'const' in str(inp1.varnode):
                        access = inp1.get_varnode_offset()
                        logging.debug("Global [W]rite access found at: %s", access)
                        state.memory_map.global_accesses[addr] = ("[W]", access)

                #FIXME: Tracknode
                state.memory_map.set(inp0, inp1, inp2)
            elif opcode == PcodeOp.LOAD:
                inp0 = inputs[0]
                inp1 = state.varnode_map.get(inputs[1])

                if isinstance(inp1, ActualNode):
                    if 'const' in str(inp1.varnode):
                        access = inp1.get_varnode_offset()
                        logging.debug("Global [R]ead access found at: %s", access)
                        state.memory_map.global_accesses[addr] = ("[R]", access)

                deref_result = state.memory_map.get(inp0, inp1)

                #real_output = state.varnode_map.get(output, (output, 0))
                state.varnode_map.set(output, deref_result)
            else:
                logging.error("Unknown Opcode: %s - stopping tracking", op)
                done = True
                break

        if done == True:
            break

    return state


def create_mappings(file_name, flat_program_api):
    memory = currentProgram.getMemory()

    # First, remove all blocks
    for memory_block in memory.getBlocks():
        memory.removeBlock(memory_block, flat_program_api.getMonitor())

    all_file_bytes = memory.getAllFileBytes()
    file_bytes = all_file_bytes[0]

    maps = []
    with open("{}-mappings".format(file_name), 'r') as f:
        for line in f.read().split('\n'):
            if line == '':
                continue
            (file_offset, virt, length, flags) = line.split(' ')
            maps.append((int(file_offset, 16), int(virt, 16), int(length), flags))

    duplicate_mappings = 0
    invalid_mappings = 0
    mapped_bytes = 0
    seen_file_offsets = defaultdict(int)
    for (idx, (file_offset, virt, length, flags)) in enumerate(maps):
        name = "map_{}".format(idx)

        if seen_file_offsets[file_offset] > 100:
            duplicate_mappings += 1
            logging.debug("Skipping duplicate mapping")
            continue
        if file_offset + length > file_bytes.getSize():
            invalid_mappings += 1
            logging.debug("Skipping invalid mapping")
            continue

        mapped_bytes += length
        virt_start = get_virt_address(virt)
        memory_block = memory.createInitializedBlock(name, virt_start, file_bytes, file_offset, length, False)
        memory_block.setRead('R' in flags)
        memory_block.setWrite('W' in flags)
        memory_block.setExecute('X' in flags)
        memory_block.setVolatile(False)
        memory_block.setSourceName("katana")
        memory_block.setComment("")

        seen_file_offsets[file_offset] += 1

    logging.info("Skipped %s duplicate mappings!", duplicate_mappings)
    logging.info("Skipped %s invalid mappings!", invalid_mappings)
    logging.info("Mapped %s aka %s bytes in total!", mapped_bytes, hex(mapped_bytes))


# Create functions we have outside information for
def create_functions(symbols):
    funs = []
    fm = currentProgram.getFunctionManager()
    logging.info("Creating functions..")
    for symbol in symbols:
        start = get_virt_address(symbol.start)
        logging.debug('Creating %s @ %s [size %s]', symbol.name, start, symbol.size)
        if not currentProgram.getAddressFactory().isValidAddress(start):
            logging.error('Address is invalid!')

        try:
            if symbol.size == 0:
                func = fm.createFunction(symbol.name, start, AddressSet(start), SourceType.USER_DEFINED)
            else:
                end = get_virt_address(symbol.start + symbol.size - 1)
                func = fm.createFunction(symbol.name, start, AddressSet(start, end), SourceType.USER_DEFINED)
        except OverlappingFunctionException:
            logging.warn('Could not create function as it is overlapping: %s', symbol.name)
            continue
        except IllegalArgumentException:
            logging.warn('Could not create function, illegal argument: %s', symbol.name)
            continue

        if func is None:
            logging.error('Could not create function %s', symbol.name)

        #TODO
        func.setCallingConvention(func.getDefaultCallingConventionName())
        funs.append(func)
    return funs
