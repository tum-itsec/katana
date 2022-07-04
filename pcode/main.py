import logging
import sys

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.util import ProgramContextImpl, VarnodeContext

from ghidra.app.decompiler import DecompInterface

from ghidra.program.model.data import Undefined
from ghidra.program.model.pcode import VarnodeTranslator

import infoload
import tracker
import pcodetest
from accessprocessor import AccessProcessor


def print_decompiled_code(ifc, func):
    logging.info("Printing decompiled code for function: %s", func.getName())
    result = ifc.decompileFunction(func, 0, None)
    print(result.getDecompiledFunction().getC())

def print_refined_pcode(ifc, func):
    logging.info("Printing refined pcode for function: %s", func.getName())
    result = ifc.decompileFunction(func, 0, None)
    high_func = result.getHighFunction()

    ops_it = high_func.getPcodeOps()
    while ops_it.hasNext():
        op = ops_it.next()
        print(op)

def print_raw_pcode(func):
    logging.info("Printing raw pcode for function: %s", func.getName())

    if not flat_program_api.disassemble(func.getEntryPoint()):
        logging.warn("Disassembly of %s failed", func.getName())
        return

    listing = func.getProgram().getListing()
    addr_set = func.getBody()

    instruction_it = listing.getInstructions(addr_set, True)
    while instruction_it.hasNext():
        ins = instruction_it.next()
        pcode_ops = ins.getPcode()
        print("[{}] {}".format(hex(ins.getAddress().getOffsetAsBigInteger()), ins))
        for op in pcode_ops:
            print("\t {}".format(op))


def do_regular_analysis():
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)

    access_processor = AccessProcessor(all_symbols)

    logging.info("Function count: %s", fm.getFunctionCount())
    #for func in fm.getFunctionsNoStubs(True):
    for func in funs:
        name = func.getName()
        addr = func.getEntryPoint().getOffsetAsBigInteger()

        logging.info("Processing function: %s", name)

        # functions to debug
        #dbg_list = ['tracing_release_pipe']
        #dbg_list = ['release_task']
        #dbg_list = ['start_secondary']
        #dbg_list = ['walk_system_ram_range']
        #dbg_list = ['efi_query_variable_store']
        #dbg_list = ['__recover_optprobed_insn']
        #dbg_list = ['normalize_rt_tasks']
        #dbg_list = ['inet_recv_error']
        #dbg_list = ['sock_alloc_file']

        #TODO:
        #dbg_list = ["try_to_unmap_one"]
        dbg_list = []

        if dbg_list:
            logging.getLogger().setLevel(logging.DEBUG)
            if name not in dbg_list:
                continue

            print_decompiled_code(ifc, func)
            print_raw_pcode(func)

        logging.info("Processing function: %s @ %s", name, hex(addr))

        c = model.get(name)
        if not c:
            logging.info("\x1b[31m{} not found in GCC Info File!\x1b[0m".format(name))
            continue

        access_processor.set_current_function(func, c)

        # parameter accesses
        #struct_db = list(x for x in c.accesses if x.symbol.startswith("$"))[:1]
        struct_db = list(x for x in c.accesses if x.symbol.startswith("$") and int(x.calls) <= 1)
        global_db = [x for x in c.accesses if not x.symbol.startswith("$")]
        state = tracker.track_pcode_run(flat_program_api, func, struct_db)

        logging.debug("Containerofs found: %s", state.containerofs)
        logging.debug("Return value accesses found: %s", state.return_value_accesses)
        logging.debug("MemoryMap (tracked) accesses found: %s", state.memory_map.get_tracked_accesses())
        logging.debug("MemoryMap (global) accesses found: %s", state.memory_map.get_global_accesses())
        logging.debug("VarnodeMap (global) accesses found: %s", state.varnode_map.get_global_accesses())

        access_processor.process_parameter_matches_regular(struct_db, state.parameter_accesses)
        access_processor.process_global_matches(global_db, state.global_accesses)
        access_processor.process_tracked_calls(model, c.calls, state.calls)
        access_processor.process_tracked_indirect_calls(c.indirect_calls, state.indirect_calls)
        access_processor.process_containerofs(c.container_of, state.containerofs)
        access_processor.process_return_values(c.retvals, state.return_values)
        access_processor.process_return_value_accesses(c.retval_uses_after_call, state.return_value_accesses)
        access_processor.process_global_vars(c.globs, state.global_pointers)


    access_processor.save_info(file_name + "-layout")


logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(levelname)s: %(message)s')

file_name = str(currentProgram.getExecutablePath())
args = getScriptArgs()
if len(args) < 2:
    logging.error('Usage: pcode_tracker.py $fieldspath analyze_vmlinux/analyze_dump/unittest_vmlinux')

fields_path = args[0]
action = args[1]

fm = currentProgram.getFunctionManager()

calling_convention = fm.getDefaultCallingConvention()
if 'flow_test' in file_name:
    model = infoload.read_tracking_file("./flow_test_fields.txt", calling_convention, currentProgram)
    symbols = infoload.read_testing_symbols(file_name)
else:
    model = infoload.read_tracking_file(fields_path, calling_convention, currentProgram)
    (symbols, all_symbols) = infoload.read_katana_symbols(file_name, model)

    for func in fm.getFunctions(True):
        # (ugly workaround) remove all existing functions (created by the importer reading symbols)
        fm.removeFunction(func.getEntryPoint())

flat_program_api = FlatProgramAPI(currentProgram)

# A bit hacky but saves some boilerplate
tracker.currentProgram = currentProgram
program_context = ProgramContextImpl(currentProgram.getLanguage())
space_context = ProgramContextImpl(currentProgram.getLanguage())
varnode_context = VarnodeContext(currentProgram, program_context, space_context)
tracker.varnode_context = varnode_context
tracker.varnode_translator = VarnodeTranslator(currentProgram)
tracker.stack_pointer_varnode = varnode_context.getStackVarnode()
tracker.all_symbols = all_symbols
tracker.symbol_range = [min(addr for addr in all_symbols if isinstance(addr, (int, long)) and addr > 0x1000), max(addr for addr in all_symbols if isinstance(addr, (int, long)) and addr > 0x1000)] # Has at least some data symbols (init_task, ...)

# Get return varnode - this somehow broke for memory dumps in 9.2.2
undef_dt = Undefined.getUndefinedDataType(currentProgram.getDefaultPointerSize())
return_storage = calling_convention.getReturnLocation(undef_dt, currentProgram)
if return_storage.getVarnodeCount() > 1:
    logging.warning('More than one varnode for return value storage!')
return_varnode = return_storage.getVarnodes()[0]
tracker.return_varnode = return_varnode
logging.debug("Return varnode: %s", return_varnode)

if action == 'analyze_dump':
    tracker.create_mappings(file_name, flat_program_api)

funs = tracker.create_functions(symbols)

if action in ['analyze_vmlinux', 'analyze_dump']:
    logging.getLogger().setLevel(logging.WARNING)
    do_regular_analysis()
elif action == 'unittest_vmlinux':
    logging.getLogger().setLevel(logging.WARNING)
    pcodetest.do_unittests(currentProgram.getExecutablePath(), funs, flat_program_api, model, all_symbols)
else:
    logging.error('Unknown action: %s', action)
