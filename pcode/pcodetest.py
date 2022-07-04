from __future__ import print_function
from collections import namedtuple, defaultdict
import subprocess
import logging
import re

from accessprocessor import AccessProcessor
import tracker

class AnalysisType(object):
    def __init__(self, identifier, struct, member):
        self.identifier = identifier
        self.struct = struct
        self.member = member

    def __str__(self):
        return "[{}] {}->{}".format(self.identifier, self.struct, self.member)

class Parameter(AnalysisType):
    def __init__(self, param_idx, struct, member):
        self.param_idx = param_idx
        super(Parameter, self).__init__('PARAMETER', struct, member)

    def __str__(self):
        return "[{} (parameter \x1b[0;35m{}\x1b[0m)] {}->{}".format(self.identifier, str(self.param_idx), self.struct, self.member)

class Global(AnalysisType):
    def __init__(self, symbol, struct, member):
        self.symbol = symbol
        super(Global, self).__init__('GLOBAL', struct, member)

    def __str__(self):
        return "[{} (via symbol \x1b[0;35m{}\x1b[0m)] {}->{}".format(self.identifier, self.symbol, self.struct, self.member)

class Call(AnalysisType):
    def __init__(self, callee, param_idx, struct, member):
        self.callee = callee
        self.param_idx = param_idx
        super(Call, self).__init__('CALL', struct, member)

    def __str__(self):
        return "[{} (via callee \x1b[0;35m{}\x1b[0m)] {}->{}".format(self.identifier, self.callee, self.struct, self.member)

class IndirectCall(AnalysisType):
    def __init__(self, param_idx, struct, member):
        self.param_idx = param_idx
        super(IndirectCall, self).__init__('INDIRECT_CALL', struct, member)

class ContainerOf(AnalysisType):
    def __init__(self, struct, member):
        super(ContainerOf, self).__init__('CONTAINER', struct, member)

class ReturnValue(AnalysisType):
    def __init__(self, struct, member):
        super(ReturnValue, self).__init__('RETURN_VALUE', struct, member)

class ReturnValueAccess(AnalysisType):
    def __init__(self, callee, struct, member):
        self.callee = callee
        super(ReturnValueAccess, self).__init__('RETURN_VALUE_ACCESS', struct, member)

    def __str__(self):
        return "[{} (via callee \x1b[0;35m{}\x1b[0m)] {}->{}".format(self.identifier, self.callee, self.struct, self.member)


def get_type_offsets(vmlinux, typename):
    output = subprocess.check_output(['pahole', '--hex', '--nested_anon_include', '--class_name=' + typename, vmlinux])
    output = re.sub(br' __attribute__\(\(.*\)\);', b';', output) # Remove attributes
    for match in re.finditer(br'(\S+|\(\*[^()]+\)\(.*\));\s*/\*\s+(0x[0-9a-fA-F]+|0)(?:\s|:)', output, re.MULTILINE):
        member = match.group(1)
        offset = int(match.group(2), 0)
        match = re.match(br'([^\[:]+)', member)
        if match is not None:
            member = match.group(1) # Strip array extents and bitfields
        match = re.match(br'\(\*([^)]+)\)', member)
        if match is not None:
            member = match.group(1) # Strip function pointer
        member = member.decode()
        if member == '}':
            continue # Skip ends of anonymous structs or unions
        yield (member, offset)


class Unittest():
    def __init__(self, function_name, accesses):
        self.function_name = function_name
        self.accesses = accesses

    def get_actual_offset(self, vmlinux_path, access):
        members = get_type_offsets(vmlinux_path, access.struct)
        for member in members:
            if member[0] == access.member:
                actual_offset = member[1]
                return actual_offset
        else:
            logging.warning('No offset found in debug info for: %s->%s', access.struct, access.member)
            return None

    def get_recovered_offset(self, analysis_type, reconstructed_types, access):
        for tracked_access in reconstructed_types[access.struct]:
            if analysis_type not in tracked_access[3]:
                continue

            if tracked_access[0] == access.member:
                recovered_offset = tracked_access[1]
                return recovered_offset

        return None

    def check(self, state, reconstructed_types, vmlinux_path, all_symbols):
        for access in self.accesses:
            print("\t{}: ".format(str(access)), end='')
            if isinstance(access, Parameter) or isinstance(access, ContainerOf) or isinstance(access, ReturnValue) or isinstance(access, ReturnValueAccess) or isinstance(access, IndirectCall):
                actual_offset = self.get_actual_offset(vmlinux_path, access)
                recovered_offset = self.get_recovered_offset(access.identifier, reconstructed_types, access)

                logging.info('Actual offset of: %s is %s. Recovered %s', str(access), actual_offset, recovered_offset)

                if actual_offset == recovered_offset:
                    print('\x1b[32mPASS\x1b[0m')
                else:
                    print('\x1b[31mFAIL\x1b[0m')
            if isinstance(access, Global):
                if access.symbol not in all_symbols:
                    print('\x1b[31mFAIL - symbol not found\x1b[0m')
                    continue

                actual_offset = self.get_actual_offset(vmlinux_path, access)
                recovered_offset = self.get_recovered_offset(access.identifier, reconstructed_types, access)
                
                logging.info('Actual offset of: %s is %s. Recovered %s', str(access), actual_offset, recovered_offset)

                if actual_offset == recovered_offset:
                    print('\x1b[32mPASS\x1b[0m')
                else:
                    print('\x1b[31mFAIL\x1b[0m')
            if isinstance(access, Call):
                actual_offset = self.get_actual_offset(vmlinux_path, access)
                for (callee, parameters) in state.calls.values():
                    if access.callee == callee:
                        param = parameters[access.param_idx]
                        if param.deref_offset is not None and param.latest_offset is None:
                            recovered_offset = param.deref_offset
                            break
                        elif param.latest_offset is not None:
                            recovered_offset = param.latest_offset
                            break
                else:
                    print('\x1b[31mFAIL - could not recover call parameter\x1b[0m')
                    continue

                logging.info('Actual offset of: %s is %s. Recovered %s', str(access), actual_offset, recovered_offset)

                if actual_offset == recovered_offset:
                    print('\x1b[32mPASS\x1b[0m')
                else:
                    print('\x1b[31mFAIL\x1b[0m')

                #recovered_offset = self.get_recovered_offset(access.identifier, state, reconstructed_types, access)


unittests = [
    #Unittest('selinux_sock_graft', [Parameter(1, 'socket_alloc', 'vfs_inode')]),
    Unittest('uncore_shared_reg_config', [Parameter(0, 'intel_uncore_box', 'shared_regs')]),
    #Unittest('ndisc_cleanup', [Global('nd_tbl', 'neigh_table', 'parms')]),
    # Fails because *(container_of(rdi, -0x20))
    #Unittest('neigh_hash_free_rcu', [Call('kfree', 0, 'neigh_hash_table', 'hash_buckets')]),
    Unittest('single_release',
        [Call('kvfree', 0, 'seq_file', 'buf'),
         Call('kmem_cache_free', 1, 'file', 'private_data'),
         Call('kfree', 0, 'seq_file', 'op')]
    ),
    #Unittest('__neigh_create', [Call('neigh_hash_grow', 1, 'neigh_hash_table', 'hash_shift')]),
    # Fails because same container of is matched twice instead of once
    #Unittest('usb_release_interface_cache', [ContainerOf('usb_interface_cache', 'ref')]),
    Unittest('each_symbol_section', [ContainerOf('module', 'list')]),
    Unittest('show_state_filter', [ContainerOf('task_struct', 'tasks'), ContainerOf('task_struct', 'thread_node')]),
    Unittest('nfs_dreq_bytes_left',
        [Parameter(0, 'nfs_direct_req', 'bytes_left'),
         ReturnValue('nfs_direct_req', 'bytes_left')]
    ),
    Unittest('tcp_conn_request',
        [ReturnValueAccess('reqsk_alloc', 'tcp_request_sock', 'af_specific'),
         ReturnValueAccess('reqsk_alloc', 'tcp_request_sock', 'ts_off')]
    ),
    Unittest('kprobe_debug_handler', [IndirectCall(0, 'kprobe', 'post_handler')])
]

def do_unittests(vmlinux_path, functions, flat_program_api, model, all_symbols):
    logging.info("Starting unit tests!")
    for unittest in unittests:
        print('Testing function: {}'.format(unittest.function_name))

        access_processor = AccessProcessor(all_symbols)
        for x in functions:
            if str(x.getName()) == unittest.function_name:
                func = x
                break

        c = model.get(unittest.function_name)
        if not c:
            logging.warning("\x1b[31m{} not found in GCC Info File!\x1b[0m".format(unittest.function_name))
            continue

        access_processor.set_current_function(func, c)

        struct_db = list(x for x in c.accesses if x.symbol.startswith("$") and int(x.calls) == 0)
        global_db = [x for x in c.accesses if not x.symbol.startswith("$")]
        state = tracker.track_pcode_run(flat_program_api, func, struct_db)

        access_processor.process_parameter_matches_regular(struct_db, state.parameter_accesses)
        access_processor.process_global_matches(global_db, state.global_accesses)
        access_processor.process_tracked_calls(model, c.calls, state.calls)
        access_processor.process_tracked_indirect_calls(c.indirect_calls, state.indirect_calls)
        access_processor.process_containerofs(c.container_of, state.containerofs)
        access_processor.process_return_values(c.retvals, state.return_values)
        access_processor.process_return_value_accesses(c.retval_uses_after_call, state.return_value_accesses)

        unittest.check(state, access_processor.reconstructed_types, vmlinux_path, all_symbols)
