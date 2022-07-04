from collections import defaultdict, OrderedDict
import logging
import pprint
import copy

MAX_REASONABLE_OFFSET = 0x8000

class AccessProcessor:
    def __init__(self, all_symbols):
        self.all_symbols = all_symbols
        self.reconstructed_types = defaultdict(list)
        self.pending_types = defaultdict(list)
        self.reconstructed_globals = defaultdict(list)
        self.pending_globals = defaultdict(list)
        self.parameter_offsets = 0
        self.global_offsets = 0
        self.global_variable_offsets = 0
        self.call_offsets = 0
        self.indirect_call_offsets = 0
        self.containerof_offsets = 0
        self.return_value_offsets = 0
        self.return_value_access_offsets = 0
        self.inlined_call_offsets = 0
        self.unknown_function_calls = 0

    def set_current_function(self, func, model):
        self.func = func
        self.name = func.getName()
        self.addr = func.getEntryPoint().getOffsetAsBigInteger()
        self.linkage = model.linkage

    def maybe_track_global(self, global_name, value_node, source_type):
        # Handles cases such as fn(&global_name) => fn(value) (from call/call_indirect),
        # and cases such as global_name => value (from global_var)
        # The case global_name.member => value (from global_access) is handled separately, because it requires first recovering the type
        if isinstance(value_node, (int, long)):
            value = value_node
        elif hasattr(value_node, 'get_varnode_offset'):
            value = value_node.get_varnode_offset()
        else:
            return
        logging.info("\x1b[32m[GlobalVar|{}] Found potential address {} for {}\x1b[0m".format(source_type.title(), hex(value), global_name))
        self.reconstructed_globals[global_name].append(value)

    def process_global_vars(self, db, tracked):
        logging.debug("Global db: %s", db)
        logging.debug("Global accesses: %s", tracked)
        # TODO: This might not be sane.
        for (entry, visibility), value in zip(db, tracked):
            self.maybe_track_global(entry, value, 'var')
            self.global_variable_offsets += 1

    def process_parameter_matches_distance(self, db, parameter_accesses):
        # Dict indexed by parameter index
        processed_db = defaultdict(list)

        for entry in db:
            param_idx = int(entry.symbol[1:])
            processed_db[param_idx].append(entry)


        for (param_idx, entries) in processed_db.items():
            access_count = min(len(entries), len(parameter_accesses[param_idx]))
            filtered_accesses = list(filter(lambda x: x[1] < MAX_REASONABLE_OFFSET and x > 0, parameter_accesses[param_idx][:access_count]))
            print("Calculating distances between:", entries, " and:", filtered_accesses)
            for (entry_idx, db_entry) in enumerate(entries[:access_count]):

                for (access_idx, access) in enumerate(filtered_accesses):
                    offset = access[1]

                    distance = abs(access_idx - entry_idx)
                    print("Distance found:", distance, " between access, ", access, " and", db_entry)
                    logging.info("\x1b[32m[Parameter] Found offset {} for {}->{}\x1b[0m".format(hex(offset), db_entry.stype, db_entry.field))
                    self.reconstructed_types[db_entry.stype].append((db_entry.field, offset, distance, "{}[{}][PARAMETER]@{}".format(self.name, self.linkage, hex(self.addr))))
                    self.parameter_offsets += 1

    def process_parameter_matches_regular(self, db, parameter_accesses):
        # Dict indexed by parameter index
        processed_db = defaultdict(list)

        for entry in db:
            param_idx = int(entry.symbol[1:])
            processed_db[param_idx].append(entry)

        logging.debug("Parameter db: %s", processed_db)
        logging.debug("Parameter accesses: %s", parameter_accesses)

        for (param_idx, entries) in processed_db.items():
            for (db_entry, access) in zip(entries, parameter_accesses[param_idx]):
                offset = access[1]

                if offset > MAX_REASONABLE_OFFSET or offset < 0:
                    continue

                if len(db_entry.fields) == 1:
                    member = db_entry.fields[0].member
                    logging.info("\x1b[32m[Parameter] Found offset {} for {}->{}\x1b[0m".format(hex(offset), db_entry.stype, member))
                    self.reconstructed_types[db_entry.stype].append((member, offset, -1, "{}[{}][PARAMETER]@{}".format(self.name, self.linkage, hex(self.addr))))
                    self.parameter_offsets += 1
                else:
                    self.pending_types[db_entry.stype].append((db_entry.fields, offset, "{}[{}][PARAMETER]@{}".format(self.name, self.linkage, hex(self.addr))))



    def process_global_matches(self, global_db, global_accesses):

        logging.debug("Global db: %s", global_db)
        logging.debug("Global accesses: %s", global_accesses)

        # TODO: sort globals by access address?
        for global_db_entry in global_db:
            if global_db_entry.symbol not in self.all_symbols:
                sym = global_db_entry.symbol
                if sym.startswith("<private>"):
                    private = True
                    sym = sym[len("<private>"):]
                else:
                    private = False
                    logging.info("\x1b[31mNo offset for global:(\x1b[0m")
                for key, access in global_accesses.items():
                    self.pending_globals[sym].append((global_db_entry.stype, global_db_entry.fields, private, access[1], "{}[{}][GLOBAL_{}]@{}".format(self.name, self.linkage, "PRIVATE" if private else "PUBLIC", hex(self.addr))))
                continue

            for (key, access) in global_accesses.items():
                offset = access[1] - self.all_symbols[global_db_entry.symbol]
                if offset > MAX_REASONABLE_OFFSET or offset < 0:
                    continue

                if len(global_db_entry.fields) == 1:
                    member = global_db_entry.fields[0].member
                    logging.info("\x1b[32m[Global] Found offset {} for {}->{}\x1b[0m".format(hex(offset), global_db_entry.stype, member))
                    self.reconstructed_types[global_db_entry.stype].append((member, offset, -1, "{}[{}][GLOBAL]@{}".format(self.name, self.linkage, hex(self.addr))))
                    self.global_offsets += 1
                    
                    del global_accesses[key]
                    break
                else:
                    self.pending_types[global_db_entry.stype].append((global_db_entry.fields, offset, "{}[{}][GLOBAL]@{}".format(self.name, self.linkage, hex(self.addr))))
                

    def process_tracked_calls(self, model, call_db, tracked_calls):
        call_db = copy.deepcopy(call_db)
        logging.debug("Call db: %s", call_db)
        logging.debug("Tracked calls: %s", tracked_calls)
        all_possible_fn_calls = {}
        for db_entry in call_db:
            all_possible_fn_calls[db_entry.callee] = False
        
        # TODO: Clone dbs first because we remove indices from it
        # TODO: sort dict by addr (key)?
        for (callee, parameters) in tracked_calls.values():
            if callee in all_possible_fn_calls:
                all_possible_fn_calls[callee] = True
            for (rm_idx, call) in enumerate(call_db):
                if call.callee == callee:
                    for (idx, info) in call.arguments.items():
                        if isinstance(info, str):
                            # Argument could be (the address of) a global.
                            self.maybe_track_global(info.lstrip('#'), parameters[idx], 'call')
                        else:
                            stype = info.stype
                            member = info.fields[0].member
                            if parameters[idx].deref_offset is not None and parameters[idx].latest_offset is None:
                                offset = parameters[idx].deref_offset
                            elif parameters[idx].latest_offset is not None:
                                offset = parameters[idx].latest_offset
                            else:
                                continue
                            if offset > MAX_REASONABLE_OFFSET or offset < 0:
                                continue

                            if len(info.fields) == 1:
                                logging.info("\x1b[32m[Call] Found callee for: {}->{} @ {}\x1b[0m".format(stype, member, offset))
                                self.reconstructed_types[stype].append((member, offset, -1, "{}[{}][CALL]@{}".format(self.name, self.linkage, hex(self.addr))))
                                self.call_offsets += 1
                            else:
                                self.pending_types[stype].append((info.fields, offset, "{}[{}][CALL]@{}".format(self.name, self.linkage, hex(self.addr))))
                    del call_db[rm_idx]
                    break

        # Consider functions that most likely have been inlined
        for fn_name, seen in all_possible_fn_calls.items():
            if seen:
                continue

            probably_inlined_db = copy.deepcopy(model.get(fn_name))
            if not probably_inlined_db:
                self.unknown_function_calls += 1
                logging.info("\x1b[31mFor recursive call tracking: {} not found in GCC Info File!\x1b[0m".format(fn_name))
                continue

            logging.info("Recursively tracking calls for: %s", fn_name)

            for rm_idx, inlined_call in enumerate(probably_inlined_db.calls):
                for original_call in all_possible_fn_calls.keys():
                    #logging.info("Checking for original call: %s", original_call)
                    if inlined_call.callee == original_call:
                        logging.info("Can't consider call '%s' because it already occured in the original function!", inlined_call.callee)
                        break
                else:
                    # Here we can actually track it
                    for (callee, parameters) in tracked_calls.values():
                        if inlined_call.callee == callee:
                            for (idx, info) in inlined_call.arguments.items():
                                if isinstance(info, str):
                                    # Argument could be (the address of) a global.
                                    self.maybe_track_global(info.lstrip('#'), parameters[idx], 'call')
                                else:
                                    stype = info.stype
                                    member = info.fields[0].member
                                    if parameters[idx].deref_offset is not None and parameters[idx].latest_offset is None:
                                        offset = parameters[idx].deref_offset
                                    elif parameters[idx].latest_offset is not None:
                                        offset = parameters[idx].latest_offset
                                    else:
                                        continue
                                    if offset > MAX_REASONABLE_OFFSET or offset < 0:
                                        continue

                                    if len(info.fields) == 1:
                                        logging.info("\x1b[32m[Call Recursive] Found callee for: {}->{} @ {}\x1b[0m".format(stype, member, offset))
                                        self.reconstructed_types[stype].append((member, offset, -1, "{}[{}][CALL_RECURSIVE]@{}".format(self.name, self.linkage, hex(self.addr))))
                                        self.inlined_call_offsets += 1
                                    else:
                                        self.pending_types[stype].append((info.fields, offset, "{}[{}][CALL_RECURSIVE]@{}".format(self.name, self.linkage, hex(self.addr))))
                            del probably_inlined_db.calls[rm_idx]
                            break






    def process_tracked_indirect_calls(self, indirect_call_db, tracked_indirect_calls):

        # TODO: sort dict by addr (key)?
        for ((tracked_source, parameters), (call)) in zip(tracked_indirect_calls.values(), indirect_call_db):
            # Deal with source of the indirect call
            source = call.callee
            # FIXME!!
            if "->" not in source.stype and source.stype != "?" and tracked_source != "ALREADY_GLOBAL_IDENTIFIED":
                struct = source.stype
                if len(source.fields) == 1:
                    member = source.fields[0].member

                    if source.direct:
                        offset = tracked_source.latest_offset
                    else:
                        offset = tracked_source.deref_offset

                    # If an access through a global happens we don't track it here, but we should have caught it already anyways
                    if offset is not None:
                        logging.info("\x1b[32m[Indirect Call] Found callee for: {}->{} @ {}\x1b[0m".format(struct, member, offset))
                        self.reconstructed_types[struct].append((member, offset, -1, "{}[{}][INDIRECT_CALL]@{}".format(self.name, self.linkage, hex(self.addr))))
                        self.indirect_call_offsets += 1
                else:
                    logging.warn("Indirect call fields not tracked!")

            for (idx, info) in call.arguments.items():
                if isinstance(info, str):
                    # Argument could be (the address of) a global.
                    self.maybe_track_global(info.lstrip('#'), parameters[idx], 'call')
                else:
                    stype = info.stype
                    member = info.fields[0].member
                    if parameters[idx].deref_offset is not None and parameters[idx].latest_offset is None:
                        offset = parameters[idx].deref_offset
                    elif parameters[idx].latest_offset is not None:
                        offset = parameters[idx].latest_offset
                    else:
                        continue
                    if offset > MAX_REASONABLE_OFFSET or offset < 0:
                        continue

                    if len(info.fields) == 1:
                        logging.info("\x1b[32m[Indirect Call] Found argument for: {}->{} @ {}\x1b[0m".format(stype, member, offset))
                        self.reconstructed_types[stype].append((member, offset, -1, "{}[{}][INDIRECT_CALL_ARG]@{}".format(self.name, self.linkage, hex(self.addr))))
                        self.indirect_call_offsets += 1
                    else:
                        self.pending_types[stype].append((info.fields, offset, "{}[{}][INDIRECT_CALL_ARG]@{}".format(self.name, self.linkage, hex(self.addr))))



    def process_containerofs(self, containerof_db, containerof_accesses):
        logging.debug("Containerof db: %s", containerof_db)
        logging.debug("Containerof accesses: %s", containerof_accesses)

        ordered_accesses = OrderedDict()
        for offset in containerof_accesses.values():
            if offset not in ordered_accesses:
                ordered_accesses[offset] = 1
            else:
                ordered_accesses[offset] += 1

        ordered_db = OrderedDict()
        for db_entry in containerof_db:
            if db_entry not in ordered_db:
                ordered_db[db_entry] = 1
            else:
                ordered_db[db_entry] += 1

        for (db_entry, count1) in ordered_db.items():
            for (offset, count2) in ordered_accesses.items():
                if count1 == count2:
                    member = db_entry.fields
                    logging.info("\x1b[32m[container_of] Found offset: {}->{} @ {}!\x1b[0m".format(db_entry.stype, member, offset))
                    self.reconstructed_types[db_entry.stype].append((member, offset, -1, "{}[{}][CONTAINER]@{}".format(self.name, self.linkage, hex(self.addr))))
                    self.containerof_offsets += 1

                    del ordered_accesses[offset]
                    break
            else:
                logging.info("\x1b[31mNo offset for containerof :(\x1b[0m")

    def process_return_values(self, return_value_db, return_values):
        logging.debug("Return value db: %s", return_value_db)
        logging.debug("Return value accesses: %s", return_values)

        # Only track the last return
        if return_value_db and return_values:
            db_entry = return_value_db[-1]
            return_value = return_values[-1]

            if db_entry.direct:
                offset = return_value.latest_offset
            else:
                offset = return_value.deref_offset

            if offset is not None and offset >= 0 and offset <= MAX_REASONABLE_OFFSET and db_entry.stype != '???':
                if len(db_entry.fields) == 1:
                    member = db_entry.fields[0].member
                    logging.info("\x1b[32m[Return Value] Found offset {} for {}->{}\x1b[0m".format(hex(offset), db_entry.stype, member))
                    self.reconstructed_types[db_entry.stype].append((member, offset, -1, "{}[{}][RETURN_VALUE]@{}".format(self.name, self.linkage, hex(self.addr))))
                    self.return_value_offsets += 1
                else:
                    self.pending_types[db_entry.stype].append((db_entry.fields, offset, "{}[{}][RETURN_VALUE]@{}".format(self.name, self.linkage, hex(self.addr))))

    def process_return_value_accesses(self, return_value_accesses_db, return_value_accesses):
        logging.debug("Return value call db: %s", return_value_accesses_db)
        logging.debug("Return value call accesses: %s", return_value_accesses)

        if not (return_value_accesses_db and return_value_accesses):
            return

        for db_entry in return_value_accesses_db:
            for (access_addr, (callee, offset)) in return_value_accesses.items():
                if db_entry.symbol == (callee + '()'):
                    member = db_entry.fields[0].member
                    if offset > MAX_REASONABLE_OFFSET or offset < 0:
                        continue

                    if len(db_entry.fields) == 1:
                        logging.info("\x1b[32m[Return Value Access] Found deref for: {}->{} @ {}\x1b[0m".format(db_entry.stype, member, offset))
                        self.reconstructed_types[db_entry.stype].append((member, offset, -1, "{}[{}][RETURN_VALUE_ACCESS]@{}".format(self.name, self.linkage, hex(self.addr))))
                        self.return_value_access_offsets += 1
                        del return_value_accesses[access_addr]
                        break
                    else:
                        self.pending_types[db_entry.stype].append((db_entry.fields, offset, "{}[{}][RETURN_VALUE_ACCESS]@{}".format(self.name, self.linkage, hex(self.addr))))


    def save_info(self, file_name):
        print("Found parameter offsets: ", self.parameter_offsets)
        print("Found global offsets: ", self.global_offsets)
        print("Found global variable offsets: ", self.global_variable_offsets)
        print("Found call offsets: ", self.call_offsets)
        print("Found indirect call offsets: ", self.indirect_call_offsets)
        print("Found containerof offsets: ", self.containerof_offsets)
        print("Found return value offsets: ", self.return_value_offsets)
        print("Found return value access offsets: ", self.return_value_access_offsets)
        print("Found inlined function calls: ", self.inlined_call_offsets)
        print("Amount unknown function calls: ", self.unknown_function_calls)

        import json
        with open(file_name, "w") as outfile:
            wrapper = {}
            wrapper['reconstructed'] = self.reconstructed_types
            wrapper['pending'] = self.pending_types
            wrapper['globals'] = {
                "reconstructed": self.reconstructed_globals,
                "pending": self.pending_globals
            }
            json.dump(wrapper, outfile, indent=2)
