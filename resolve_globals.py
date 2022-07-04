# This is run from resolve_direct_accesses.py!
# It tries to use the newly resolved struct offsets to generate additional candidates for
# global accesses.

import collections

if __name__ == '__main__':
    print('Did you mean to run resolve_direct_accesses.py?')
    exit(1)

# For debugging, add pending global entries that could not be resolved back...
DO_ADD_PENDING_AS = None # '___PENDING___'

def resolve_entry(entry, layout):
    typename, members, is_private_symbol, address, source = entry
    lookups = []
    prev_type = typename
    for member, result_type in members:
        lookups.append((prev_type, member))
        prev_type = result_type
    for base_type, member in lookups[::-1]:
        offset = layout[base_type][member]
        if offset is None:
            return None
        address -= offset
    return address

def resolve_globals(global_guesses, layout):
    reconstructed_globals = global_guesses['reconstructed']
    pending_globals = global_guesses['pending']

    remaining = collections.defaultdict(list)
    for global_name, entries in pending_globals.items():
        for entry in entries:
            address = resolve_entry(entry, layout)
            if address is None:
                if DO_ADD_PENDING_AS:
                    remaining[global_name].append(entry)
            else:
                if global_name not in reconstructed_globals:
                    reconstructed_globals[global_name] = []
                reconstructed_globals[global_name].append(address)

    if DO_ADD_PENDING_AS:
        reconstructed_globals[DO_ADD_PENDING_AS] = remaining
    return reconstructed_globals
