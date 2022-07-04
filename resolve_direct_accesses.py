#!/usr/bin/env python3
import argparse
import enum
import collections
import json
import re
import subprocess
import sys
from sympy import *
import numpy as np
from collections import defaultdict

from pcode.layout import Layout
import pendinglayout

from resolve_globals import resolve_globals

def count_members(type_dict):
    count = 0
    for struct in type_dict:
        count += len(type_dict[struct].items())

    return count

def keyify(fields):
    return '.'.join([a + b for (a, b) in fields])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('layout', help='path to layout')
    parser.add_argument('structinfo', help='path to structinfo')
    args = parser.parse_args()

    layout_path = args.layout
    with open(layout_path) as jsonf:
        extracted = json.load(jsonf)

    reconstructed_offsets = extracted['reconstructed']
    layout = Layout(reconstructed_offsets, args.structinfo) # Replicate majority vote accurately, instead of doing it in here...
    pending_offsets = extracted['pending']

    global_info = extracted['globals']

    for (struct, members) in pending_offsets.items():
        for foo in members:
            foo.insert(0, keyify(foo[0]))

    pending_layout = pendinglayout.Layout(pending_offsets)

    majority_pending = defaultdict(dict)
    for (struct, members) in pending_offsets.items():
        for (key, links, offset, source) in members:
            majority = pending_layout[struct][key]
            trust = pending_layout[struct].get_trust_for_fields(key)
            majority_pending[struct][key] = (links, majority, trust, False)

    changed = True
    while changed:
        print("Restarting!")
        changed = False
        for (outer_struct, members) in list(majority_pending.items()):
            for (x, (links, offset, pending_trust, _)) in filter(lambda x: x[1][3] == False, members.items()):
                print(f"Looking at: {outer_struct} -> {links} @ {offset} T {pending_trust}")

                # Produce equation we can't solve yet
                var_map = dict()
                var_idx = 0
                current_struct = outer_struct
                eq = "Eq("
                for link in links:
                    (member, struct) = link
                    #print("Link:", link)
                    new_var = (current_struct, member)

                    if new_var in var_map:
                        var_name = var_map[new_var]
                    else:
                        var_name = f"var_{var_idx}"
                        var_map[new_var] = var_name
                        var_idx += 1

                    eq += f"{var_name}+"
                    current_struct = struct

                eq = eq[:-1]
                eq += f", {offset})"

                # Get the number of unknowns
                num_unknowns = len(links)
                for ((struct, member), var) in var_map.items():
                    if member in layout[struct]:
                        num_unknowns -= 1

                # If we have have an offset for everything in this chain we figure out the least trustworthy and leave it out of the chain
                least_trust = 99999999
                least_trust_idx = None
                if num_unknowns == 0:
                    for idx, ((struct, member), var) in enumerate(var_map.items()):
                        cur_trust = layout[struct].get_trust_for_member(member)
                        if cur_trust < least_trust:
                            least_trust = cur_trust
                            least_trust_idx = idx

                # If however the chain is even less trustworthy we trust the members and most likely will not get a result
                if least_trust > pending_trust:
                    print("Chain not trustworthy!")
                    least_trust_idx = None

                # Add variables that we know the value of
                unknowns = []
                for idx, ((struct, member), var) in enumerate(var_map.items()):
                    if idx != least_trust_idx and member in layout[struct]:
                        eq += f",Eq({var}, {layout[struct][member]})"
                    else:
                        unknowns.append((struct, member))

                # Add overlapping unknowns
                current_struct = outer_struct
                for idx, (member, struct) in enumerate(links):
                    generated = (current_struct, [(member, struct)])
                    inner_current_struct = struct
                    for (inner_member, inner_struct) in links[idx+1:]:
                        generated[1].append((inner_member, inner_struct))
                        inner_current_struct = inner_struct
                        #print("Generated:", generated)

                        (eq_struct, eq_fields) = generated
                        try:
                            inner_offset = majority_pending[eq_struct][keyify(eq_fields)][1]
                            #print("Offset:", inner_offset)
                            #print("Var Map:", var_map)

                            new_eq = "Eq("
                            b = eq_struct
                            for (eq_member, eq_struct) in eq_fields:
                                #print("Var Map idx:", (b, eq_member))
                                new_eq += f"{var_map[(b, eq_member)]}+"
                                b = eq_struct
                            new_eq = new_eq[:-1]
                            new_eq += f", {inner_offset})"

                            eq += f",{new_eq}"
                        except KeyError:
                            pass
                            #print("Keyerror!")


                    current_struct = struct

                print("Final equation:", eq)
                solution = solve(sympify(eq))
                print("Solution:", solution)
                if isinstance(solution, list):
                    print("Couldn't derive anything")
                else:
                    num_resolved = 0
                    if least_trust_idx is not None:
                        least_trust = 99999999
                        for idx, ((struct, member), var) in enumerate(var_map.items()):
                            if idx == least_trust_idx:
                                continue
                            cur_trust = layout[struct].get_trust_for_member(member)
                            if cur_trust < least_trust:
                                least_trust = cur_trust

                        if least_trust == 99999999:
                            print("BUG")
                            sys.exit(-1)

                        if least_trust < pending_trust:
                            final_trust = least_trust
                        else:
                            final_trust = pending_trust
                    else:
                        final_trust = pending_trust
                    final_trust = least_trust if least_trust_idx is not None else pending_trust
                    for unknown in unknowns:
                        struct, member = unknown
                        key = symbols(var_map[unknown])
                        try:
                            resolved = int(solution[key])
                        except KeyError:
                            #print("Couldn't resolve")
                            resolved = None
                        except TypeError:
                            #print("Couldn't resolve")
                            resolved = None

                        if resolved is not None and resolved > 0 and resolved <= 8000:
                            print(f"Resolved {struct}->{member} @ {resolved}!")
                            if struct not in reconstructed_offsets:
                                reconstructed_offsets[struct] = []
                            reconstructed_offsets[struct].append((member, resolved, -1, f"[RESOLVED_FROM_DOTS]TRUST={final_trust}"))
                            changed = True
                            num_resolved += 1

                    if num_resolved == len(unknowns):
                        print("Everything resolved for this chain!")
                        majority_pending[outer_struct][x] = (links, offset, final_trust, True)

    wrapper = {}
    wrapper['reconstructed'] = reconstructed_offsets
    wrapper['pending'] = pending_offsets
    wrapper['globals'] = resolve_globals(global_info, Layout(reconstructed_offsets, args.structinfo))
    with open(f"{layout_path}-processed", "w") as f:
        json.dump(wrapper, f, indent=2)
