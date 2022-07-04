import json
import argparse
import glob
import os
import collections

p = argparse.ArgumentParser()
p.add_argument("indir")
p.add_argument("outfile")
args = p.parse_args()

db = collections.defaultdict(list)
items = 0

for i in glob.glob(os.path.join(args.indir, "*.c")):
    print("DB Items {} - Processing {}".format(items, i))
    d = json.load(open(i))
    for e in d:
        # Normalize path, sometimes the GCC adds a ./ at the start
        e["loc"] = os.path.normpath(e["loc"])

        # Do some sanity checks for the rare case of clashing struct names
        old = db[e["name"]]
        if len(old) > 0:
            # Simple case: The same header was compiled in different compilation units -> ignore
            # Note: There are structs in the kernel with different locations and same field layout. We do not care here about them...
            # If they have the same layout, we do not treat them seperatly
            if any(oe["fields"] == e["fields"] for oe in old):
                continue
            elif all(oe["loc"] != e["loc"] for oe in old):
                print("Warning: Same struct name, but different fields and location {} differs in file {}".format(e["name"], i))
            elif "vdso32" in i:
                print("Skipping vdso32 duplicate!")
                continue
            else:
                print("Warning: Same struct name, same location but different fields! {} differs in file {}".format(e["name"], i))
        db[e["name"]].append(e)
        items += 1

with open(args.outfile, "w") as sf:
    json.dump(db, sf, indent=2)
