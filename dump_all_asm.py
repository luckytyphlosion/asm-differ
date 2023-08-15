import argparse
from xmap import XMap, OvAddr
import glob
import pathlib
import sys
import subprocess
import json
import re

decomposed_function_addr_split_regex = re.compile("^[0-9a-f]{8} <", flags=re.MULTILINE)
dummy_or_zero_function_regex = re.compile("^(?:\s+[0-9a-f]+:\s+2000\s+movs\s+r0,\s+#0\n)?\s+[0-9a-f]+:\s+4770\s+bx\s+lr", flags=0)

def check_symbol_deadstripped(xmap, function_name, obj_basename):
    possible_symbols = xmap.symbols_by_name.get(function_name)

    if possible_symbols is not None:
        found_symbol = None
    
        for possible_symbol in possible_symbols:
            if possible_symbol.filename == obj_basename:
                found_symbol = possible_symbol
                break
    
        if found_symbol is None:
            print(f"Deadstripped function {function_name} found in {obj_basename}, name exists in {', '.join(symbol.filename for symbol in possible_symbols)}!")
            found_symbol_serialized = None
        else:
            found_symbol_serialized = found_symbol.serialize()
    else:
        print(f"Deadstripped function {function_name} found in {obj_basename}!")
        found_symbol_serialized = None

    return found_symbol_serialized

# python3 diff.py --decomp-diff-1 retsam_decomposed_function_database.json --decomp-diff-2 pokeheartgold_decomposed_function_database.json --decomp-diff-results-info retsam_pokeheartgold_processed.dump --decomp-diff-results-score retsam_pokeheartgold_scores.dump -I --no-show-branches NitroMain

def main():
    MODE = 1
    if MODE == 0:
        DEFAULT_XMAP_FILENAME = "../pokeheartgold/build/heartgold.us/main.elf.xMAP"
        DEFAULT_BUILD_DIR = "../pokeheartgold/build"
        DATABASE_FILENAME = "pokeheartgold_decomposed_function_database.json"
        DEFAULT_ID = "pokeheartgold"
    elif MODE == 1:
        DEFAULT_XMAP_FILENAME = "../retsam_00jupc/bin/ARM9-TS/Rom/main.nef.xMAP"
        DEFAULT_BUILD_DIR = "../retsam_00jupc/obj"
        DATABASE_FILENAME = "retsam_decomposed_function_database.json"
        DEFAULT_ID = "retsam"
    else:
        print("No mode selected!")
        sys.exit(1)

    ap = argparse.ArgumentParser()
    ap.add_argument("-x", "--xmap-filename", dest="xmap_filename", default=DEFAULT_XMAP_FILENAME, help="Filename to XMap")
    ap.add_argument("-b", "--build-dir", dest="build_dir", default=DEFAULT_BUILD_DIR, help="Project directory")
    ap.add_argument("-o", "--database-filename", dest="database_filename", default=DATABASE_FILENAME, help="Database filename")
    ap.add_argument("-id", "--id", dest="id", default=DEFAULT_ID, help="Id.")

    args = ap.parse_args()

    xmap = XMap(args.xmap_filename, ".main")

    output = ""

    obj_basenames_from_xmap = {basename: 0 for basename in xmap.symbols_by_filename.keys()}
    existing_obj_full_filenames = []

    for obj_full_filename in glob.glob(f"{args.build_dir}/**/*.o", recursive=True):
        print(f"obj_full_filename: {obj_full_filename}")

        if "/lib/" in obj_full_filename:
            continue

        obj_basename_from_build_dir = pathlib.Path(obj_full_filename).name
        basename_count = obj_basenames_from_xmap.get(obj_basename_from_build_dir)
        if basename_count is None:
            print(f"Warning: {obj_full_filename} not in xmap!")
        else:
            basename_count += 1
            if basename_count > 1:
                print(f"Warning: {obj_basename_from_build_dir} has multiple full names!")
            obj_basenames_from_xmap[obj_basename_from_build_dir] = basename_count
            existing_obj_full_filenames.append(obj_full_filename)

    decomposed_function_database_contents = []
    obj_symbol_names = set()
    iter_count = 0

    for obj_full_filename in existing_obj_full_filenames:
        print(f"Disassembling {obj_full_filename}!")
        obj_basename = pathlib.Path(obj_full_filename).name
        #if obj_basename != "fieldobj_drawdata.o":
        #    continue

        asm_differ_output = subprocess.check_output(["python3", "diff.py", "-f", obj_full_filename, "-1", "--ds-test", "--print-asm", "NitroMain"]).decode("utf-8")
        stripped_asm_differ_output = asm_differ_output.strip()
        if stripped_asm_differ_output == "":
            print(f"Found non-text object {obj_basename}!")
            continue

        no_section_asm_differ_output = stripped_asm_differ_output.replace("Disassembly of section .text:", "").strip()

        decomposed_functions_str_for_obj = [x.strip() for x in decomposed_function_addr_split_regex.split(no_section_asm_differ_output)]
        for decomposed_function_str in decomposed_functions_str_for_obj:
            if decomposed_function_str == "":
                continue

            function_name, seperator, rest_of_function = decomposed_function_str.partition(">:\n")
            if dummy_or_zero_function_regex.match(rest_of_function):
                print(f"Found dummy or return zero function {function_name}!\n{rest_of_function}")
                continue

            #match_obj = decomposed_function_str_name_regex.match(function_name_line)
            #if not match_obj:
            #    raise RuntimeError(f"Non-matching function_name_line found! function_name_line: {function_name_line}, obj_basename: {obj_basename}, asm_differ_output: {asm_differ_output}")

            found_symbol_serialized = check_symbol_deadstripped(xmap, function_name, obj_basename)
            if found_symbol_serialized is None:
                deadstripped = True
                found_symbol_serialized = {
                    "name": function_name,
                    "full_addr": {
                        "overlay": -1,
                        "addr": -1
                    },
                    "section": ".text",
                    "size": 0,
                    "filename": obj_basename,
                    "archive": None
                }
            else:
                deadstripped = False

            decomposed_function = {
                "name": function_name,
                "symbol": found_symbol_serialized,
                "contents": rest_of_function,
                "deadstripped": deadstripped
            }

            obj_symbol_names.add(function_name)
            decomposed_function_database_contents.append(decomposed_function)
        
        iter_count += 1
        #if iter_count > 5:
        #    break

    decomposed_function_database_contents.sort(key=lambda x: OvAddr.unserialize(x["symbol"]["full_addr"]))

    xmap_symbol_names = set(symbol_name for symbol_name, symbol in xmap.symbols_by_name.items() if symbol[0].section == ".text")

    missing_symbol_names = xmap_symbol_names - obj_symbol_names
    with open(f"missing_symbol_names_{args.id}.dump", "w+") as f:
        f.write("\n".join(missing_symbol_names))

    decomposed_function_database = {
        "id": args.id,
        "contents": decomposed_function_database_contents
    }

    with open(args.database_filename, "w+") as f:
        json.dump(decomposed_function_database, f, indent=2)

if __name__ == "__main__":
    main()
