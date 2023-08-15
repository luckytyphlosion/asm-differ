import key_int
from xmap import XMap
from diff import DecomposedFunction, DecompDB, Line
import collections
import pickle
import pathlib
import glob

class ScoreEntry:
    __slots__ = ("name", "score", "other_symbol")

    def __init__(self, name, score, other_symbol):
        self.name = name
        self.score = score
        self.other_symbol

class PlatAndRetsamSymbol:
    __slots__ = ("plat_symbol", "retsam_symbol")

    def __init__(self, plat_symbol, retsam_symbol):
        self.plat_symbol = plat_symbol
        self.retsam_symbol = retsam_symbol

def load_pickle_from_filename(filename):
    with open(filename, "rb") as f:
        return pickle.load(f)

def main():
    print("Reading in files!")
    scores = key_int.read_in_key_integer_file("retsam_pokeheartgold_scores.dump")
    hgss_db = load_pickle_from_filename("pokeheartgold_decomposed_function_database.pickle")
    retsam_db = load_pickle_from_filename("retsam_decomposed_function_database.pickle")

    hgss_xmap = XMap("../pokeheartgold/build/heartgold.us/main.elf.xMAP", ".main")
    retsam_xmap = XMap("../retsam_00jupc/bin/ARM9-TS/Rom/main.nef.xMAP", ".main")
    platinum_xmap = XMap("../pokeplatinum-new/build/main.nef.xMAP", ".main")

    short_id_to_decomp_db = {
        "p": hgss_db,
        "r": retsam_db
    }

    hgss_to_retsam_zero_scores = collections.defaultdict(list)

    function_filename_asm_or_src = {}

    print("Finding asm vs. src objects!")

    for obj_full_filename in glob.glob(f"../pokeheartgold/build/heartgold.us/**/*.o", recursive=True):
        if "/asm/" in obj_full_filename:
            subdir_value = "asm"
        elif "/src/" in obj_full_filename:
            subdir_value = "src"
        else:
            subdir_value = None

        if subdir_value is not None:
            function_filename_asm_or_src[pathlib.Path(obj_full_filename).name] = subdir_value

    print("Going over scores!")

    for i, (score_function_names, score) in enumerate(scores.items()):
        hgss_function_key, retsam_function_key = score_function_names.split(";", maxsplit=1)
        hgss_symbol = DecomposedFunction.key_to_symbol(hgss_function_key, short_id_to_decomp_db)
        if hgss_symbol.full_addr.addr == -1:
            print(f"Skipped deadstripped hgss function {hgss_symbol.name}!")
            continue

        retsam_symbol = DecomposedFunction.key_to_symbol(retsam_function_key, short_id_to_decomp_db)

        if score == 0:
            if retsam_symbol.full_addr.addr != -1:
                plat_symbol = platinum_xmap.symbols_by_addr.get(retsam_symbol.full_addr)
            else:
                plat_symbol = None

            hgss_to_retsam_zero_scores[hgss_symbol.full_addr].append(PlatAndRetsamSymbol(plat_symbol, retsam_symbol))
        else:
            pass

        if i & 0xffff == 0:
            print(f"i: {i}")

    asm_output = []
    src_output = []

    for hgss_full_addr, corresponding_plat_and_retsam_symbols in hgss_to_retsam_zero_scores.items():
        hgss_symbol = hgss_xmap.symbols_by_addr[hgss_full_addr]
        plat_and_retsam_symbol_names_and_addrs = []

        for i, corresponding_plat_and_retsam_symbol in enumerate(corresponding_plat_and_retsam_symbols):
            plat_symbol = corresponding_plat_and_retsam_symbol.plat_symbol
            retsam_symbol = corresponding_plat_and_retsam_symbol.retsam_symbol

            if plat_symbol is not None:
                plat_and_retsam_symbol_names_and_addrs.append(f"  {plat_symbol.name}, {retsam_symbol.name} [{retsam_symbol.full_addr}]\n")
            else:
                plat_and_retsam_symbol_names_and_addrs.append(f"  {retsam_symbol.name}\n")
            if i >= 4:
                plat_and_retsam_symbol_names_and_addrs.append(f"  <{len(corresponding_plat_and_retsam_symbols) - 5} functions remaining>\n")
                break

        cur_output = f"{hgss_symbol.name} ({hgss_full_addr}):\n{''.join(plat_and_retsam_symbol_names_and_addrs)}\n"

        if function_filename_asm_or_src[hgss_symbol.filename] == "asm":
            asm_output.append(cur_output)
        else:
            src_output.append(cur_output)

    output = ""
    output += f"== ASM functions (total {len(asm_output)}) ==\n{''.join(asm_output)}\n\n== src functions (total {len(src_output)}) ==\n{''.join(src_output)}\n"

    with open("hgss_retsam_matching_funcs.dump", "w+") as f:
        f.write("".join(output))

if __name__ == "__main__":
    main()
