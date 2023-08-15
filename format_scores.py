import key_int
from xmap import XMap
from diff import DecomposedFunction, DecompDB
import collections
import pickle

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
    scores = key_int.read_in_key_integer_file("retsam_pokeheartgold_scores.dump")
    hgss_db = load_pickle_from_filename("pokeheartgold_decomposed_function_database.pickle")
    retsam_db = load_pickle_from_filename("retsam_decomposed_function_database.pickle")

    hgss_xmap = XMap("../pokeheartgold/build/heartgold.us/main.elf.xMAP", ".main")
    retsam_xmap = XMap("../retsam_00jupc/bin/ARM9-TS/Rom/main.nef.xMAP", ".main")
    platinum_xmap = XMap("../pokeplatinum-new/build/main.nef.xMAP", ".main")

    short_id_to_decomp_db = {
        "h": hgss_db,
        "r": retsam_db
    }

    hgss_to_retsam_zero_scores = collections.defaultdict(list)

    for score_function_names, score in scores.items():
        hgss_function_key, retsam_function_key = score_function_names.split(";", maxsplit=1)
        hgss_symbol = DecomposedFunction.key_to_symbol(hgss_function_key, short_id_to_decomp_db)
        if hgss_symbol.full_addr.addr == -1:
            print("Skipped deadstripped 
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

    output = []

    for hgss_full_addr, corresponding_plat_and_retsam_symbols in hgss_to_retsam_zero_scores.items():
        hgss_symbol = hgss_xmap.symbols_by_addr[hgss_full_addr].name
        plat_and_retsam_symbol_names_and_addrs = []

        for corresponding_plat_and_retsam_symbol in corresponding_plat_and_retsam_symbols:
            plat_symbol = corresponding_plat_and_retsam_symbol.plat_symbol
            retsam_symbol = corresponding_plat_and_retsam_symbol.retsam_symbol

            if plat_symbol is not None:
                plat_and_retsam_symbol_names_and_addrs.append(f"({plat_symbol.name}, {retsam_symbol.name} at {retsam_symbol.full_addr})")
            else:
                plat_and_retsam_symbol_names_and_addrs.append(f"({retsam_symbol.name} at {retsam_symbol.full_addr})")

        output.extend(f"{hgss_symbol.name} ({hgss_full_addr}) -> {', '.join(plat_and_retsam_symbol_names_and_addrs)}\n")

    with open("hgss_retsam_matching_funcs.dump", "w+") as f:
        f.write("".join(output))

if __name__ == "__main__":
    main()
