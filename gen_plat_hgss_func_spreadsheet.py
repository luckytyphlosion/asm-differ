import key_int
from xmap import XMap, OvAddr
from diff import DecomposedFunction, DecompDB, Line, Config, ARM32_SETTINGS, TableData, PlainFormatter, DiffMode, TableLine, Text
import diff as asm_differ
import collections
import pickle
import pathlib
import glob
import json

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

MAX_NONZERO_SCORE_ENTRIES = 5

# hgss filename | plat filename | retsam filename | hgss addr | hgss name | plat addr | plat name | retsam name
#                                                                           plat addr | plat name | retsam name

class NonzeroScoreTracker:
    __slots__ = ("score_table", "last_entry_score")

    def __init__(self):
        self.score_table = collections.defaultdict(lambda: collections.defaultdict(list))
        self.last_entry_score = 2**32 - 1

    def add(self, hgss_symbol, plat_symbol, retsam_symbol, score):
        scores_for_hgss_symbol = self.score_table[hgss_symbol.full_addr]
        if len(scores_for_hgss_symbol) < MAX_NONZERO_SCORE_ENTRIES:
            scores_for_hgss_symbol[score].append(PlatAndRetsamSymbol(plat_symbol, retsam_symbol))
            if len(scores_for_hgss_symbol) == MAX_NONZERO_SCORE_ENTRIES:
                self.last_entry_score = max(scores_for_hgss_symbol.keys())
                #print(f"set last_entry_score: {self.last_entry_score}, scores_for_hgss_symbol.keys(): {tuple(scores_for_hgss_symbol.keys())}")
        else:
            if score <= self.last_entry_score:
                scores_for_hgss_symbol[score].append(PlatAndRetsamSymbol(plat_symbol, retsam_symbol))
                if score < self.last_entry_score:
                    del scores_for_hgss_symbol[self.last_entry_score]
                    self.last_entry_score = max(scores_for_hgss_symbol.keys())
                    #print(f"set last_entry_score: {self.last_entry_score}, scores_for_hgss_symbol.keys(): {tuple(scores_for_hgss_symbol.keys())}")

    def has_addr(self, hgss_full_addr):
        return hgss_full_addr in self.score_table



    def format_output(self, hgss_xmap, function_filename_asm_or_src, create_combined_output=False):
        nonzero_asm_output = []
        nonzero_src_output = []
        nonzero_combined_output_list = []

        for hgss_full_addr, scores_for_hgss_symbol in sorted(self.score_table.items(), key=lambda x: x[0]):
            hgss_symbol = hgss_xmap.symbols_by_addr[hgss_full_addr]
            cur_output = ""
            cur_output += f"{hgss_symbol.name} ({hgss_full_addr})"
            cur_output_pt2 = ""

            for score, corresponding_plat_and_retsam_symbols in sorted(scores_for_hgss_symbol.items(), key=lambda x: x[0])[:5]:
                cur_output_pt2 += f"  Score: {score}\n"

                plat_and_retsam_symbol_names_and_addrs = []

                for i, corresponding_plat_and_retsam_symbol in enumerate(corresponding_plat_and_retsam_symbols):
                    plat_symbol = corresponding_plat_and_retsam_symbol.plat_symbol
                    retsam_symbol = corresponding_plat_and_retsam_symbol.retsam_symbol
        
                    if plat_symbol is not None:
                        plat_and_retsam_symbol_names_and_addrs.append(f"    {plat_symbol.name}, {retsam_symbol.name} [{retsam_symbol.full_addr}]\n")
                    else:
                        plat_and_retsam_symbol_names_and_addrs.append(f"    {retsam_symbol.name} ({retsam_symbol.filename})\n")
                    if i >= 4:
                        plat_and_retsam_symbol_names_and_addrs.append(f"    <{len(corresponding_plat_and_retsam_symbols) - 5} functions remaining>\n")
                        break

                cur_output_pt2 += f"{''.join(plat_and_retsam_symbol_names_and_addrs)}\n"

            cur_output_uncombined = f"{cur_output}:\n{cur_output_pt2}"
            
            if function_filename_asm_or_src[hgss_symbol.filename] == "asm":
                is_asm_func = True
                nonzero_asm_output.append(cur_output_uncombined)
            else:
                is_asm_func = False
                nonzero_src_output.append(cur_output_uncombined)

            if create_combined_output:
                cur_output_combined = f"{cur_output} [{'asm' if is_asm_func else 'src'}]:\n{cur_output_pt2}"
                nonzero_combined_output_list.append(cur_output_combined)

        nonzero_output = ""
        nonzero_output += f"== ASM functions (total {len(nonzero_asm_output)}) ==\n{''.join(nonzero_asm_output)}\n\n== src functions (total {len(nonzero_src_output)}) ==\n{''.join(nonzero_src_output)}\n"

        if len(nonzero_combined_output_list) != 0:
            nonzero_combined_output = f"== All functions (total {len(nonzero_combined_output_list)}) ==\n{''.join(nonzero_combined_output_list)}\n"
        else:
            nonzero_combined_output = ""

        return nonzero_output, nonzero_combined_output


#class SpreadsheetEntry:
#    __slots__ = ("plat_symbol", "retsam_symbol", "hgss_symbol", "score")
#
#    def __init__(self, plat_symbol, retsam_symbol, hgss_symbol, score):
#        self.plat_symbol = plat_symbol
#        self.retsam_symbol = retsam_symbol
#        self.hgss_symbol = hgss_symbol
#        self.score = score

class SpreadsheetEntry:
    __slots__ = ("plat_and_retsam_symbols", "hgss_symbol", "score")

    def __init__(self, plat_and_retsam_symbols, hgss_symbol, score):
        self.plat_and_retsam_symbols = plat_and_retsam_symbols
        self.hgss_symbol = hgss_symbol
        self.score = score

def main():
    print("Reading in files!")
    scores = key_int.read_in_key_integer_file("retsam_pokeheartgold_scores.dump")
    hgss_db = load_pickle_from_filename("pokeheartgold_decomposed_function_database.pickle")
    retsam_db = load_pickle_from_filename("retsam_decomposed_function_database.pickle")

    with open("retsam_decomposed_function_database.json", "r") as f:
        retsam_db_unprocessed = json.load(f)

    retsam_key_to_forced_full_addr = {}
    for sym_info in retsam_db_unprocessed["contents"]:
        retsam_key_to_forced_full_addr[DecomposedFunction.get_key_from_json("r", sym_info)] = OvAddr.unserialize(sym_info["symbol"]["full_addr"])

    hgss_xmap = XMap("../pokeheartgold/build/heartgold.us/main.elf.xMAP", ".main")
    retsam_xmap = XMap("../retsam_00jupc/bin/ARM9-TS/Rom/main.nef.xMAP", ".main")
    platinum_xmap = XMap("../pokeplatinum-new/build/main.nef.xMAP", ".main")

    hgss_decomposed_functions_by_key = DecompDB.create_decomposed_functions_by_key(hgss_db)
    retsam_decomposed_functions_by_key = DecompDB.create_decomposed_functions_by_key(retsam_db)

    for key, retsam_decomposed_function in retsam_decomposed_functions_by_key.items():
        retsam_decomposed_function.symbol.full_addr = retsam_key_to_forced_full_addr[key]

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
    nonzero_score_tracker = NonzeroScoreTracker()
    both_score_tracker = NonzeroScoreTracker()

    sorted_scores = sorted(scores.items(), key=lambda x: x[1])

    for i, (score_function_names, score) in enumerate(sorted_scores):
        hgss_function_key, retsam_function_key = score_function_names.split(";", maxsplit=1)
        hgss_symbol = hgss_decomposed_functions_by_key[hgss_function_key].symbol
        if hgss_symbol.full_addr.addr == -1:
            #print(f"Skipped deadstripped hgss function {hgss_symbol.name}!")
            continue

        retsam_symbol = retsam_decomposed_functions_by_key[retsam_function_key].symbol
        if type(retsam_symbol.full_addr.addr) == int:
            plat_symbol = platinum_xmap.symbols_by_addr.get(retsam_symbol.full_addr)
        else:
            plat_symbol = None

        if score == 0:
            hgss_to_retsam_zero_scores[hgss_symbol.full_addr].append(PlatAndRetsamSymbol(plat_symbol, retsam_symbol))
        elif not hgss_symbol.full_addr in hgss_to_retsam_zero_scores:
            nonzero_score_tracker.add(hgss_symbol, plat_symbol, retsam_symbol, score)

        #both_score_tracker.add(hgss_symbol, plat_symbol, retsam_symbol, score)

        if i & 0xffff == 0:
            #break
            print(f"i: {i}")

        #if i > 10000000:
        #    break

    spreadsheet_data = {}
    ambiguous_corresponding_plat_and_retsam_symbols = {}

    # evaluate all

    for hgss_full_addr, corresponding_plat_and_retsam_symbols in sorted(hgss_to_retsam_zero_scores.items(), key=lambda x: x[0]):
        hgss_symbol, hgss_symbol_index = hgss_xmap.symbols_and_indices_by_addr[hgss_full_addr]
        #if len(corresponding_plat_and_retsam_symbols) == 1:
        #    plat_symbol = corresponding_plat_and_retsam_symbols[0].plat_symbol
        #    retsam_symbol = corresponding_plat_and_retsam_symbols[0].retsam_symbol
        #    spreadsheet_data[hgss_symbol.full_addr] = SpreadsheetEntry(plat_symbol, retsam_symbol, hgss_symbol, 0)
        #else:
        spreadsheet_data[hgss_symbol.full_addr] = SpreadsheetEntry(corresponding_plat_and_retsam_symbols, hgss_symbol, 0)

    for hgss_full_addr, scores_for_hgss_symbol in sorted(nonzero_score_tracker.score_table.items(), key=lambda x: x[0]):
        hgss_symbol = hgss_xmap.symbols_by_addr[hgss_full_addr]
        score, corresponding_plat_and_retsam_symbols = sorted(scores_for_hgss_symbol.items(), key=lambda x: x[0])[0]
        #if len(corresponding_plat_and_retsam_symbols) == 1:
        #    plat_symbol = corresponding_plat_and_retsam_symbols[0].plat_symbol
        #    retsam_symbol = corresponding_plat_and_retsam_symbols[0].retsam_symbol
        #    spreadsheet_data[hgss_full_addr] = SpreadsheetEntry(plat_symbol, retsam_symbol, hgss_symbol, score)
        #else:
        spreadsheet_data[hgss_symbol.full_addr] = SpreadsheetEntry(corresponding_plat_and_retsam_symbols, hgss_symbol, score)
        #for score, corresponding_plat_and_retsam_symbols in [:5]:
        #
        #else:
        #    print(f"Finding previous HGSS symbol to {hgss_symbol.name}!")
        #    hgss_prev_symbol_index = hgss_symbol_index - 1
        #    while True:
        #        hgss_prev_symbol = hgss_xmap.symbols_ordered_by_addr[hgss_prev_symbol_index]
        #        spreadsheet_entry = spreadsheet_data.get(hgss_prev_symbol.full_addr)
        #        if spreadsheet_entry is not None:
        #            break
        #        hgss_prev_symbol_index -= 1
        #
        #    print(f"Found previous hgss symbol: {hgss_prev_symbol.name}")
        #    retsam_prev_symbol = spreadsheet_entry.retsam_symbol
        #    print(f"Corresponding previous retsam symbol: {retsam_prev_symbol.name}")
        #    closest_retsam_symbol_to_prev = None
        #    corresponding_plat_symbol_for_closest_retsam_symbol_to_prev = None
        #    best_retsam_symbol_diff = 9999999999
        #
        #    for corresponding_plat_and_retsam_symbol in corresponding_plat_and_retsam_symbols:
        #        print(f"corresponding_plat_and_retsam_symbol.retsam_symbol: {corresponding_plat_and_retsam_symbol.retsam_symbol}")
        #        print(f"corresponding_plat_and_retsam_symbol.plat_symbol: {corresponding_plat_and_retsam_symbol.plat_symbol}")
        #        possible_retsam_symbol = corresponding_plat_and_retsam_symbol.retsam_symbol
        #        if possible_retsam_symbol.full_addr.overlay != retsam_prev_symbol.full_addr.overlay:
        #            continue
        #
        #        current_retsam_symbol_diff = possible_retsam_symbol.full_addr.addr - retsam_prev_symbol.full_addr.addr
        #        if current_retsam_symbol_diff > 0 and current_retsam_symbol_diff < best_retsam_symbol_diff:
        #            best_retsam_symbol_diff = current_retsam_symbol_diff
        #            closest_retsam_symbol_to_prev = possible_retsam_symbol
        #            corresponding_plat_symbol_for_closest_retsam_symbol_to_prev = corresponding_plat_and_retsam_symbol.plat_symbol
        #
        #    if closest_retsam_symbol_to_prev is None:
        #        raise RuntimeError()
        #
        #    retsam_symbol = closest_retsam_symbol_to_prev
        #    plat_symbol = corresponding_plat_symbol_for_closest_retsam_symbol_to_prev
        #
        #    spreadsheet_data[hgss_symbol.full_addr] = SpreadsheetEntry(plat_symbol, retsam_symbol, hgss_symbol)

    output = []
    # hgss addr, plat addr, hgss name, plat name, retsam name, score
    for hgss_symbol_full_addr, spreadsheet_entry in sorted(spreadsheet_data.items(), key=lambda x: x[0]):
        for i, plat_and_retsam_symbol in enumerate(sorted(spreadsheet_entry.plat_and_retsam_symbols, key=lambda x: x.retsam_symbol.full_addr)):
            cur_output = [""] * 6
            if i == 0:
                cur_output[0] = f"'{hgss_symbol_full_addr}"
                cur_output[2] = spreadsheet_entry.hgss_symbol.name
                cur_output[4] = str(spreadsheet_entry.score)
            else:
                cur_output[4] = "X"

            if plat_and_retsam_symbol.plat_symbol is not None:
                cur_output[1] = f"'{plat_and_retsam_symbol.plat_symbol.full_addr}"
                cur_output[3] = plat_and_retsam_symbol.plat_symbol.name

            cur_output[5] = plat_and_retsam_symbol.retsam_symbol.name

            output.append("\t".join(cur_output))
        output.append("")

    with open("gen_plat_hgss_func_spreadsheet_out.dump", "w+") as f:
        f.write("\n".join(output) + "\n")

    #asm_output = []
    #src_output = []
    #
    #for hgss_full_addr, corresponding_plat_and_retsam_symbols in sorted(hgss_to_retsam_zero_scores.items(), key=lambda x: x[0]):
    #    hgss_symbol = hgss_xmap.symbols_by_addr[hgss_full_addr]
    #    plat_and_retsam_symbol_names_and_addrs = []
    #
    #    for i, corresponding_plat_and_retsam_symbol in enumerate(corresponding_plat_and_retsam_symbols):
    #        plat_symbol = corresponding_plat_and_retsam_symbol.plat_symbol
    #        retsam_symbol = corresponding_plat_and_retsam_symbol.retsam_symbol
    #
    #        if plat_symbol is not None:
    #            plat_and_retsam_symbol_names_and_addrs.append(f"  {plat_symbol.name}, {retsam_symbol.name} [{retsam_symbol.full_addr}]\n")
    #        else:
    #            plat_and_retsam_symbol_names_and_addrs.append(f"  {retsam_symbol.name} ({retsam_symbol.filename})\n")
    #        if i >= 4:
    #            plat_and_retsam_symbol_names_and_addrs.append(f"  <{len(corresponding_plat_and_retsam_symbols) - 5} functions remaining>\n")
    #            break
    #
    #    cur_output = f"{hgss_symbol.name} ({hgss_full_addr}):\n{''.join(plat_and_retsam_symbol_names_and_addrs)}\n"
    #
    #    if function_filename_asm_or_src[hgss_symbol.filename] == "asm":
    #        asm_output.append(cur_output)
    #    else:
    #        src_output.append(cur_output)
    #
    #output = ""
    #output += f"== ASM functions (total {len(asm_output)}) ==\n{''.join(asm_output)}\n\n== src functions (total {len(src_output)}) ==\n{''.join(src_output)}\n"
    #
    #nonzero_output, nonzero_combined_output = nonzero_score_tracker.format_output(hgss_xmap, function_filename_asm_or_src)
    #both_output, both_combined_output = both_score_tracker.format_output(hgss_xmap, function_filename_asm_or_src, True)
    #
    #with open("hgss_retsam_matching_funcs.txt", "w+") as f:
    #    f.write(output)
    #
    #with open("hgss_retsam_similar_funcs.txt", "w+") as f:
    #    f.write(nonzero_output)
    #
    #with open("hgss_retsam_all_funcs.txt", "w+") as f:
    #    f.write(both_output)
    #
    #with open("hgss_retsam_all_funcs_combined.txt", "w+") as f:
    #    f.write(both_combined_output)

if __name__ == "__main__":
    main()
