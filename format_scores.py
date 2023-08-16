import key_int
from xmap import XMap
from diff import DecomposedFunction, DecompDB, Line, Config, ARM32_SETTINGS, TableData, PlainFormatter, DiffMode, TableLine, Text
import diff as asm_differ
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

MAX_NONZERO_SCORE_ENTRIES = 5

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

def diff_line_to_table_line(line):
    cells = [
        (line[0].base or Text(), line[0].line1),
    ]
    for ol in line[1:]:
        cells.append((ol.fmt2, ol.line2))

    return TableLine(
        key=line[0].key2,
        is_data_ref=line[0].is_data_ref,
        cells=tuple(cells),
    )

def create_diff2_func():
    hgss_db = load_pickle_from_filename("pokeheartgold_decomposed_function_database.pickle")
    retsam_db = load_pickle_from_filename("retsam_decomposed_function_database.pickle")
    hgss_xmap = XMap("../pokeheartgold/build/heartgold.us/main.elf.xMAP", ".main")
    retsam_xmap = XMap("../retsam_00jupc/bin/ARM9-TS/Rom/main.nef.xMAP", ".main")
    hgss_decomposed_functions_by_key = DecompDB.create_decomposed_functions_by_key(hgss_db)
    retsam_decomposed_functions_by_key = DecompDB.create_decomposed_functions_by_key(retsam_db)

    formatter = PlainFormatter(column_width=40)

    config = Config(
        arch=ARM32_SETTINGS,
        # Build/objdump options
        diff_obj=False,
        objfile=None,
        make=False,
        source_old_binutils=False,
        diff_section=".text",
        inlines=False,
        max_function_size_lines=1024,
        max_function_size_bytes=1024 * 4,
        # Display options
        formatter=formatter,
        diff_mode=DiffMode.NORMAL,
        base_shift=0,
        skip_lines=0,
        compress=False,
        show_rodata_refs=True,
        show_branches=False,
        show_line_numbers=False,
        show_source=False,
        stop_at_ret=False,
        ignore_large_imms=False,
        ignore_addr_diffs=True,
        algorithm="levenshtein",
        reg_categories={},
        score_only=False,
        line_nums_start_at_zero=True
    )

    def diff2(hgss_func, retsam_func):
        hgss_symbol = hgss_xmap.symbols_by_name[hgss_func][0]
        retsam_symbol = retsam_xmap.symbols_by_name[retsam_func][0]

        hgss_key = f"p.{hgss_symbol.full_addr}"
        retsam_key = f"r.{retsam_symbol.full_addr}"

        hgss_decomposed_function = hgss_decomposed_functions_by_key[hgss_key]
        retsam_decomposed_function = retsam_decomposed_functions_by_key[retsam_key]

        #hgss_contents = hgss_decomposed_function.
        #print(f"== hgss ==\n{hgss_contents}\n\n== retsam ==\n{retsam_contents}")
        diff_output = asm_differ.do_diff(hgss_decomposed_function.processed_lines, retsam_decomposed_function.processed_lines, config)

        table_data = TableData(
            headers=[],
            current_score=0,
            max_score=0,
            previous_score=0,
            lines=[diff_line_to_table_line((line, line)) for line in diff_output.lines]
        )
        output = ""
        output += f"score: {diff_output.score}\n"
        output += config.formatter.table(table_data)
        
        print(output)

    #def diff3(hgss_func, retsam_func):
    #    hgss_symbol = hgss_xmap.symbols_by_name[hgss_func][0]
    #    retsam_symbol = retsam_xmap.symbols_by_name[retsam_func][0]
    #
    #    hgss_key = f"p.{hgss_symbol.full_addr}"
    #    retsam_key = f"r.{retsam_symbol.full_addr}"
    #
    #    hgss_decomposed_function = hgss_decomposed_functions_by_key[hgss_key]
    #    retsam_decomposed_function = retsam_decomposed_functions_by_key[retsam_key]
    #
    #    print(f"== hgss ==\n{hgss_decomposed_function.processed_lines}\n\n== retsam ==\n{retsam_contents}")
    return diff2

def main():
    print("Reading in files!")
    scores = key_int.read_in_key_integer_file("retsam_pokeheartgold_scores.dump")
    hgss_db = load_pickle_from_filename("pokeheartgold_decomposed_function_database.pickle")
    retsam_db = load_pickle_from_filename("retsam_decomposed_function_database.pickle")

    hgss_xmap = XMap("../pokeheartgold/build/heartgold.us/main.elf.xMAP", ".main")
    retsam_xmap = XMap("../retsam_00jupc/bin/ARM9-TS/Rom/main.nef.xMAP", ".main")
    platinum_xmap = XMap("../pokeplatinum-new/build/main.nef.xMAP", ".main")

    hgss_decomposed_functions_by_key = DecompDB.create_decomposed_functions_by_key(hgss_db)
    retsam_decomposed_functions_by_key = DecompDB.create_decomposed_functions_by_key(retsam_db)

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

    for i, (score_function_names, score) in enumerate(scores.items()):
        hgss_function_key, retsam_function_key = score_function_names.split(";", maxsplit=1)
        hgss_symbol = hgss_decomposed_functions_by_key[hgss_function_key].symbol
        if hgss_symbol.full_addr.addr == -1:
            #print(f"Skipped deadstripped hgss function {hgss_symbol.name}!")
            continue

        retsam_symbol = retsam_decomposed_functions_by_key[retsam_function_key].symbol
        if retsam_symbol.full_addr.addr != -1:
            plat_symbol = platinum_xmap.symbols_by_addr.get(retsam_symbol.full_addr)
        else:
            plat_symbol = None

        if score == 0:
            hgss_to_retsam_zero_scores[hgss_symbol.full_addr].append(PlatAndRetsamSymbol(plat_symbol, retsam_symbol))
        else:
            nonzero_score_tracker.add(hgss_symbol, plat_symbol, retsam_symbol, score)

        if i & 0xffff == 0:
            print(f"i: {i}")

        if i > 10000000:
            break

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

    nonzero_asm_output = []
    nonzero_src_output = []

    for hgss_full_addr, scores_for_hgss_symbol in nonzero_score_tracker.score_table.items():
        hgss_symbol = hgss_xmap.symbols_by_addr[hgss_full_addr]
        cur_output = ""
        cur_output += f"{hgss_symbol.name} ({hgss_full_addr}):\n"

        for score, corresponding_plat_and_retsam_symbols in sorted(scores_for_hgss_symbol.items(), key=lambda x: x[0]):
            cur_output += f"  Score: {score}\n"

            plat_and_retsam_symbol_names_and_addrs = []

            for i, corresponding_plat_and_retsam_symbol in enumerate(corresponding_plat_and_retsam_symbols):
                plat_symbol = corresponding_plat_and_retsam_symbol.plat_symbol
                retsam_symbol = corresponding_plat_and_retsam_symbol.retsam_symbol
    
                if plat_symbol is not None:
                    plat_and_retsam_symbol_names_and_addrs.append(f"    {plat_symbol.name}, {retsam_symbol.name} [{retsam_symbol.full_addr}]\n")
                else:
                    plat_and_retsam_symbol_names_and_addrs.append(f"    {retsam_symbol.name}\n")
                if i >= 4:
                    plat_and_retsam_symbol_names_and_addrs.append(f"    <{len(corresponding_plat_and_retsam_symbols) - 5} functions remaining>\n")
                    break

            cur_output += f"{''.join(plat_and_retsam_symbol_names_and_addrs)}\n"

        if function_filename_asm_or_src[hgss_symbol.filename] == "asm":
            nonzero_asm_output.append(cur_output)
        else:
            nonzero_src_output.append(cur_output)

    nonzero_output = ""
    nonzero_output += f"== ASM functions (total {len(nonzero_asm_output)}) ==\n{''.join(nonzero_asm_output)}\n\n== src functions (total {len(nonzero_src_output)}) ==\n{''.join(nonzero_src_output)}\n"

    with open("hgss_retsam_matching_funcs.txt", "w+") as f:
        f.write("".join(output))

    with open("hgss_retsam_similar_funcs.txt", "w+") as f:
        f.write("".join(nonzero_output))

if __name__ == "__main__":
    main()
