# Copyright (c) 2022 luckytyphlosion
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import re

overlay_regex = re.compile(r"^#>([0-9a-fA-F]{8})\s+SDK_OVERLAY\.[^\.]+\.ID \(linker command file\)$")
overlay_start_regex = re.compile(r"^#>([0-9a-fA-F]{8})\s+SDK_OVERLAY\.[^\.]+\.START \(linker command file\)$")
overlay_text_end_regex = re.compile(r"^#>([0-9a-fA-F]{8})\s+SDK_OVERLAY\.[^\.]+\.TEXT_END \(linker command file\)$")
overlay_end_regex = re.compile(r"^#>([0-9a-fA-F]{8})\s+SDK_OVERLAY\.[^\.]+\.BSS_END \(linker command file\)$")
filename_regex = re.compile(r"^\s*\(([^\)]+)\)")

class OvAddr:
    __slots__ = ("overlay", "addr")

    def __init__(self, overlay, addr):
        self.overlay = overlay
        self.addr = addr

    def __key(self):
        return (self.overlay, self.addr)

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        if isinstance(other, OvAddr):
            return self.__key() == other.__key()
        return NotImplemented

    def __repr__(self):
        return f"{self.overlay:02x}:{self.addr:07x}"

    def __lt__(self, other):
        if isinstance(other, OvAddr):
            if self.overlay < other.overlay:
                return True
            elif self.overlay > other.overlay:
                return False
            else:
                return self.addr < other.addr
        return NotImplemented

    def __eq__(self, other):
        if isinstance(other, OvAddr):
            return self.overlay == other.overlay and self.addr == other.addr
        return NotImplemented

    def __le__(self, other):
        if isinstance(other, OvAddr):
            if self.overlay < other.overlay:
                return True
            elif self.overlay > other.overlay:
                return False
            else:
                return self.addr <= other.addr

        raise NotImplemented

    def serialize(self):
        return {"overlay": self.overlay, "addr": self.addr}

    @classmethod
    def parse(cls, full_addr_str):
        overlay_str, addr_str = full_addr_str.split(":")
        return cls(int(overlay_str, 16), int(addr_str, 16))

    @classmethod
    def unserialize(cls, serialized_input):
        return cls(serialized_input["overlay"], serialized_input["addr"])

class Symbol:
    __slots__ = ("name", "full_addr", "section", "size", "filename", "archive")

    def __init__(self, name, full_addr, section, size, filename, archive):
        self.name = name
        self.full_addr = full_addr
        self.section = section
        self.size = size
        self.filename = filename
        self.archive = archive

    def __repr__(self):
        return f"Symbol(name={self.name}, full_addr={self.full_addr}, section={self.section}, size={self.size}, filename={self.filename}, archive={self.archive}"

    def serialize(self):
        return {
            "name": self.name,
            "full_addr": self.full_addr.serialize(),
            "section": self.section,
            "size": self.size,
            "filename": self.filename,
            "archive": self.archive
        }

    @classmethod
    def unserialize(cls, serialized_input):
        return cls(
            serialized_input["name"],
            OvAddr.unserialize(serialized_input["full_addr"]),
            serialized_input["section"],
            serialized_input["size"],
            serialized_input["filename"],
            serialized_input["archive"]
        )

class XMap:
    __slots__ = ("filename", "start_section", "symbols_by_addr", "symbols_by_name", "overlay_start_addrs", "overlay_end_addrs", "overlay_text_end_addrs", "symbols_by_filename", "archive_filenames_by_archive", "filename_archives_by_filename")

    def __init__(self, filename, start_section):
        self.filename = filename
        self.start_section = start_section
        self.symbols_by_addr = {}
        self.symbols_by_name = {}
        self.overlay_start_addrs = {}
        self.overlay_end_addrs = {}
        self.overlay_text_end_addrs = {}
        self.symbols_by_filename = {}
        self.archive_filenames_by_archive = {}
        self.filename_archives_by_filename = {}
        self.read_xmap()

    def read_xmap(self):
        lines = []
        start_section_line = f"# {self.start_section}\n"

        with open(self.filename, "r") as f:
            for line in f:
                if line == start_section_line:
                    break

            cur_overlay = -1
            for line in f:
                line = line.strip()
                if line == "":
                    continue
                elif line.endswith("Exception Table Index	()"):
                    continue

                if line[0] == '#':
                    match_obj = overlay_regex.match(line)
                    if match_obj:
                        cur_overlay = int(match_obj.group(1), 16)
                    elif (match_obj := overlay_start_regex.match(line)):
                        self.overlay_start_addrs[cur_overlay] = int(match_obj.group(1), 16)
                    elif (match_obj := overlay_end_regex.match(line)):
                        self.overlay_end_addrs[cur_overlay] = int(match_obj.group(1), 16)
                    elif (match_obj := overlay_text_end_regex.match(line)):
                        self.overlay_text_end_addrs[cur_overlay] = int(match_obj.group(1), 16)                        
                    elif line.startswith("# Memory map:"):
                        break
                else:
                    split_line = line.split(maxsplit=4)
                    name = split_line[3]
                    if name in ("$d", "$t", "$a", "$b") or "." in name[0]:
                        continue

                    addr = int(split_line[0], 16)
                    if "@" in name[0]:
                        name = f"FunctionRODATA_{addr:07x}"
                    size = int(split_line[1], 16)
                    section = split_line[2]
                    match_obj = filename_regex.match(split_line[4])
                    if match_obj and ":" not in name and "(" not in name:
                        filename_archive = match_obj.group(1).strip().split()
                        if len(filename_archive) == 1:
                            filename = filename_archive[0]
                            archive = None
                        else:
                            filename = filename_archive[1]
                            archive = filename_archive[0]
                    else:                        
                        #print(f"c++ symbol found! line: {line}")
                        filename = "cpp_todo"
                        archive = None
                        if cur_overlay == -1:
                            name = f"cpp_{addr:07X}"
                        else:
                            name = f"NitroMain // cpp_ov{cur_overlay}_{addr:07X}"

                    full_addr = OvAddr(cur_overlay, addr)
                    symbol = Symbol(name, full_addr, section, size, filename, archive)
                    if full_addr not in self.symbols_by_addr:
                        #if symbol.full_addr < self.symbol_addr_cutoff:
                        self.symbols_by_addr[full_addr] = symbol
                    else:
                        pass
                        #print(f"Assumption failed! Duplicate full addr found! value: {full_addr}, original: {self.symbols_by_addr[full_addr].name}, duplicate: {symbol.name}")

                    if symbol.name not in self.symbols_by_name:
                        self.symbols_by_name[symbol.name] = [symbol]
                    else:
                        self.symbols_by_name[symbol.name].append(symbol)

                    if symbol.archive is None and symbol.filename != "cpp_todo":
                        if symbol.filename not in self.symbols_by_filename:                        
                            self.symbols_by_filename[symbol.filename] = [symbol]
                        else:
                            self.symbols_by_filename[symbol.filename].append(symbol)

        self.symbols_by_addr = {k: v for k, v in sorted(self.symbols_by_addr.items(), key=lambda item: item[1].full_addr)}

    def gen_archive_filename_info(self):
        for symbols in self.symbols_by_name.values():
            for symbol in symbols:
                if symbol.archive is not None:
                    object_filenames = self.archive_filenames_by_archive.get(symbol.archive)
                    if object_filenames is None:
                        object_filenames = set()
                        self.archive_filenames_by_archive[symbol.archive] = object_filenames

                    object_filenames.add(symbol.filename)

                    archive_filenames = self.filename_archives_by_filename.get(symbol.filename)
                    if archive_filenames is None:
                        archive_filenames = set()
                        self.filename_archives_by_filename[symbol.filename] = archive_filenames

                    archive_filenames.add(symbol.archive)

    def print_warn_info(self):
        for object_filename, archive_filenames in self.filename_archives_by_filename.items():
            if len(archive_filenames) > 1:
                print(f"Filename {object_filename} appears in multiple archives {archive_filenames}!")

        #filenames = {}
        #for symbol in self.symbols_by_addr.values():
        #    filenames[symbol.filename] = True
        #
        #output = ""
        #for filename in filenames:
        #    output += f"{filename}\n"
        #
        #with open("diamond_out.txt", "w+") as f:
        #    f.write(output)

def main():
    XMap("main.nef.xMAP", ".main")
    #XMap("pokediamond.us.xMAP", ".arm9")

if __name__ == "__main__":
    main()
