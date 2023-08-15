
def read_in_key_integer_file(filename):
    with open(filename, "r") as f:
        #lines = f.read.splitlines()
        dict_obj = {(split_line := line.rstrip("\n").split("|", maxsplit=1))[0]: int(split_line[1]) for line in f}
        return dict_obj

def write_key_integer_file(filename, data):
    output = "".join([f"{key}|{value}\n" for key, value in data.items()])
    with open(filename, "w+") as f:
        f.write(output)
