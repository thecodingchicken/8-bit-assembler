import argparse
import os
import json
import re
import warnings
import glob
import datetime

# Instruction set with reads_ram and writes_ram for RAM access tracking
instruction_set = {
    "nop": {"opcode": "0000", "operand": "none", "reads_ram": False, "writes_ram": False},
    "lda": {"opcode": "0001", "operand": "address", "reads_ram": True, "writes_ram": False},
    "add": {"opcode": "0010", "operand": "address", "reads_ram": True, "writes_ram": False},
    "sub": {"opcode": "0011", "operand": "address", "reads_ram": True, "writes_ram": False},
    "sta": {"opcode": "0100", "operand": "address", "reads_ram": False, "writes_ram": True},
    "ldi": {"opcode": "0101", "operand": "value", "reads_ram": False, "writes_ram": False},
    "jmp": {"opcode": "0110", "operand": "address", "reads_ram": False, "writes_ram": False},
    "jc": {"opcode": "0111", "operand": "address", "reads_ram": False, "writes_ram": False},
    "jz": {"opcode": "1000", "operand": "address", "reads_ram": False, "writes_ram": False},
    "out": {"opcode": "1110", "operand": "none", "reads_ram": False, "writes_ram": False},
    "hlt": {"opcode": "1111", "operand": "none", "reads_ram": False, "writes_ram": False}
}

# Program storage
PROGRAMS_DIR = "programs"
PROGRAMS_DB = "programs.json"

def ensure_programs_dir():
    """Create programs directory and initialize programs.json if missing."""
    if not os.path.exists(PROGRAMS_DIR):
        os.makedirs(PROGRAMS_DIR)
    if not os.path.exists(PROGRAMS_DB):
        with open(PROGRAMS_DB, "w") as f:
            json.dump([], f)

def save_program(code, name=None):
    """Save program to programs/ and update programs.json."""
    ensure_programs_dir()
    if not name:
        name = f"program_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    filename = os.path.join(PROGRAMS_DIR, f"{name}.asm")
    with open(filename, "w") as f:
        f.write(code)
    with open(PROGRAMS_DB, "r") as f:
        programs = json.load(f)
    programs.append({"name": name, "filename": filename, "timestamp": datetime.datetime.now().isoformat()})
    with open(PROGRAMS_DB, "w") as f:
        json.dump(programs, f, indent=2)
    return name

def load_programs():
    """Load programs from programs.json."""
    ensure_programs_dir()
    with open(PROGRAMS_DB, "r") as f:
        return json.load(f)

def program_menu():
    """Display menu of previous programs and return selected code and name."""
    programs = load_programs()
    if not programs:
        print("No previous programs found.")
        return None, None
    print("\nPrevious Programs:")
    for i, prog in enumerate(programs):
        print(f"{i+1}. {prog['name']} ({prog['timestamp']})")
    print("0. Cancel")
    while True:
        try:
            choice = int(input("Select program (0 to cancel): "))
            if choice == 0:
                return None, None
            if 1 <= choice <= len(programs):
                with open(programs[choice-1]["filename"], "r") as f:
                    return f.read(), programs[choice-1]["name"]
            print(f"Invalid choice. Enter 0 to {len(programs)}.")
        except ValueError:
            print("Enter a number.")

def assemble(code, max_instructions=16, max_address=15, strict_ram_check=False, opcode_bits=4, operand_bits=4):
    """Assemble code for SAP computer. Returns machine_code, ram_init, instruction_lines, initialized_ram, symbol_table."""
    symbol_table = {}
    machine_code = []
    ram_init = {}  # Store RAM initial values (address: value)
    initialized_ram = set()  # Track initialized RAM addresses
    address = 0
    instruction_lines = []  # Store (binary, assembly_line) pairs

    # Validate bit widths
    if opcode_bits + operand_bits != 8:
        raise ValueError(f"Opcode bits ({opcode_bits}) + operand bits ({operand_bits}) must equal 8")

    # First pass: Build symbol table and check instruction count
    lines = code.splitlines()
    for line in lines:
        line = line.split(";")[0].strip()  # Remove comments for parsing
        full_line = line.split(";")[0].rstrip() + (" ;" + ";".join(line.split(";")[1:]) if ";" in line else "")
        if not line:
            continue
        if line.startswith("#ram"):
            parts = line.split()
            if len(parts) != 3:
                raise ValueError(f"Invalid #ram directive: {line}")
            try:
                ram_addr = int(parts[1], 0)
                ram_value = int(parts[2], 0)
                if ram_addr > max_address or ram_value > max_address:
                    raise ValueError(f"RAM address or value out of range: {line}")
                ram_init[ram_addr] = ram_value
                initialized_ram.add(ram_addr)
            except ValueError:
                raise ValueError(f"Invalid #ram address or value: {line}")
            continue
        if ":" in line:
            label = line.split(":")[0].strip()
            symbol_table[label] = format(address, f"0{max(4, operand_bits)}b")
            line = line.split(":")[1].strip()
            full_line = line.split(";")[0].rstrip() + (" ;" + ";".join(line.split(";")[1:]) if ";" in line else "")
        if line:
            address += 1
        if address > max_instructions:
            raise ValueError(f"Program exceeds maximum of {max_instructions} instructions")

    # Generate RAM initialization instructions
    for ram_addr, ram_value in ram_init.items():
        ldi_binary = f"{instruction_set['ldi']['opcode']}{format(ram_value, f'0{operand_bits}b')}"
        sta_binary = f"{instruction_set['sta']['opcode']}{format(ram_addr, f'0{operand_bits}b')}"
        machine_code.extend([ldi_binary, sta_binary])
        instruction_lines.extend([
            (ldi_binary, f"ldi {ram_value} ; Generated for #ram {ram_addr} {ram_value}"),
            (sta_binary, f"sta [{ram_addr}] ; Generated for #ram {ram_addr} {ram_value}")
        ])
        address += 2
        if address > max_instructions:
            raise ValueError(f"Program with RAM init exceeds {max_instructions} instructions")

    # Second pass: Generate machine code
    address = len(machine_code)
    for raw_line in lines:
        full_line = raw_line.rstrip()
        line = raw_line.split(";")[0].strip()
        if not line or line.startswith("#ram"):
            continue
        if ":" in line:
            line = line.split(":")[1].strip()
            full_line = line.split(";")[0].rstrip() + (" ;" + ";".join(raw_line.split(";")[1:]) if ";" in raw_line else "")
        if line:
            match = re.match(r"(\w+)\s*(?:\[(\w+)\]|(\w+))?", line, re.IGNORECASE)
            if not match:
                raise ValueError(f"Invalid syntax at line: {line}")
            instr, operand1, operand2 = match.groups()
            instr = instr.lower()
            if instr not in instruction_set:
                raise ValueError(f"Unknown instruction: {instr}")
            opcode = instruction_set[instr]["opcode"]
            operand_type = instruction_set[instr]["operand"]
            binary = opcode
            if operand_type == "none":
                binary += "0" * operand_bits
            elif operand_type == "address":
                operand = operand1 or operand2
                if operand in symbol_table:
                    binary += symbol_table[operand][-operand_bits:]
                else:
                    try:
                        addr = int(operand, 0)
                        if addr > max_address:
                            raise ValueError(f"Address out of range: {operand}")
                        binary += format(addr, f"0{operand_bits}b")
                        if instruction_set[instr]["reads_ram"] and addr not in initialized_ram:
                            message = (f"Instruction '{full_line}' at address {address} accesses "
                                      f"uninitialized RAM[{addr}]. Consider adding `#ram {addr} 0`.")
                            if strict_ram_check:
                                raise ValueError(message)
                            else:
                                warnings.warn(message)
                        if instruction_set[instr]["writes_ram"]:
                            initialized_ram.add(addr)
                    except ValueError:
                        raise ValueError(f"Invalid address or unresolved label: {operand}")
            elif operand_type == "value":
                try:
                    value = int(operand2, 0)
                    if value > max_address:
                        raise ValueError(f"Value out of range: {operand2}")
                    binary += format(value, f"0{operand_bits}b")
                except ValueError:
                    raise ValueError(f"Invalid value: {operand2}")
            machine_code.append(binary)
            instruction_lines.append((binary, full_line))
            address += 1
            if address > max_instructions:
                raise ValueError(f"Program exceeds {max_instructions} instructions")

    return machine_code, ram_init, instruction_lines, initialized_ram, symbol_table

def format_for_switches(binary):
    """Format binary instruction as switch settings (on/off)."""
    return ", ".join("on" if bit == "1" else "off" for bit in binary)

def print_listing(instruction_lines, show_switches=False, show_comments=True, symbol_table=None):
    """Print assembly listing with address, binary, hex, and optional switches/comments."""
    print("Program Listing:")
    for i, (binary, assembly_line) in enumerate(instruction_lines):
        if not isinstance(binary, str):
            raise TypeError(f"Non-string binary value at address {i}: {binary}")
        hex_val = f"0x{int(binary, 2):02X}"
        parts = assembly_line.split(";", 1)
        asm = parts[0].strip()
        comment = parts[1].strip() if len(parts) > 1 and show_comments else ""
        match = re.match(r"(\w+)\s*(?:\[(\w+)\]|(\w+))?", asm, re.IGNORECASE)
        if match:
            instr, operand1, operand2 = match.groups()
            instr = instr.lower()
            operand = operand1 or operand2
            if instr in ["lda", "add", "sub", "sta", "jmp", "jc", "jz"] and operand:
                if operand in symbol_table:
                    resolved_addr = int(symbol_table[operand], 2)
                    asm += f" ({resolved_addr})"
                else:
                    try:
                        resolved_addr = int(operand, 0)
                        asm += f" ({resolved_addr})"
                    except ValueError:
                        pass
        line = f"Addr {format(i, '04b')} ( {i:5d} ) : {binary} ({hex_val}) | {asm:<23}"
        if show_switches:
            switch_settings = format_for_switches(binary)
            line += f" Switches: {switch_settings}"
        if show_comments and comment:
            line += f" {comment}"
        print(line)

def to_listing_file(instruction_lines, filename="program.lst", show_switches=False, show_comments=True, symbol_table=None):
    """Write assembly listing to file."""
    with open(filename, "w") as f:
        f.write("Program Listing:\n")
        for i, (binary, assembly_line) in enumerate(instruction_lines):
            if not isinstance(binary, str):
                raise TypeError(f"Non-string binary value at address {i}: {binary}")
            hex_val = f"0x{int(binary, 2):02X}"
            parts = assembly_line.split(";", 1)
            asm = parts[0].strip()
            comment = parts[1].strip() if len(parts) > 1 and show_comments else ""
            match = re.match(r"(\w+)\s*(?:\[(\w+)\]|(\w+))?", asm, re.IGNORECASE)
            if match:
                instr, operand1, operand2 = match.groups()
                instr = instr.lower()
                operand = operand1 or operand2
                if instr in ["lda", "add", "sub", "sta", "jmp", "jc", "jz"] and operand:
                    if operand in symbol_table:
                        resolved_addr = int(symbol_table[operand], 2)
                        asm += f" ({resolved_addr})"
                    else:
                        try:
                            resolved_addr = int(operand, 0)
                            asm += f" ({resolved_addr})"
                        except ValueError:
                            pass
            line = f"Addr {format(i, '04b')} ( {i:5d} ) : {binary} ({hex_val}) | {asm:<23}"
            if show_switches:
                switch_settings = format_for_switches(binary)
                line += f" Switches: {switch_settings}"
            if show_comments and comment:
                line += f" {comment}"
            f.write(line + "\n")

def to_hex_file(machine_code, filename="program.hex"):
    """Write machine code to hex file for EEPROM."""
    with open(filename, "w") as f:
        for binary in machine_code:
            if not isinstance(binary, str):
                raise TypeError(f"Non-string binary value: {binary}")
            f.write(f"{int(binary, 2):02X}\n")

def live_mode():
    """Interactive mode to enter and assemble instructions."""
    print("Entering Live Mode. Type instructions (one per line). Enter empty line to assemble.")
    print("Use Ctrl+C to exit.")
    instructions = []
    while True:
        try:
            line = input("> ").strip()
            if not line:
                if not instructions:
                    print("No instructions entered. Continuing...")
                    continue
                code = "\n".join(instructions)
                show_switches = input("Show switch settings? (y/n): ").lower() == 'y'
                show_comments = input("Show comments? (y/n): ").lower() == 'y'
                generate_hex = input("Generate hex file? (y/n): ").lower() == 'y'
                generate_listing = input("Generate listing file? (y/n): ").lower() == 'y'
                save = input("Save program to history? (y/n): ").lower() == 'y'
                prog_name = None
                if save:
                    prog_name = input("Program name (leave blank for auto-generated): ").strip() or None
                try:
                    machine_code, ram_init, instruction_lines, initialized_ram, symbol_table = assemble(
                        code, strict_ram_check=False
                    )
                    print_listing(
                        instruction_lines,
                        show_switches=show_switches,
                        show_comments=show_comments,
                        symbol_table=symbol_table
                    )
                    if generate_listing:
                        to_listing_file(
                            instruction_lines,
                            show_switches=show_switches,
                            show_comments=show_comments,
                            symbol_table=symbol_table
                        )
                        print("\nListing file 'program.lst' generated.")
                    if generate_hex:
                        to_hex_file(machine_code)
                        print("\nHex file 'program.hex' generated.")
                    print("\nInitial RAM Contents:")
                    if ram_init:
                        for addr, value in sorted(ram_init.items()):
                            print(f"RAM[{format(addr, '04b')} ( {addr:5d} )] = {value} ({hex(value)})")
                    else:
                        print("No RAM initialization specified.")
                    print(f"\nTotal Program Bytes: {len(machine_code)}")
                    print(f"Total RAM Usage: {len(initialized_ram)} bytes")
                    if save:
                        name = save_program(code, prog_name)
                        print(f"Program saved as {name}.")
                except Exception as e:
                    print(f"Assembly error: {e}")
                instructions = []
                print("\nEnter next program or empty line to assemble again.")
            else:
                instructions.append(line)
        except KeyboardInterrupt:
            print("\nExiting Live Mode.")
            break

def main():
    parser = argparse.ArgumentParser(description="SAP Assembler for 8-bit breadboard computer")
    parser.add_argument("input_file", nargs="?", help="Input assembly file (.asm), optional in live or menu mode")
    parser.add_argument("-s", "--switches", action="store_true", help="Show switch settings in listing")
    parser.add_argument("-c", "--comments", action="store_true", default=True, help="Show comments in listing")
    parser.add_argument("-b", "--no-hex", action="store_false", dest="generate_hex", help="Disable hex file generation")
    parser.add_argument("-a", "--no-source-code", action="store_false", dest="generate_listing", help="Disable listing file generation")
    parser.add_argument("-l", "--live", action="store_true", help="Run in interactive live mode")
    parser.add_argument("-m", "--menu", action="store_true", help="Show menu of previous programs")
    args = parser.parse_args()

    if args.live and args.menu:
        parser.error("Cannot use --live and --menu together")

    if args.menu:
        code, prog_name = program_menu()
        if not code:
            print("No program selected. Exiting.")
            return
    elif args.live:
        live_mode()
        return
    elif not args.input_file:
        parser.error("input_file required unless --live or --menu is specified")
    else:
        if not os.path.exists(args.input_file):
            print(f"Error: Input file '{args.input_file}' not found.")
            return
        with open(args.input_file, "r") as f:
            code = f.read()
        prog_name = os.path.splitext(os.path.basename(args.input_file))[0]

    try:
        machine_code, ram_init, instruction_lines, initialized_ram, symbol_table = assemble(
            code, strict_ram_check=False
        )
        print_listing(
            instruction_lines,
            show_switches=args.switches,
            show_comments=args.comments,
            symbol_table=symbol_table
        )
        if args.generate_listing:
            to_listing_file(
                instruction_lines,
                show_switches=args.switches,
                show_comments=args.comments,
                symbol_table=symbol_table
            )
            print("\nListing file 'program.lst' generated.")
        if args.generate_hex:
            to_hex_file(machine_code)
            print("\nHex file 'program.hex' generated.")
        print("\nInitial RAM Contents:")
        if ram_init:
            for addr, value in sorted(ram_init.items()):
                print(f"RAM[{format(addr, '04b')} ( {addr:5d} )] = {value} ({hex(value)})")
        else:
            print("No RAM initialization specified.")
        print(f"\nTotal Program Bytes: {len(machine_code)}")
        print(f"Total RAM Usage: {len(initialized_ram)} bytes")
        save_program(code, prog_name)
        print(f"Program saved as {prog_name}.")
    except Exception as e:
        print(f"Assembly error: {e}")

if __name__ == "__main__":
    main()