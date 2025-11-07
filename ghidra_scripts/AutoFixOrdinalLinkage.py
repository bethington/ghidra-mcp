#Auto-Fix Ordinal Linkage for External Function Pointers
#
#Automatically fixes external function pointers by looking up ordinal names in DLL export mappings
#and renaming symbols to their real function names. Processes all external locations in all imported DLLs.
#
#@author Ben Ethington
#@category Diablo 2.Ordinal Linkage
#@description Automatically fixes external function pointers by mapping ordinals to real function names from DLL exports
#@keybinding
#@menupath Diablo II.Ordinal Linkage.Auto Fix Ordinal Linkage

from ghidra.program.model.symbol import SourceType, ExternalLocation
from ghidra.program.model.listing import Function
from ghidra.program.model.address import GenericAddress
import os
import re

def load_dll_mappings(dll_exports_dir):
    """
    Load all DLL export mappings from text files.

    Returns a dictionary: {
        "D2COMMON.DLL": {
            "Ordinal_10078": {"name": "FindNearestValidRoomWrapper", "address": "6fd9d870"},
            "Ordinal_10591": {"name": "InitializeUnitStructure", "address": "6fd62030"},
            ...
        }
    }
    """
    mappings = {}

    if not os.path.exists(dll_exports_dir):
        print("[ERROR] DLL exports directory not found: {}".format(dll_exports_dir))
        return mappings

    # Find all .txt files in the directory
    txt_files = []
    for filename in os.listdir(dll_exports_dir):
        if filename.endswith('.txt'):
            txt_files.append(filename)

    print("Found {} DLL export mapping files".format(len(txt_files)))
    print("")

    for txt_file in txt_files:
        filepath = os.path.join(dll_exports_dir, txt_file)
        dll_name = txt_file.replace('.txt', '.dll').upper()

        if dll_name not in mappings:
            mappings[dll_name] = {}

        print("Loading mappings from: {}".format(txt_file))

        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or '->' not in line:
                    continue

                # Parse format: DLLNAME::ExportName@paramSize@address->GhidraFunctionName
                # or: DLLNAME::Ordinal_XXXXX@paramSize@address->ActualFunctionName
                try:
                    # Split by '->' to separate export from Ghidra name
                    parts = line.split('->')
                    if len(parts) != 2:
                        continue

                    export_part = parts[0]  # DLLNAME::ExportName@paramSize@address
                    ghidra_name = parts[1]  # ActualFunctionName

                    # Extract DLL name, export name, and address
                    # Format: DLLNAME::Name@param@address
                    if '::' not in export_part:
                        continue

                    dll_part, rest = export_part.split('::', 1)

                    # Split by '@' to get name and address parts
                    at_parts = rest.split('@')
                    if len(at_parts) < 2:
                        continue

                    export_name = at_parts[0]  # e.g., "Ordinal_10078" or "_BinkBufferBlit"
                    address = at_parts[-1]     # Last part is always the address

                    # Store mapping
                    if export_name.startswith('Ordinal_'):
                        mappings[dll_name][export_name] = {
                            'name': ghidra_name.strip(),
                            'address': address.strip()
                        }

                except Exception as e:
                    print("  [WARN] Error parsing line: {} - {}".format(line, str(e)))
                    continue

        ordinal_count = len([k for k in mappings[dll_name].keys() if k.startswith('Ordinal_')])
        print("  Loaded {} ordinal mappings".format(ordinal_count))

    print("")
    return mappings


def find_all_external_ordinal_pointers():
    """
    Find all external function pointers that reference ordinals.

    Returns a list of dictionaries with pointer information.
    """
    pointers = []

    # Get the external program (e.g., D2COMMON.DLL)
    external_manager = currentProgram.getExternalManager()
    external_names = external_manager.getExternalLibraryNames()

    print("Scanning external libraries for ordinal pointers...")
    print("")

    for lib_name in external_names:
        print("Processing library: {}".format(lib_name))

        # Get all external locations for this library
        external_locations = external_manager.getExternalLocations(lib_name)

        ordinal_count = 0
        for ext_loc in external_locations:
            label = ext_loc.getLabel()

            # Check if this is an ordinal reference
            if label and label.startswith('Ordinal_'):
                address = ext_loc.getExternalSpaceAddress()

                pointers.append({
                    'dll': lib_name.upper(),
                    'ordinal_name': label,
                    'external_location': ext_loc,
                    'external_address': address
                })
                ordinal_count += 1

        print("  Found {} ordinal pointers".format(ordinal_count))

    print("")
    print("Total ordinal pointers found: {}".format(len(pointers)))
    print("")
    return pointers


def fix_ordinal_pointer(pointer_info, mapping):
    """
    Fix a single ordinal pointer by updating its external location.

    Args:
        pointer_info: Dictionary with pointer information
        mapping: Dictionary with new name and address

    Returns:
        True if successful, False otherwise
    """
    from ghidra.program.model.symbol import SourceType

    dll = pointer_info['dll']
    ordinal_name = pointer_info['ordinal_name']
    ext_loc = pointer_info['external_location']

    new_name = mapping['name']
    new_address = mapping['address']

    try:
        # Get the symbol for this external location
        symbol = ext_loc.getSymbol()

        if symbol:
            # Rename the symbol using setName()
            symbol.setName(new_name, SourceType.USER_DEFINED)
            return True
        else:
            print("    [WARN] No symbol found for {}".format(ordinal_name))
            return False

    except Exception as e:
        print("    [ERROR] Failed to fix {}: {}".format(ordinal_name, str(e)))
        return False


def log_and_print(log_file, message):
    """Write to both console and log file"""
    print(message)
    with open(log_file, 'a') as f:
        f.write(message + "\n")


def main():
    # Create log file with timestamp
    import time
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    log_file = r"C:\Users\benam\source\mcp\ghidra-mcp\ordinal_fix_log_{}.txt".format(timestamp)

    # Initialize log file
    with open(log_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("AUTO-FIX ORDINAL LINKAGE\n")
        f.write("Program: {}\n".format(currentProgram.getName()))
        f.write("Timestamp: {}\n".format(time.strftime("%Y-%m-%d %H:%M:%S")))
        f.write("=" * 80 + "\n\n")

    log_and_print(log_file, "=" * 80)
    log_and_print(log_file, "AUTO-FIX ORDINAL LINKAGE")
    log_and_print(log_file, "=" * 80)
    log_and_print(log_file, "")
    log_and_print(log_file, "Program: {}".format(currentProgram.getName()))
    log_and_print(log_file, "Log file: {}".format(log_file))
    log_and_print(log_file, "")

    # Configuration
    dll_exports_dir = r"C:\Users\benam\source\mcp\ghidra-mcp\dll_exports"

    # Step 1: Load DLL export mappings
    log_and_print(log_file, "[1/4] Loading DLL export mappings...")
    log_and_print(log_file, "")
    mappings = load_dll_mappings(dll_exports_dir)

    if not mappings:
        log_and_print(log_file, "[ERROR] No DLL mappings loaded. Aborting.")
        return

    total_mappings = sum(len(v) for v in mappings.values())
    log_and_print(log_file, "Loaded {} total ordinal mappings from {} DLLs".format(total_mappings, len(mappings)))
    log_and_print(log_file, "")

    # Step 2: Find all external ordinal pointers
    log_and_print(log_file, "[2/4] Finding all external ordinal pointers...")
    log_and_print(log_file, "")
    pointers = find_all_external_ordinal_pointers()

    if not pointers:
        log_and_print(log_file, "[INFO] No ordinal pointers found. Nothing to fix.")
        return

    # Step 3: Match pointers with mappings and fix them
    log_and_print(log_file, "[3/4] Fixing ordinal pointers...")
    log_and_print(log_file, "")

    success_count = 0
    fail_count = 0
    missing_count = 0
    fixes_by_dll = {}

    for pointer in pointers:
        dll = pointer['dll']
        ordinal_name = pointer['ordinal_name']

        # Check if we have a mapping for this DLL and ordinal
        if dll not in mappings:
            log_and_print(log_file, "  [SKIP] {} - No mappings available for {}".format(ordinal_name, dll))
            missing_count += 1
            continue

        if ordinal_name not in mappings[dll]:
            log_and_print(log_file, "  [SKIP] {} - No mapping found in {}".format(ordinal_name, dll))
            missing_count += 1
            continue

        # Get the mapping
        mapping = mappings[dll][ordinal_name]
        new_name = mapping['name']
        new_address = mapping['address']

        # Track fixes by DLL
        if dll not in fixes_by_dll:
            fixes_by_dll[dll] = []

        log_and_print(log_file, "  Fixing: {} -> {} @ {}".format(ordinal_name, new_name, new_address))

        # Fix the pointer
        if fix_ordinal_pointer(pointer, mapping):
            success_count += 1
            fixes_by_dll[dll].append("{} -> {}".format(ordinal_name, new_name))
        else:
            fail_count += 1

    # Step 4: Summary
    log_and_print(log_file, "")
    log_and_print(log_file, "=" * 80)
    log_and_print(log_file, "[4/4] SUMMARY")
    log_and_print(log_file, "=" * 80)
    log_and_print(log_file, "Total ordinal pointers found: {}".format(len(pointers)))
    log_and_print(log_file, "Successfully fixed: {}".format(success_count))
    log_and_print(log_file, "Failed to fix: {}".format(fail_count))
    log_and_print(log_file, "No mapping available: {}".format(missing_count))
    log_and_print(log_file, "")

    # Detailed breakdown by DLL
    if fixes_by_dll:
        log_and_print(log_file, "FIXES BY DLL:")
        log_and_print(log_file, "")
        for dll, fixes in sorted(fixes_by_dll.items()):
            log_and_print(log_file, "  {} ({} fixed):".format(dll, len(fixes)))
            for fix in fixes[:10]:  # Show first 10
                log_and_print(log_file, "    - {}".format(fix))
            if len(fixes) > 10:
                log_and_print(log_file, "    ... and {} more".format(len(fixes) - 10))
            log_and_print(log_file, "")

    if success_count > 0:
        log_and_print(log_file, "[SUCCESS] Fixed {} ordinal pointers!".format(success_count))

    log_and_print(log_file, "=" * 80)
    log_and_print(log_file, "")
    log_and_print(log_file, "Log file saved to: {}".format(log_file))
    log_and_print(log_file, "")


# Run the script
if __name__ == '__main__':
    main()
