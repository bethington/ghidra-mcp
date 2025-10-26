#Export function addresses and parameters info
#This script exports all Diablo 2 functions to JSON format with complete metadata including
#function names, addresses, parameter counts, return types, disassembly snippets (first 5 bytes),
#jumpback addresses for hooking, and detailed parameter information (name, type, location, size).
#Outputs both formatted (game.json) and minified (game_minify.json) versions.
#Useful for creating function hooking frameworks or external analysis tools.
#
#@author dzik
#@category Diablo 2
#@keybinding 
#@menupath 
#@toolbar

import json

from ghidra.util.exception import CancelledException, InvalidInputException

def minify(file_name):
    file_data = open(file_name, "r", 1).read() # store file info in variable
    json_data = json.loads(file_data) # store in json structure
    json_string = json.dumps(json_data, separators=(',', ":")) # Compact JSON structure
    file_name = str(file_name).replace(".json", "") # remove .json from end of file_name string
    new_file_name = "{0}_minify.json".format(file_name)
    open(new_file_name, "w+", 1).write(json_string) # open and write json_string to file
    
def write_json(data, filename='game.json'):
    with open(filename,'w') as f:
        json.dump(data, f, indent=2)

try:
    data = []
    o = 0
    for func in currentProgram.functionManager.getFunctions(1):
        if "{}".format(func.getEntryPoint()) == "00681a48":
            break
        o = o + 1
        e = {
            "name" : func.getName(),
            "address" : "0x{}".format(func.getEntryPoint()),
            "paramcount" : func.getParameterCount(),
            "returntype" : "{}".format(func.getReturn().getDataType()),
            "ASM" : "",
            "jumpback" : "",
            "params": [
            ]
        }
        
        #get asm what we replace in case we want to hook function and it's jumpback location
        for inst in currentProgram.listing.getInstructions(func.getBody(), True):
            if inst.getAddress() >= func.getEntryPoint().add(5):
                e["jumpback"] = "0x{}".format(inst.getAddress())
                break
            e["ASM"] = e["ASM"] + "{}\n".format(inst)
        
        i = 0
        for p in func.getParameters():
            t = e["params"]
            name = p.getName()
            type = p.getDataType()
            size = type.getLength()
            if p.isRegisterVariable():
                loc = p.getRegister()
            if p.isStackVariable():
                loc = "Stack[0x{:02X}]".format(p.getStackOffset())
            w = {
                "name" : "{}".format(name),
                "type" : "{}".format(type),
                "location" : "{}".format(loc),
                "idx" : i,
                "size" : size
            }
            i = i + 1
            t.append(w)
        data.append(e)
    write_json(data)
    minify('game.json')
    print("Exported {} functions".format(o))
except CancelledException:
    pass