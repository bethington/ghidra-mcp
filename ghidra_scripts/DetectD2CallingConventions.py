#Batch Detection Script for Diablo II Custom Calling Conventions
#
#This script automatically detects all functions using Diablo II's custom calling
#conventions (__d2call, __d2regcall, __d2mixcall, __d2edicall) in the current program.
#
#Detection is based on assembly patterns observed in callers and callees.
#
#Output:
#- Console listing of detected functions per convention
#- CSV export option to save results
#- Detection confidence levels
#
#@author Ben Ethington
#@category Diablo 2
#@description Batch detects Diablo II custom calling conventions (__d2call, __d2regcall, __d2mixcall, __d2edicall) using assembly patterns
#@keybinding
#@menupath Diablo II.Detect Calling Conventions
#
"""
Supporting documentation for Batch Detection Script

IMPROVEMENTS IN THIS VERSION (v2.0):
1. Added __d2edicall detection (EDI context pointer convention)
2. Distinguishes between register save vs. register parameter usage
3. Better stack parameter detection (positive ESP offsets only, not locals)
4. Improved RET immediate parsing with proper regex
5. Multi-caller consensus analysis for higher confidence
6. Filters out tiny functions (<5 instructions) to avoid thunk false positives
7. Better ESI detection that ignores PUSH ESI (preservation vs usage)
8. Tracks register saves to avoid counting preserved registers as parameters
9. More accurate confidence scoring based on pattern completeness
10. **NEW: Standard prologue filtering** - Filters out standard Windows conventions
    that have PUSH EBP; MOV EBP,ESP prologues, dramatically reducing false positives

DETECTION METHODS:
- Caller-side analysis: Examines MOV/PUSH patterns before CALL instructions
- Callee-side analysis: Examines register usage, stack access, and return type
- Multi-caller validation: Requires 2+ callers to agree for high confidence
- Prologue analysis: Distinguishes D2 custom conventions (minimal prologue) from
  standard Windows conventions (PUSH EBP; MOV EBP,ESP frame setup)
"""

from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import CodeUnit
import re

# Configuration
VERBOSE = True
EXPORT_CSV = False
EXPORT_JSON = True  # Export results to JSON for automated testing
CONFIDENCE_THRESHOLD = 0.75  # 75% confidence minimum

class ConventionDetector:
    def __init__(self):
        self.results = {
            '__d2call': [],
            '__d2regcall': [],
            '__d2mixcall': [],
            '__d2edicall': [],
            'unknown': []
        }
        self.listing = currentProgram.getListing()
        self.func_mgr = currentProgram.getFunctionManager()
        self.monitor = monitor
        self.current_program = currentProgram

    def log(self, msg):
        if VERBOSE:
            print("[D2ConvDetector] " + msg)

    def detect_d2call_caller_pattern(self, instr):
        """
        Detect __d2call from caller pattern:
        MOV EBX, <param>
        PUSH <param>
        CALL <func>
        """
        # Must be a CALL instruction
        if not instr.getMnemonicString() == "CALL":
            return False, 0.0

        # Look back for MOV EBX pattern
        prev_instr = instr.getPrevious()
        mov_ebx_found = False
        push_count = 0
        confidence = 0.0

        # Scan up to 10 instructions back
        for i in range(10):
            if prev_instr is None:
                break

            mnemonic = prev_instr.getMnemonicString()

            # Found MOV EBX - strong indicator
            if mnemonic == "MOV":
                op_str = prev_instr.toString()
                if "EBX" in op_str:
                    mov_ebx_found = True
                    confidence += 0.5
                    break

            # Count PUSH instructions (for stack parameters)
            if mnemonic == "PUSH":
                push_count += 1
                confidence += 0.15

            prev_instr = prev_instr.getPrevious()

        # __d2call: EBX + Stack parameters + callee cleanup
        if mov_ebx_found and push_count > 0:
            return True, min(0.9, confidence + push_count * 0.1)
        elif mov_ebx_found and push_count == 0:
            return True, 0.6  # EBX alone is weaker signal

        return False, 0.0

    def has_standard_prologue(self, func):
        """
        Check if function has a standard Windows prologue pattern.
        
        Standard prologues indicate standard calling conventions (__stdcall, __cdecl,
        __fastcall, __thiscall), NOT Diablo II custom conventions.
        
        Common standard prologue patterns:
        1. PUSH EBP; MOV EBP,ESP [; SUB ESP, imm]
        2. Stack canary: MOV EAX,[cookie]; XOR EAX,EBP; MOV [EBP-8],EAX
        3. Exception handling setup
        
        Diablo II custom conventions typically have:
        - Minimal prologues (just SUB ESP, imm or no prologue)
        - No EBP frame pointer
        - Direct register usage without standard frame setup
        
        Returns:
            bool: True if standard prologue detected, False otherwise
        """
        entry = func.getEntryPoint()
        if entry is None:
            return False
        
        listing = currentProgram.getListing()
        instr = listing.getInstructionAt(entry)
        if instr is None:
            return False
        
        # Check first 4 instructions for standard prologue patterns
        prologue_instrs = []
        for _ in range(4):
            if instr is None:
                break
            prologue_instrs.append(instr)
            instr = instr.getNext()
        
        if len(prologue_instrs) < 2:
            return False
        
        # Pattern 1: PUSH EBP; MOV EBP,ESP
        first_mnem = prologue_instrs[0].getMnemonicString()
        first_ops = str(prologue_instrs[0].getDefaultOperandRepresentation(0)).upper()
        
        second_mnem = prologue_instrs[1].getMnemonicString()
        second_op0 = str(prologue_instrs[1].getDefaultOperandRepresentation(0)).upper() if prologue_instrs[1].getNumOperands() > 0 else ""
        second_op1 = str(prologue_instrs[1].getDefaultOperandRepresentation(1)).upper() if prologue_instrs[1].getNumOperands() > 1 else ""
        
        # Check for PUSH EBP
        has_push_ebp = first_mnem == "PUSH" and "EBP" in first_ops
        
        # Check for MOV EBP,ESP
        has_mov_ebp_esp = second_mnem == "MOV" and "EBP" in second_op0 and "ESP" in second_op1
        
        if has_push_ebp and has_mov_ebp_esp:
            return True
        
        # Pattern 2: Stack canary detection (often after MOV EBP,ESP)
        if len(prologue_instrs) >= 4:
            # Look for: MOV EAX,[cookie]; XOR EAX,EBP pattern
            for i in range(len(prologue_instrs) - 1):
                instr1 = prologue_instrs[i]
                instr2 = prologue_instrs[i+1]
                
                mnem1 = instr1.getMnemonicString()
                mnem2 = instr2.getMnemonicString()
                
                # Stack canary pattern
                if mnem1 == "MOV" and mnem2 == "XOR":
                    op1_dest = str(instr1.getDefaultOperandRepresentation(0)).upper()
                    op2_dest = str(instr2.getDefaultOperandRepresentation(0)).upper()
                    op2_src = str(instr2.getDefaultOperandRepresentation(1)).upper()
                    
                    # MOV EAX, [cookie]; XOR EAX, EBP
                    if "EAX" in op1_dest and "EAX" in op2_dest and "EBP" in op2_src:
                        return True
        
        return False

    def detect_d2call_callee_pattern(self, func):
        """
        Detect __d2call from callee pattern:
        - Uses EBX as parameter (not just saved)
        - Accesses stack parameters
        - Ends with RET <immediate>
        """
        entry = func.getEntryPoint()
        if entry is None:
            return False, 0.0
        
        # Filter out standard conventions with standard prologues
        if self.has_standard_prologue(func):
            return False, 0.0

        confidence = 0.0
        uses_ebx_as_param = False
        has_ret_immediate = False
        accesses_stack_param = False
        saved_ebx = False

        # Scan first 20 instructions
        instr = self.listing.getInstructionAt(entry)
        count = 0

        while instr is not None and count < 20:
            count += 1
            mnemonic = instr.getMnemonicString()
            op_str = instr.toString()

            # Check if EBX is saved (register preservation, not parameter usage)
            if mnemonic == "PUSH" and "EBX" in op_str:
                saved_ebx = True
            elif mnemonic == "MOV" and "EBX" in op_str:
                # MOV EDI,EBX or MOV EAX,[EBX] = using EBX as parameter
                # MOV EBX,ESP or MOV EBX,[ESP] = not parameter usage
                if ",EBX" in op_str or "[EBX" in op_str:
                    uses_ebx_as_param = True
                    confidence += 0.4

            # Check for EBX dereference/comparison (strong parameter indicator)
            if ("[EBX" in op_str or "EBX," in op_str) and mnemonic in ["MOV", "CMP", "TEST", "LEA", "ADD"]:
                uses_ebx_as_param = True
                confidence += 0.2

            # Check for stack parameter access (positive ESP offsets only)
            if "ESP" in op_str and mnemonic in ["MOV", "LEA", "PUSH"]:
                # Look for [ESP+4], [ESP+8], etc (parameters, not locals)
                if "+0x" in op_str or "+ 0x" in op_str:
                    try:
                        # Extract offset value
                        offset_match = re.search(r'\+\s*0x([0-9a-fA-F]+)', op_str)
                        if offset_match:
                            offset = int(offset_match.group(1), 16)
                            if offset >= 4:  # Valid parameter offset
                                accesses_stack_param = True
                                confidence += 0.2
                    except:
                        pass

            instr = instr.getNext()

        # Check for RET with immediate (callee cleanup)
        ret_instr = self.get_last_return(func)
        if ret_instr is not None:
            ret_str = ret_instr.toString()
            # Look for RET 0x4, RET 0x8, etc
            if re.search(r'RET\s+0x[0-9a-fA-F]+', ret_str):
                has_ret_immediate = True
                confidence += 0.4
            elif re.search(r'RET\s*$', ret_str):
                # Plain RET reduces confidence for d2call
                confidence -= 0.3

        # __d2call: Uses EBX as param + Stack params + RET immediate
        if uses_ebx_as_param and accesses_stack_param and has_ret_immediate:
            return True, min(0.95, confidence)
        elif uses_ebx_as_param and has_ret_immediate:
            return True, min(0.75, confidence)
        elif uses_ebx_as_param and accesses_stack_param:
            return True, min(0.65, confidence)

        return False, 0.0

    def detect_d2regcall_pattern(self, func):
        """
        Detect __d2regcall:
        - Uses EBX, EAX, and ECX as parameters (not saved registers)
        - Exactly 3 parameters expected
        - NO stack parameters
        - RET without immediate (caller cleanup)
        """
        entry = func.getEntryPoint()
        if entry is None:
            return False, 0.0
        
        # Filter out standard conventions with standard prologues
        if self.has_standard_prologue(func):
            return False, 0.0

        confidence = 0.0
        uses_regs = {'EBX': False, 'EAX': False, 'ECX': False}
        saved_regs = {'EBX': False, 'EAX': False, 'ECX': False}
        has_stack_params = False
        has_ret_immediate = False

        instr = self.listing.getInstructionAt(entry)
        count = 0

        while instr is not None and count < 25:
            count += 1
            mnemonic = instr.getMnemonicString()
            op_str = instr.toString()

            # Track register saves (PUSH EBX, PUSH EAX, PUSH ECX)
            if mnemonic == "PUSH":
                for reg in ['EBX', 'EAX', 'ECX']:
                    if reg in op_str:
                        saved_regs[reg] = True

            # Check for register usage as parameters (after potential saves)
            for reg in ['EBX', 'EAX', 'ECX']:
                if reg in op_str and not saved_regs[reg]:
                    # Look for actual usage: MOV EDI,EBX or CMP EAX,0 or MOV [ESI],ECX
                    if mnemonic in ["MOV", "CMP", "TEST", "LEA", "ADD", "SUB"] and ("," + reg in op_str or reg + "," in op_str or "[" + reg in op_str):
                        uses_regs[reg] = True
                        confidence += 0.25

            # __d2regcall should NOT have stack parameters
            if "ESP" in op_str and mnemonic in ["MOV", "PUSH", "LEA"]:
                # Check for positive ESP offset (parameter access)
                if "+0x" in op_str or "+ 0x" in op_str:
                    try:
                        offset_match = re.search(r'\+\s*0x([0-9a-fA-F]+)', op_str)
                        if offset_match:
                            offset = int(offset_match.group(1), 16)
                            if offset >= 4:  # Stack parameter detected
                                has_stack_params = True
                                confidence -= 0.5
                    except:
                        pass

            instr = instr.getNext()

        # Check return instruction
        ret_instr = self.get_last_return(func)
        if ret_instr is not None:
            ret_str = ret_instr.toString()
            if re.search(r'RET\s*$', ret_str):
                # Pure RET without immediate (caller cleanup)
                confidence += 0.4
            elif re.search(r'RET\s+0x[0-9a-fA-F]+', ret_str):
                # RET with immediate (callee cleanup) - wrong for d2regcall
                has_ret_immediate = True
                confidence -= 0.4

        # __d2regcall: All three registers + no stack params + caller cleanup
        all_regs_used = all(uses_regs.values())
        if all_regs_used and not has_stack_params and not has_ret_immediate:
            return True, min(0.95, confidence)
        elif all_regs_used and not has_stack_params:
            return True, min(0.75, confidence)

        return False, 0.0

    def detect_d2mixcall_pattern(self, func):
        """
        Detect __d2mixcall:
        - EAX + ESI for first two parameters (used, not just saved)
        - Stack parameters for remainder
        - RET with immediate (callee cleanup)
        """
        entry = func.getEntryPoint()
        if entry is None:
            return False, 0.0
        
        # Filter out standard conventions with standard prologues
        if self.has_standard_prologue(func):
            return False, 0.0

        confidence = 0.0
        uses_eax = False
        uses_esi_as_param = False
        saved_esi = False
        accesses_stack_params = False
        has_ret_immediate = False

        instr = self.listing.getInstructionAt(entry)
        count = 0

        while instr is not None and count < 25:
            count += 1
            mnemonic = instr.getMnemonicString()
            op_str = instr.toString()

            # Track if ESI is saved (PUSH ESI means it's being preserved, not used as param)
            if mnemonic == "PUSH" and "ESI" in op_str:
                saved_esi = True

            # Check for EAX usage as parameter
            if "EAX" in op_str and mnemonic in ["MOV", "CMP", "TEST", "LEA", "ADD"]:
                if ",EAX" in op_str or "EAX," in op_str or "[EAX" in op_str:
                    uses_eax = True
                    confidence += 0.3

            # Check for ESI usage as parameter (not just save/restore)
            if "ESI" in op_str and not saved_esi:
                # Look for ESI dereference or usage: MOV EAX,[ESI] or CMP ESI,0
                if "[ESI" in op_str or "ESI," in op_str or ",ESI" in op_str:
                    if mnemonic in ["MOV", "CMP", "TEST", "LEA", "ADD", "SUB"]:
                        uses_esi_as_param = True
                        confidence += 0.3

            # Look for stack parameter access
            if "ESP" in op_str and mnemonic in ["MOV", "LEA", "PUSH"]:
                if "+0x" in op_str or "+ 0x" in op_str:
                    try:
                        offset_match = re.search(r'\+\s*0x([0-9a-fA-F]+)', op_str)
                        if offset_match:
                            offset = int(offset_match.group(1), 16)
                            if offset >= 4:
                                accesses_stack_params = True
                                confidence += 0.15
                    except:
                        pass

            instr = instr.getNext()

        # Check return
        ret_instr = self.get_last_return(func)
        if ret_instr is not None:
            ret_str = ret_instr.toString()
            if re.search(r'RET\s+0x[0-9a-fA-F]+', ret_str):
                # RET with immediate (callee cleanup)
                has_ret_immediate = True
                confidence += 0.35
            else:
                confidence -= 0.2

        # __d2mixcall: EAX + ESI + stack params + RET immediate
        if uses_eax and uses_esi_as_param and accesses_stack_params and has_ret_immediate:
            return True, min(0.95, confidence)
        elif uses_eax and uses_esi_as_param and (accesses_stack_params or has_ret_immediate):
            return True, min(0.70, confidence)

        return False, 0.0

    def detect_d2edicall_pattern(self, func):
        """
        Detect __d2edicall:
        - EDI used as context pointer (first parameter)
        - Stack parameters for additional params
        - RET with immediate (callee cleanup)
        - Typically used for room/level processing functions
        """
        entry = func.getEntryPoint()
        if entry is None:
            return False, 0.0
        
        # Filter out standard conventions with standard prologues
        if self.has_standard_prologue(func):
            return False, 0.0

        confidence = 0.0
        uses_edi_as_param = False
        saved_edi = False
        accesses_stack_params = False
        has_ret_immediate = False

        instr = self.listing.getInstructionAt(entry)
        count = 0

        while instr is not None and count < 25:
            count += 1
            mnemonic = instr.getMnemonicString()
            op_str = instr.toString()

            # Track if EDI is saved (PUSH EDI = preservation, not parameter)
            if mnemonic == "PUSH" and "EDI" in op_str:
                saved_edi = True

            # Check for EDI usage as parameter (context pointer)
            if "EDI" in op_str and not saved_edi:
                # Look for EDI dereference or usage: MOV EAX,[EDI] or CMP EDI,0
                if "[EDI" in op_str or "EDI," in op_str or ",EDI" in op_str:
                    if mnemonic in ["MOV", "CMP", "TEST", "LEA", "ADD", "SUB"]:
                        uses_edi_as_param = True
                        confidence += 0.4

            # Look for stack parameter access
            if "ESP" in op_str and mnemonic in ["MOV", "LEA"]:
                if "+0x" in op_str or "+ 0x" in op_str:
                    try:
                        offset_match = re.search(r'\+\s*0x([0-9a-fA-F]+)', op_str)
                        if offset_match:
                            offset = int(offset_match.group(1), 16)
                            if offset >= 4:
                                accesses_stack_params = True
                                confidence += 0.2
                    except:
                        pass

            instr = instr.getNext()

        # Check return
        ret_instr = self.get_last_return(func)
        if ret_instr is not None:
            ret_str = ret_instr.toString()
            if re.search(r'RET\s+0x[0-9a-fA-F]+', ret_str):
                # RET with immediate (callee cleanup)
                has_ret_immediate = True
                confidence += 0.35
            else:
                confidence -= 0.2

        # __d2edicall: EDI context + optional stack params + RET immediate
        if uses_edi_as_param and has_ret_immediate:
            return True, min(0.90, confidence)
        elif uses_edi_as_param and accesses_stack_params:
            return True, min(0.70, confidence)

        return False, 0.0

    def get_last_return(self, func):
        """Get the last RET instruction in function"""
        try:
            body = func.getBody()
            last_addr = body.getMaxAddress()

            instr = self.listing.getInstructionAt(last_addr)
            while instr is not None:
                if "RET" in instr.getMnemonicString():
                    return instr
                instr = instr.getPrevious()
                if instr is None or not body.contains(instr.getAddress()):
                    break
        except:
            pass

        return None

    def analyze_callers(self, func):
        """
        Analyze multiple callers for consensus on calling convention.
        Returns (convention_name, confidence) or None
        """
        try:
            callers = func.getCallingFunctions(self.monitor)
            if callers is None or callers.isEmpty():
                return None

            caller_votes = {
                '__d2call': 0,
                '__d2regcall': 0,
                '__d2mixcall': 0,
                '__d2edicall': 0
            }

            caller_count = 0
            for caller in callers:
                if caller_count >= 5:  # Check max 5 callers
                    break

                # Find CALL instructions to our function
                call_sites = self.find_call_sites(caller, func)
                for call_addr in call_sites:
                    call_instr = self.listing.getInstructionAt(call_addr)
                    if call_instr is None:
                        continue

                    # Analyze instructions before CALL
                    pattern = self.analyze_caller_pattern(call_instr)
                    if pattern:
                        caller_votes[pattern] += 1
                    caller_count += 1

            if caller_count == 0:
                return None

            # Find convention with most votes
            best_convention = max(caller_votes, key=caller_votes.get)
            vote_count = caller_votes[best_convention]

            if vote_count >= 2:  # At least 2 callers agree
                confidence = min(0.85, 0.5 + (vote_count * 0.15))
                return (best_convention, confidence)

        except Exception as e:
            self.log(f"Error analyzing callers: {e}")

        return None

    def find_call_sites(self, caller_func, target_func):
        """Find all CALL instructions in caller that target the given function"""
        call_sites = []
        target_addr = target_func.getEntryPoint()

        try:
            body = caller_func.getBody()
            instr = self.listing.getInstructionAt(body.getMinAddress())

            while instr is not None and body.contains(instr.getAddress()):
                if instr.getMnemonicString() == "CALL":
                    # Check if this CALL targets our function
                    for i in range(instr.getNumOperands()):
                        op = instr.getOpObjects(i)
                        if op and len(op) > 0:
                            if str(op[0]) == str(target_addr):
                                call_sites.append(instr.getAddress())
                                break

                instr = instr.getNext()

        except Exception as e:
            pass

        return call_sites

    def analyze_caller_pattern(self, call_instr):
        """
        Analyze instructions before CALL to determine calling convention.
        Returns convention name or None
        """
        # Look back up to 10 instructions
        instr = call_instr.getPrevious()
        
        found_mov_ebx = False
        found_mov_eax = False
        found_mov_ecx = False
        found_mov_esi = False
        found_mov_edi = False
        push_count = 0

        for i in range(10):
            if instr is None:
                break

            mnemonic = instr.getMnemonicString()
            op_str = instr.toString()

            # Track register setup
            if mnemonic == "MOV":
                if "EBX," in op_str:
                    found_mov_ebx = True
                if "EAX," in op_str:
                    found_mov_eax = True
                if "ECX," in op_str:
                    found_mov_ecx = True
                if "ESI," in op_str:
                    found_mov_esi = True
                if "EDI," in op_str:
                    found_mov_edi = True

            if mnemonic == "PUSH":
                push_count += 1

            instr = instr.getPrevious()

        # Classify based on pattern
        if found_mov_edi and push_count > 0:
            return '__d2edicall'
        elif found_mov_ebx and found_mov_eax and found_mov_ecx and push_count == 0:
            return '__d2regcall'
        elif found_mov_eax and found_mov_esi:
            return '__d2mixcall'
        elif found_mov_ebx and push_count > 0:
            return '__d2call'

        return None

    def classify_function(self, func):
        """Classify a function by its calling convention"""
        func_name = func.getName()
        func_addr = func.getEntryPoint().toString()

        # Skip tiny functions (likely thunks/stubs)
        if func.getBody().getNumAddresses() < 5:
            return None

        # Skip obvious thunks
        if func_name.startswith("thunk_"):
            return None

        # First, check callers for consensus (most reliable)
        caller_result = self.analyze_callers(func)
        if caller_result:
            convention, confidence = caller_result
            if confidence >= CONFIDENCE_THRESHOLD:
                return (convention, confidence)

        # Fall back to callee-side detection
        
        # Test for __d2call (highest priority - most common)
        is_d2call, conf_d2call = self.detect_d2call_callee_pattern(func)
        if is_d2call and conf_d2call >= CONFIDENCE_THRESHOLD:
            return ('__d2call', conf_d2call)

        # Test for __d2edicall
        is_d2edicall, conf_d2edicall = self.detect_d2edicall_pattern(func)
        if is_d2edicall and conf_d2edicall >= CONFIDENCE_THRESHOLD:
            return ('__d2edicall', conf_d2edicall)

        # Test for __d2regcall
        is_d2regcall, conf_d2regcall = self.detect_d2regcall_pattern(func)
        if is_d2regcall and conf_d2regcall >= CONFIDENCE_THRESHOLD:
            return ('__d2regcall', conf_d2regcall)

        # Test for __d2mixcall
        is_d2mixcall, conf_d2mixcall = self.detect_d2mixcall_pattern(func)
        if is_d2mixcall and conf_d2mixcall >= CONFIDENCE_THRESHOLD:
            return ('__d2mixcall', conf_d2mixcall)

        # Return highest confidence even if below threshold
        candidates = [
            ('__d2call', conf_d2call),
            ('__d2edicall', conf_d2edicall),
            ('__d2regcall', conf_d2regcall),
            ('__d2mixcall', conf_d2mixcall)
        ]
        
        # Include caller result if available
        if caller_result:
            candidates.append(caller_result)
        
        best = max(candidates, key=lambda x: x[1])
        if best[1] > 0.4:  # Low threshold for uncertain classification
            return ('unknown', best[1])

        return None

    def scan_all_functions(self):
        """Scan all functions in program"""
        func_count = 0
        detected_count = 0

        funcs = self.func_mgr.getFunctions(True)
        total = 0
        for f in self.func_mgr.getFunctions(True):
            total += 1

        self.log(f"Scanning {total} functions...")

        for func in self.func_mgr.getFunctions(True):
            func_count += 1

            if func_count % 100 == 0:
                self.log(f"Progress: {func_count}/{total} functions scanned")

            result = self.classify_function(func)
            if result is None:
                continue

            convention, confidence = result
            func_name = func.getName()
            func_addr = func.getEntryPoint().toString()

            entry = {
                'address': func_addr,
                'name': func_name,
                'confidence': confidence
            }

            self.results[convention].append(entry)
            detected_count += 1

        return func_count, detected_count

    def print_results(self):
        """Print detection results to console"""
        print("\n" + "="*70)
        print("DIABLO II CALLING CONVENTION DETECTION RESULTS")
        print("="*70 + "\n")

        total_detected = 0

        # Print __d2call results
        d2call_funcs = self.results['__d2call']
        print(f"__d2call: {len(d2call_funcs)} functions detected")
        print("-" * 70)
        for entry in sorted(d2call_funcs, key=lambda x: x['confidence'], reverse=True)[:20]:
            print(f"  {entry['address']}: {entry['name']}")
            print(f"    Confidence: {entry['confidence']:.1%}")
        if len(d2call_funcs) > 20:
            print(f"  ... and {len(d2call_funcs) - 20} more")
        print()
        total_detected += len(d2call_funcs)

        # Print __d2regcall results
        d2regcall_funcs = self.results['__d2regcall']
        print(f"__d2regcall: {len(d2regcall_funcs)} functions detected")
        print("-" * 70)
        for entry in sorted(d2regcall_funcs, key=lambda x: x['confidence'], reverse=True)[:20]:
            print(f"  {entry['address']}: {entry['name']}")
            print(f"    Confidence: {entry['confidence']:.1%}")
        if len(d2regcall_funcs) > 20:
            print(f"  ... and {len(d2regcall_funcs) - 20} more")
        print()
        total_detected += len(d2regcall_funcs)

        # Print __d2mixcall results
        d2mixcall_funcs = self.results['__d2mixcall']
        print(f"__d2mixcall: {len(d2mixcall_funcs)} functions detected")
        print("-" * 70)
        for entry in sorted(d2mixcall_funcs, key=lambda x: x['confidence'], reverse=True)[:20]:
            print(f"  {entry['address']}: {entry['name']}")
            print(f"    Confidence: {entry['confidence']:.1%}")
        if len(d2mixcall_funcs) > 20:
            print(f"  ... and {len(d2mixcall_funcs) - 20} more")
        print()
        total_detected += len(d2mixcall_funcs)

        # Print __d2edicall results
        d2edicall_funcs = self.results['__d2edicall']
        print(f"__d2edicall: {len(d2edicall_funcs)} functions detected")
        print("-" * 70)
        for entry in sorted(d2edicall_funcs, key=lambda x: x['confidence'], reverse=True)[:20]:
            print(f"  {entry['address']}: {entry['name']}")
            print(f"    Confidence: {entry['confidence']:.1%}")
        if len(d2edicall_funcs) > 20:
            print(f"  ... and {len(d2edicall_funcs) - 20} more")
        print()
        total_detected += len(d2edicall_funcs)

        # Summary
        print("="*70)
        print(f"SUMMARY: {total_detected} functions detected using custom conventions")
        print("="*70 + "\n")

        if EXPORT_CSV:
            self.export_csv()
        
        if EXPORT_JSON:
            self.export_json()

    def export_csv(self):
        """Export results to CSV file"""
        import os

        csv_path = os.path.join(os.path.expanduser("~"), "Desktop", "d2_conventions.csv")

        try:
            with open(csv_path, 'w') as f:
                f.write("Convention,Address,Name,Confidence\n")

                for conv, funcs in self.results.items():
                    for entry in funcs:
                        f.write(f"{conv},{entry['address']},{entry['name']},{entry['confidence']:.2%}\n")

            print(f"[✓] Results exported to: {csv_path}")
        except Exception as e:
            print(f"[✗] Failed to export CSV: {e}")

    def export_json(self):
        """Export results to JSON file for automated testing"""
        import os
        import json

        json_path = os.path.join(os.path.expanduser("~"), "Desktop", "d2_conventions.json")

        try:
            # Convert results to JSON-serializable format
            output = {
                'program_name': currentProgram.getName(),
                'detection_timestamp': str(java.util.Date()),
                'confidence_threshold': CONFIDENCE_THRESHOLD,
                'total_detected': sum(len(funcs) for funcs in self.results.values()),
                'by_convention': {}
            }

            for conv, funcs in self.results.items():
                output['by_convention'][conv] = {
                    'count': len(funcs),
                    'functions': [
                        {
                            'address': entry['address'],
                            'name': entry['name'],
                            'confidence': float(entry['confidence'])
                        }
                        for entry in funcs
                    ]
                }

            with open(json_path, 'w') as f:
                json.dump(output, f, indent=2)

            print(f"[✓] JSON results exported to: {json_path}")
        except Exception as e:
            print(f"[✗] Failed to export JSON: {e}")


def main():
    """Main entry point"""
    if currentProgram is None:
        print("[✗] No program loaded in Ghidra!")
        return

    print("[*] Starting Diablo II calling convention detection...")
    print(f"[*] Program: {currentProgram.getName()}")

    detector = ConventionDetector()
    func_count, detected_count = detector.scan_all_functions()
    detector.print_results()

    print(f"[✓] Detection complete!")
    print(f"    Total functions scanned: {func_count}")
    print(f"    Custom conventions detected: {detected_count}")


if __name__ == "__main__":
    main()
