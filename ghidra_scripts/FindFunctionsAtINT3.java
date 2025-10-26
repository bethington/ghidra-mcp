/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// FindFunctionsAtINT3.java
// Finds potential function starts after INT3 (0xCC) padding and creates functions
// Searches for sequences of INT3 bytes (0xCC) and creates functions at the next valid address
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryAccessException;

public class FindFunctionsAtINT3 extends GhidraScript {

	private static final byte INT3_BYTE = (byte) 0xCC;
	private static final int MIN_INT3_SEQUENCE = 3;

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("No program loaded!");
			return;
		}

		Memory memory = currentProgram.getMemory();
		int foundCount = 0;
		int createdCount = 0;

		monitor.setMessage("Searching for functions after INT3 sequences...");

		// Iterate through all memory blocks
		MemoryBlock[] memoryBlocks = memory.getBlocks();
		for (MemoryBlock block : memoryBlocks) {
			if (monitor.isCancelled()) {
				println("Operation cancelled by user");
				return;
			}

			// Only process executable blocks
			if (!block.isExecute()) {
				continue;
			}

			println("Searching block: " + block.getName() + " (" + block.getStart() + " - " +
				block.getEnd() + ")");

			Address address = block.getStart();
			Address blockEnd = block.getEnd();

			boolean inInt3Sequence = false;
			Address int3Start = null;
			int int3Count = 0;

			// Scan through the block byte by byte
			while (address.compareTo(blockEnd) <= 0) {
				if (monitor.isCancelled()) {
					println("Operation cancelled by user");
					return;
				}

				try {
					byte byteValue = memory.getByte(address);

					if (byteValue == INT3_BYTE) {
						// Found an INT3 byte
						if (!inInt3Sequence) {
							inInt3Sequence = true;
							int3Start = address;
							int3Count = 1;
						}
						else {
							int3Count++;
						}
					}
					else {
						// End of INT3 sequence
						if (inInt3Sequence && int3Count >= MIN_INT3_SEQUENCE) {
							// Found potential function start
							Address potentialFuncAddr = address;

							// Check if there's already a function here
							Function existingFunc = getFunctionAt(potentialFuncAddr);

							if (existingFunc == null) {
								// Check if this looks like valid code
								if (isValidFunctionStart(memory, potentialFuncAddr)) {
									println("Found potential function at " + potentialFuncAddr +
										" (after " + int3Count + " INT3 bytes at " + int3Start +
										")");

									// Disassemble first
									boolean didDisassemble = disassemble(potentialFuncAddr);
									if (didDisassemble) {
										// Create function
										Function func = createFunction(potentialFuncAddr, null);
										if (func != null) {
											createdCount++;
											println("  -> Created function at " +
												potentialFuncAddr);
										}
										else {
											println("  -> Failed to create function at " +
												potentialFuncAddr);
										}
									}

									foundCount++;
								}
							}
						}

						inInt3Sequence = false;
						int3Count = 0;
					}

					address = address.add(1);

				}
				catch (MemoryAccessException e) {
					// Skip this address and continue
					address = address.add(1);
					continue;
				}
				catch (Exception e) {
					println("Error at " + address + ": " + e.getMessage());
					address = address.add(1);
					continue;
				}
			}
		}

		println("\n=== Summary ===");
		println("Potential functions found: " + foundCount);
		println("Functions created: " + createdCount);
		println("\nDone!");
	}

	/**
	 * Check if address looks like a valid function start by examining the first byte
	 * for common function prologues
	 */
	private boolean isValidFunctionStart(Memory memory, Address address) {
		try {
			byte byte1 = memory.getByte(address);
			int unsignedByte = byte1 & 0xFF;

			// Common x86/x64 function start patterns
			switch (unsignedByte) {
				case 0x55: // PUSH EBP
				case 0x8B: // MOV instruction (common start)
				case 0x53: // PUSH EBX
				case 0x56: // PUSH ESI
				case 0x57: // PUSH EDI
				case 0x83: // SUB ESP (8-bit immediate)
				case 0x81: // SUB ESP (32-bit immediate)
				case 0xE8: // CALL (less common but valid)
				case 0xE9: // JMP (less common but valid)
				case 0x48: // x64 REX.W prefix
				case 0x4C: // x64 REX prefix
				case 0x40: // x64 REX prefix
				case 0x41: // x64 REX.B prefix
				case 0x44: // x64 REX.R prefix
				case 0x45: // x64 REX.RB prefix
				case 0x49: // x64 REX.WB prefix
				case 0x4D: // x64 REX.WRB prefix
					return true;

				case 0xC3: // RET (could be single-instruction function, but usually not)
				case 0x90: // NOP (might be padding)
				case 0xCC: // Another INT3
					return false;

				default:
					// Default to true for other opcodes
					return true;
			}
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

}
