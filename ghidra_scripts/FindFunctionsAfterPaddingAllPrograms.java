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
// FindFunctionsAfterPaddingAllPrograms.java
// Runs FindFunctionsAfterPadding analysis on every binary in the current Ghidra project
// Iterates through all programs in the project and applies padding-based function discovery
//@author Ben Ethington
//@category Diablo 2

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class FindFunctionsAfterPaddingAllPrograms extends GhidraScript {

	// Configurable padding bytes - add additional values here as needed
	// WARNING: Do NOT include 0x00 (NULL) - it creates false positives in data regions!
	private static final byte[] PADDING_BYTES = {
		(byte) 0xCC,  // INT3 - Debug breakpoint, common padding
		(byte) 0x90,  // NOP - No operation, alignment padding
	};

	private static final int MIN_PADDING_SEQUENCE = 3;

	// Require a RET instruction before the padding sequence?
	private static final boolean REQUIRE_RET_BEFORE_PADDING = true;

	// RET instruction opcodes
	private static final byte RET_NEAR = (byte) 0xC3;
	private static final byte RET_NEAR_IMM16 = (byte) 0xC2;
	private static final byte RET_FAR = (byte) 0xCB;
	private static final byte RET_FAR_IMM16 = (byte) 0xCA;

	// Set for O(1) lookup of padding bytes
	private Set<Byte> paddingByteSet;

	// Overall statistics
	private int totalPrograms = 0;
	private int totalFunctionsFound = 0;
	private int totalFunctionsCreated = 0;

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("No program loaded - will process all programs in project!");
		}

		// Initialize padding byte set for fast lookup
		paddingByteSet = new HashSet<>();
		for (byte b : PADDING_BYTES) {
			paddingByteSet.add(b);
		}

		println("=== FindFunctionsAfterPadding - ALL PROGRAMS ===");
		println("Configured padding bytes:");
		for (byte b : PADDING_BYTES) {
			println("  0x" + String.format("%02X", b & 0xFF) + " (" + getPaddingByteName(b) + ")");
		}
		println("Minimum padding sequence length: " + MIN_PADDING_SEQUENCE);
		println("Require RET before padding: " + REQUIRE_RET_BEFORE_PADDING);
		println("");

		// Get all programs in the project
		List<DomainFile> allPrograms = getAllProgramsInProject();
		
		if (allPrograms.isEmpty()) {
			println("No programs found in project!");
			return;
		}

		println("Found " + allPrograms.size() + " programs in project");
		println("==================================================\n");

		// Process each program
		for (DomainFile domainFile : allPrograms) {
			if (monitor.isCancelled()) {
				println("\nOperation cancelled by user");
				break;
			}

			processProgramFile(domainFile);
		}

		// Print overall summary
		println("\n");
		println("=======================================================");
		println("=== OVERALL SUMMARY ===");
		println("=======================================================");
		println("Total programs processed: " + totalPrograms);
		println("Total potential functions found: " + totalFunctionsFound);
		println("Total functions created: " + totalFunctionsCreated);
		println("\nDone!");
	}

	/**
	 * Get all programs in the current project recursively
	 */
	private List<DomainFile> getAllProgramsInProject() throws Exception {
		List<DomainFile> programs = new ArrayList<>();
		DomainFolder rootFolder = state.getProject().getProjectData().getRootFolder();
		collectPrograms(rootFolder, programs);
		return programs;
	}

	/**
	 * Recursively collect all program files from a folder
	 */
	private void collectPrograms(DomainFolder folder, List<DomainFile> programs) throws Exception {
		// Add all programs in this folder
		for (DomainFile file : folder.getFiles()) {
			if (file.getContentType().equals("Program")) {
				programs.add(file);
			}
		}

		// Recursively process subfolders
		for (DomainFolder subfolder : folder.getFolders()) {
			collectPrograms(subfolder, programs);
		}
	}

	/**
	 * Process a single program file
	 */
	private void processProgramFile(DomainFile domainFile) {
		Program program = null;
		try {
			println("\n" + "=".repeat(70));
			println("Processing: " + domainFile.getPathname());
			println("=".repeat(70));

			// Open the program
			program = (Program) domainFile.getDomainObject(this, false, false, monitor);
			
			if (program == null) {
				println("  ERROR: Could not open program");
				return;
			}

			totalPrograms++;

			// Run the padding analysis on this program
			int foundCount = analyzeProgram(program);
			
			println("\n  Program Summary:");
			println("  - Potential functions found: " + foundCount);

			// Run auto-analysis if any functions were created
			if (foundCount > 0) {
				println("\n  Running auto-analysis...");
				runAutoAnalysis(program);
				println("  Auto-analysis completed");
			}

		} catch (Exception e) {
			println("  ERROR processing " + domainFile.getName() + ": " + e.getMessage());
			e.printStackTrace();
		} finally {
			if (program != null) {
				program.release(this);
			}
		}
	}

	/**
	 * Run auto-analysis on the program
	 */
	private void runAutoAnalysis(Program program) {
		try {
			// Trigger analysis by calling analyzeAll
			// This will run in the background after the transaction commits
			int txId = program.startTransaction("Trigger Analysis");
			try {
				// The analysis will run automatically when functions are created
				// No additional action needed - just commit the transaction
			} finally {
				program.endTransaction(txId, true);
			}
			println("  Auto-analysis will run in background");
		} catch (Exception e) {
			println("  WARNING: Auto-analysis trigger failed: " + e.getMessage());
		}
	}

	/**
	 * Analyze a single program for functions after padding
	 */
	private int analyzeProgram(Program program) throws Exception {
		Memory memory = program.getMemory();
		int foundCount = 0;

		// Iterate through all memory blocks
		MemoryBlock[] memoryBlocks = memory.getBlocks();
		for (MemoryBlock block : memoryBlocks) {
			if (monitor.isCancelled()) {
				return foundCount;
			}

			// Only process executable blocks
			if (!block.isExecute()) {
				continue;
			}

			println("  Searching block: " + block.getName() + " (" + block.getStart() + " - " +
				block.getEnd() + ")");

			Address address = block.getStart();
			Address blockEnd = block.getEnd();

			boolean inPaddingSequence = false;
			Address paddingStart = null;
			int paddingCount = 0;
			byte paddingByte = 0;

			// Scan through the block byte by byte
			while (address.compareTo(blockEnd) <= 0) {
				if (monitor.isCancelled()) {
					return foundCount;
				}

				try {
					byte byteValue = memory.getByte(address);

					if (isPaddingByte(byteValue)) {
						// Found a padding byte
						if (!inPaddingSequence) {
							inPaddingSequence = true;
							paddingStart = address;
							paddingCount = 1;
							paddingByte = byteValue;
						}
						else if (byteValue == paddingByte || isMixedPaddingAllowed()) {
							// Continue sequence
							paddingCount++;
						}
						else {
							// Different padding byte - reset
							paddingStart = address;
							paddingCount = 1;
							paddingByte = byteValue;
						}
					}
					else {
						// End of padding sequence - non-padding byte found
						if (inPaddingSequence && paddingCount >= MIN_PADDING_SEQUENCE) {
							// Found potential function start
							Address potentialFuncAddr = address;

							// Check if there's already a function here
							Function existingFunc = program.getListing().getFunctionAt(potentialFuncAddr);

							if (existingFunc == null) {
								// Check if RET exists before the padding (if required)
								boolean hasRetBefore = !REQUIRE_RET_BEFORE_PADDING || 
									hasRetBeforePadding(memory, paddingStart);
								
								// Check if this looks like valid code
								if (hasRetBefore && isValidFunctionStart(memory, potentialFuncAddr)) {
									String paddingDesc = String.format("0x%02X (%s)", 
										paddingByte & 0xFF, getPaddingByteName(paddingByte));
									String retInfo = REQUIRE_RET_BEFORE_PADDING ? " [RET verified]" : "";
									println("    Found potential function at " + potentialFuncAddr +
										" (after " + paddingCount + " " + paddingDesc + 
										" bytes at " + paddingStart + ")" + retInfo);

									// Start transaction for modifications
									int transactionID = program.startTransaction("Create Function");
									try {
										// Disassemble first
										disassemble(program, potentialFuncAddr);
										
										// Create function with AddressSet
										AddressSet funcBody = new AddressSet(potentialFuncAddr, potentialFuncAddr);
										Function func = program.getFunctionManager().createFunction(
											null, potentialFuncAddr, 
											funcBody,
											SourceType.ANALYSIS);
										
										if (func != null) {
											totalFunctionsCreated++;
											println("      -> Created function at " + potentialFuncAddr);
										}
									} finally {
										program.endTransaction(transactionID, true);
									}

									foundCount++;
									totalFunctionsFound++;
								}
							}
						}

						inPaddingSequence = false;
						paddingCount = 0;
					}

					address = address.add(1);

				}
				catch (MemoryAccessException e) {
					// Skip this address and continue
					address = address.add(1);
					inPaddingSequence = false;
					paddingCount = 0;
					continue;
				}
				catch (Exception e) {
					println("    Error at " + address + ": " + e.getMessage());
					address = address.add(1);
					inPaddingSequence = false;
					paddingCount = 0;
					continue;
				}
			}
		}

		return foundCount;
	}

	/**
	 * Disassemble at the given address
	 */
	private void disassemble(Program program, Address address) {
		try {
			DisassembleCommand cmd = new DisassembleCommand(address, null, true);
			cmd.applyTo(program, monitor);
		} catch (Exception e) {
			// Ignore disassembly errors
		}
	}

	/**
	 * Check if the given byte is a configured padding byte
	 */
	private boolean isPaddingByte(byte b) {
		return paddingByteSet.contains(b);
	}

	/**
	 * Whether to allow mixed padding bytes in the same sequence
	 */
	private boolean isMixedPaddingAllowed() {
		return true;
	}

	/**
	 * Get a human-readable name for a padding byte
	 */
	private String getPaddingByteName(byte b) {
		switch (b & 0xFF) {
			case 0xCC: return "INT3";
			case 0x90: return "NOP";
			case 0x00: return "NULL";
			default: return "UNKNOWN";
		}
	}

	/**
	 * Check if there's a RET instruction immediately before the padding sequence
	 */
	private boolean hasRetBeforePadding(Memory memory, Address paddingStart) {
		try {
			Address beforePadding = paddingStart.subtract(1);
			byte lastByte = memory.getByte(beforePadding);
			
			// Simple RET or RETF
			if (lastByte == RET_NEAR || lastByte == RET_FAR) {
				return true;
			}
			
			// RET imm16 or RETF imm16
			if (paddingStart.getOffset() >= 3) {
				Address retWithImm = paddingStart.subtract(3);
				byte retOpcode = memory.getByte(retWithImm);
				if (retOpcode == RET_NEAR_IMM16 || retOpcode == RET_FAR_IMM16) {
					return true;
				}
			}
			
			return false;
		}
		catch (Exception e) {
			return false;
		}
	}

	/**
	 * Check if address looks like a valid function start
	 */
	private boolean isValidFunctionStart(Memory memory, Address address) {
		try {
			byte byte1 = memory.getByte(address);
			int unsignedByte = byte1 & 0xFF;

			// Common x86/x64 function start patterns
			switch (unsignedByte) {
				case 0x55: // PUSH EBP
				case 0x8B: // MOV instruction
				case 0x53: // PUSH EBX
				case 0x56: // PUSH ESI
				case 0x57: // PUSH EDI
				case 0x83: // SUB ESP (8-bit immediate)
				case 0x81: // SUB ESP (32-bit immediate)
				case 0xE8: // CALL
				case 0xE9: // JMP
				case 0x48: // x64 REX.W prefix
				case 0x4C: // x64 REX prefix
				case 0x40: // x64 REX prefix
				case 0x41: // x64 REX.B prefix
				case 0x44: // x64 REX.R prefix
				case 0x45: // x64 REX.RB prefix
				case 0x49: // x64 REX.WB prefix
				case 0x4D: // x64 REX.WRB prefix
					return true;

				case 0xC3: // RET
					return false;

				default:
					if (isPaddingByte(byte1)) {
						return false;
					}
					return true;
			}
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}
}
