// Find Functions After Padding
//
// Scans for sequences of padding bytes (INT3, NOP) and creates functions at the next valid address. Supports single program, folder, or project-wide processing with auto-reanalysis.
//
// Usage: Run from Script Manager. Optionally requires RET before padding for stronger validation.
// Output: Creates new functions at discovered entry points in the program.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Find and create functions after padding bytes
// @menupath Diablo 2.Analysis.Find Functions After Padding

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.framework.model.*;
import ghidra.app.services.ProgramManager;
import ghidra.util.task.TaskMonitor;
import java.util.HashSet;
import java.util.Set;
import java.util.ArrayList;
import java.util.List;

public class Analyze_FindFunctionsAfterPadding extends GhidraScript {

	// Mode selection constants
	private static final String MODE_SINGLE = "Single Program (current)";
	private static final String MODE_FOLDER = "All Programs in Current Folder";
	private static final String MODE_PROJECT = "All Programs in Entire Project";

	// Configurable padding bytes - add additional values here as needed
	// WARNING: Do NOT include 0x00 (NULL) - it creates false positives in data regions!
	private static final byte[] PADDING_BYTES = {
		(byte) 0xCC,  // INT3 - Debug breakpoint, common padding
		(byte) 0x90,  // NOP - No operation, alignment padding
		// (byte) 0x00,  // NULL - DISABLED: Creates too many false positives in data/struct fields
		// Add additional padding byte values below:
		// (byte) 0x66, 0x90 would be 2-byte NOP but we check single bytes
	};

	private static final int MIN_PADDING_SEQUENCE = 3;

	// Require a RET instruction before the padding sequence?
	// This provides stronger validation that we're at a real function boundary
	private static final boolean REQUIRE_RET_BEFORE_PADDING = true;

	// RET instruction opcodes
	private static final byte RET_NEAR = (byte) 0xC3;       // RET (near return)
	private static final byte RET_NEAR_IMM16 = (byte) 0xC2; // RET imm16 (near return with stack pop)
	private static final byte RET_FAR = (byte) 0xCB;        // RETF (far return)
	private static final byte RET_FAR_IMM16 = (byte) 0xCA;  // RETF imm16 (far return with stack pop)

	// Set for O(1) lookup of padding bytes
	private Set<Byte> paddingByteSet;

	// Totals for batch processing
	private int totalProgramsProcessed = 0;
	private int totalFunctionsFound = 0;
	private int totalFunctionsCreated = 0;

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("No program loaded!");
			return;
		}

		// Initialize padding byte set for fast lookup
		paddingByteSet = new HashSet<>();
		for (byte b : PADDING_BYTES) {
			paddingByteSet.add(b);
		}

		// Mode selection
		String[] modes = { MODE_SINGLE, MODE_FOLDER, MODE_PROJECT };
		String selectedMode = askChoice("Processing Mode", 
			"Select which programs to process:", 
			java.util.Arrays.asList(modes), MODE_SINGLE);

		println("=== FindFunctionsAfterPadding ===");
		println("Mode: " + selectedMode);
		println("Configured padding bytes:");
		for (byte b : PADDING_BYTES) {
			println("  0x" + String.format("%02X", b & 0xFF) + " (" + getPaddingByteName(b) + ")");
		}
		println("Minimum padding sequence length: " + MIN_PADDING_SEQUENCE);
		println("Require RET before padding: " + REQUIRE_RET_BEFORE_PADDING);
		println("");

		// Reset totals
		totalProgramsProcessed = 0;
		totalFunctionsFound = 0;
		totalFunctionsCreated = 0;

		if (selectedMode.equals(MODE_SINGLE)) {
			// Process only current program
			processSingleProgram(currentProgram);
		} else {
			// Get project and process multiple programs
			Project project = state.getProject();
			if (project == null) {
				println("ERROR: No project open!");
				return;
			}

			ProjectData projectData = project.getProjectData();
			DomainFolder rootFolder = projectData.getRootFolder();

			if (selectedMode.equals(MODE_FOLDER)) {
				// Get the folder containing the current program
				DomainFile currentFile = currentProgram.getDomainFile();
				DomainFolder currentFolder = currentFile.getParent();
				println("Processing folder: " + currentFolder.getPathname());
				processFolderPrograms(currentFolder, false);
			} else if (selectedMode.equals(MODE_PROJECT)) {
				// Process entire project
				println("Processing entire project...");
				processFolderPrograms(rootFolder, true);
			}
		}

		// Print final summary
		println("\n========================================");
		println("=== FINAL SUMMARY ===");
		println("========================================");
		println("Total programs processed: " + totalProgramsProcessed);
		println("Total potential functions found: " + totalFunctionsFound);
		println("Total functions created: " + totalFunctionsCreated);
		println("\nDone!");
	}

	/**
	 * Process all programs in a folder, optionally recursing into subfolders
	 */
	private void processFolderPrograms(DomainFolder folder, boolean recursive) throws Exception {
		if (monitor.isCancelled()) {
			return;
		}

		// Get all domain files in this folder
		DomainFile[] files = folder.getFiles();
		for (DomainFile file : files) {
			if (monitor.isCancelled()) {
				println("Operation cancelled by user");
				return;
			}

			// Check if this is a Program file
			String contentType = file.getContentType();
			if (contentType != null && contentType.equals("Program")) {
				processProjectProgram(file);
			}
		}

		// Recurse into subfolders if requested
		if (recursive) {
			DomainFolder[] subfolders = folder.getFolders();
			for (DomainFolder subfolder : subfolders) {
				if (monitor.isCancelled()) {
					return;
				}
				println("\n--- Entering folder: " + subfolder.getPathname() + " ---");
				processFolderPrograms(subfolder, true);
			}
		}
	}

	/**
	 * Open, process, reanalyze, and save a program from the project
	 */
	private void processProjectProgram(DomainFile file) throws Exception {
		String programPath = file.getPathname();
		println("\n========================================");
		println("Opening: " + programPath);
		println("========================================");

		Program program = null;
		boolean needsRelease = false;

		try {
			// Open the program for update (exclusive access)
			program = (Program) file.getDomainObject(this, true, false, monitor);
			needsRelease = true;

			if (program == null) {
				println("ERROR: Failed to open " + programPath);
				return;
			}

			// Process this program
			processSingleProgram(program);

			// Save the program after processing
			if (program.canSave() && program.isChanged()) {
				println("Saving changes to " + programPath + "...");
				program.save("FindFunctionsAfterPadding: Created functions and reanalyzed", monitor);
				println("Saved successfully.");
			}

		} catch (Exception e) {
			println("ERROR processing " + programPath + ": " + e.getMessage());
			e.printStackTrace();
		} finally {
			// Release the program
			if (program != null && needsRelease) {
				program.release(this);
			}
		}
	}

	/**
	 * Process a single program - find functions after padding and reanalyze
	 */
	private void processSingleProgram(Program program) throws Exception {
		if (program == null) {
			println("ERROR: Program is null");
			return;
		}

		String programName = program.getName();
		println("\n--- Processing: " + programName + " ---");

		Memory memory = program.getMemory();
		int foundCount = 0;
		int createdCount = 0;

		monitor.setMessage("Searching for functions after padding in " + programName + "...");

		// Start a transaction for modifications
		int transactionId = program.startTransaction("FindFunctionsAfterPadding");
		boolean success = false;

		try {
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

				println("  Searching block: " + block.getName() + " (" + block.getStart() + " - " +
					block.getEnd() + ")");

				int[] results = processMemoryBlock(program, memory, block);
				foundCount += results[0];
				createdCount += results[1];
			}

			// Reanalyze if we created any functions
			if (createdCount > 0) {
				println("\n  Reanalyzing " + programName + " after creating " + createdCount + " functions...");
				analyzeChanges(program);
				println("  Reanalysis complete.");
			}

			success = true;

		} finally {
			program.endTransaction(transactionId, success);
		}

		totalProgramsProcessed++;
		totalFunctionsFound += foundCount;
		totalFunctionsCreated += createdCount;

		println("\n  --- Summary for " + programName + " ---");
		println("  Potential functions found: " + foundCount);
		println("  Functions created: " + createdCount);
	}

	/**
	 * Process a single memory block for padding sequences
	 */
	private int[] processMemoryBlock(Program program, Memory memory, MemoryBlock block) {
		int foundCount = 0;
		int createdCount = 0;

		Address address = block.getStart();
		Address blockEnd = block.getEnd();

		boolean inPaddingSequence = false;
		Address paddingStart = null;
		int paddingCount = 0;
		byte paddingByte = 0;

		// Scan through the block byte by byte
		while (address.compareTo(blockEnd) <= 0) {
			if (monitor.isCancelled()) {
				return new int[] { foundCount, createdCount };
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
						// Continue sequence (same byte or mixed padding allowed)
						paddingCount++;
					}
					else {
						// Different padding byte - treat as end of sequence and start new one
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
						Function existingFunc = program.getFunctionManager().getFunctionAt(potentialFuncAddr);

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

								// Disassemble first
								ghidra.app.cmd.disassemble.DisassembleCommand disCmd = 
									new ghidra.app.cmd.disassemble.DisassembleCommand(potentialFuncAddr, null, true);
								boolean didDisassemble = disCmd.applyTo(program, monitor);
								
								if (didDisassemble) {
									// Create function
									ghidra.app.cmd.function.CreateFunctionCmd funcCmd = 
										new ghidra.app.cmd.function.CreateFunctionCmd(potentialFuncAddr);
									boolean created = funcCmd.applyTo(program, monitor);
									
									if (created) {
										createdCount++;
										println("      -> Created function at " + potentialFuncAddr);
									}
									else {
										println("      -> Failed to create function at " + potentialFuncAddr);
									}
								}

								foundCount++;
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

		return new int[] { foundCount, createdCount };
	}

	/**
	 * Check if the given byte is a configured padding byte
	 */
	private boolean isPaddingByte(byte b) {
		return paddingByteSet.contains(b);
	}

	/**
	 * Whether to allow mixed padding bytes in the same sequence
	 * Set to true if you want sequences like CC CC 90 90 CC to count as continuous padding
	 * Set to false to require homogeneous padding sequences
	 */
	private boolean isMixedPaddingAllowed() {
		return true;  // Allow mixed padding by default
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
	 * Check if there's a RET instruction immediately before the padding sequence.
	 * This validates that we're after a real function end, not random padding in data.
	 * 
	 * Handles both simple RET (0xC3/0xCB) and RET with immediate (0xC2/0xCA + imm16)
	 */
	private boolean hasRetBeforePadding(Memory memory, Address paddingStart) {
		try {
			// Check the byte immediately before padding
			Address beforePadding = paddingStart.subtract(1);
			byte lastByte = memory.getByte(beforePadding);
			
			// Simple RET or RETF
			if (lastByte == RET_NEAR || lastByte == RET_FAR) {
				return true;
			}
			
			// RET imm16 or RETF imm16 - the RET opcode is 3 bytes back (opcode + 2-byte immediate)
			if (paddingStart.getOffset() >= 3) {
				Address retWithImm = paddingStart.subtract(3);
				byte retOpcode = memory.getByte(retWithImm);
				if (retOpcode == RET_NEAR_IMM16 || retOpcode == RET_FAR_IMM16) {
					return true;
				}
			}
			
			return false;
		}
		catch (MemoryAccessException e) {
			return false;
		}
		catch (Exception e) {
			return false;
		}
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
					return false;

				default:
					// Check if it's a padding byte - if so, not a valid function start
					if (isPaddingByte(byte1)) {
						return false;
					}
					// Default to true for other opcodes
					return true;
			}
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

}
