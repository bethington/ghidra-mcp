// FindFunctionsAfterPaddingWrapper.java
// Wrapper script to run FindFunctionsAfterPadding with timeout protection
//@author Ben Ethington
//@category Diablo 2

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryAccessException;
import java.util.HashSet;
import java.util.Set;

public class FindFunctionsAfterPaddingWrapper extends GhidraScript {

	private static final byte[] PADDING_BYTES = {
		(byte) 0xCC,  // INT3
		(byte) 0x90,  // NOP
	};

	private static final int MIN_PADDING_SEQUENCE = 3;
	private static final boolean REQUIRE_RET_BEFORE_PADDING = true;
	private static final byte RET_NEAR = (byte) 0xC3;
	private static final byte RET_NEAR_IMM16 = (byte) 0xC2;
	private static final byte RET_FAR = (byte) 0xCB;
	private static final byte RET_FAR_IMM16 = (byte) 0xCA;

	private Set<Byte> paddingByteSet;

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			println("ERROR: No program loaded!");
			return;
		}

		paddingByteSet = new HashSet<>();
		for (byte b : PADDING_BYTES) {
			paddingByteSet.add(b);
		}

		println("=== FindFunctionsAfterPaddingWrapper ===");
		println("Program: " + currentProgram.getName());
		println("Searching for functions after padding...");
		println("");

		Memory memory = currentProgram.getMemory();
		int foundCount = 0;
		int createdCount = 0;
		int processedBlocks = 0;

		try {
			MemoryBlock[] memoryBlocks = memory.getBlocks();
			
			for (MemoryBlock block : memoryBlocks) {
				if (monitor.isCancelled()) {
					println("Operation cancelled");
					break;
				}

				if (!block.isExecute()) {
					continue;
				}

				processedBlocks++;
				monitor.setMessage("Processing block: " + block.getName());

				Address blockStart = block.getStart();
				Address blockEnd = block.getEnd();
				Address currentAddr = blockStart;

				while (currentAddr <= blockEnd && !monitor.isCancelled()) {
					try {
						byte currentByte = memory.getByte(currentAddr) & 0xFF;

						if (paddingByteSet.contains((byte) currentByte)) {
							// Found first padding byte - check for sequence
							int paddingLength = 1;
							Address sequenceStart = currentAddr;
							Address sequenceEnd = currentAddr;

							Address checkAddr = currentAddr.add(1);
							while (checkAddr <= blockEnd) {
								try {
									byte checkByte = memory.getByte(checkAddr) & 0xFF;
									if (paddingByteSet.contains((byte) checkByte)) {
										paddingLength++;
										sequenceEnd = checkAddr;
										checkAddr = checkAddr.add(1);
									} else {
										break;
									}
								} catch (Exception e) {
									break;
								}
							}

							if (paddingLength >= MIN_PADDING_SEQUENCE) {
								foundCount++;

								// Check for RET before padding if required
								boolean hasRETBefore = true;
								if (REQUIRE_RET_BEFORE_PADDING && sequenceStart.getOffset() > 0) {
									try {
										Address prevAddr = sequenceStart.subtract(1);
										byte prevByte = memory.getByte(prevAddr) & 0xFF;
										hasRETBefore = isRetInstruction(prevByte);
									} catch (Exception e) {
										hasRETBefore = false;
									}
								}

								if (!REQUIRE_RET_BEFORE_PADDING || hasRETBefore) {
									// Try to create function at next address after padding
									Address nextAddr = sequenceEnd.add(1);
									if (nextAddr <= blockEnd) {
										try {
											Function existing = currentProgram.getFunctionManager().getFunctionContaining(nextAddr);
											if (existing == null) {
												currentProgram.getFunctionManager().createFunction(null, nextAddr, null, null);
												createdCount++;
											}
										} catch (Exception e) {
											// Function creation may fail, continue
										}
									}
								}

								currentAddr = sequenceEnd;
							}
						}

						currentAddr = currentAddr.add(1);

					} catch (MemoryAccessException e) {
						currentAddr = currentAddr.add(1);
					}
				}
			}

			println("");
			println("=== Results ===");
			println("Blocks processed: " + processedBlocks);
			println("Padding sequences found: " + foundCount);
			println("Functions created: " + createdCount);
			println("");
			println("Complete!");

		} catch (Exception e) {
			println("ERROR during processing: " + e.getMessage());
			e.printStackTrace();
		}
	}

	private boolean isRetInstruction(byte b) {
		return b == (RET_NEAR & 0xFF) ||
			   b == (RET_NEAR_IMM16 & 0xFF) ||
			   b == (RET_FAR & 0xFF) ||
			   b == (RET_FAR_IMM16 & 0xFF);
	}
}
