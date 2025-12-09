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
//Properly sizes all string data types to include null terminators and padding
//Clears undefined bytes after strings and reapplies string data type with full size
//@category Strings

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.DefinedStringIterator;

public class ProperSizeStringsScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			printerr("No program is currently open.");
			return;
		}

		Memory memory = currentProgram.getMemory();
		int processedCount = 0;
		int resizedCount = 0;

		monitor.initialize(currentProgram.getListing().getNumDefinedData());
		monitor.setMessage("Resizing strings to proper size");

		for (Data data : DefinedStringIterator.forProgram(currentProgram, currentSelection)) {
			if (monitor.isCancelled()) {
				println("Operation cancelled by user.");
				break;
			}

			try {
				StringDataInstance strInstance = StringDataInstance.getStringDataInstance(data);
				if (strInstance == null) {
					monitor.incrementProgress(1);
					continue;
				}

				Address startAddress = data.getAddress();
				
				// Get the actual data length including null terminator
				int dataLength = strInstance.getDataLength(); // includes null terminator
				
				// Calculate the full size including any padding bytes
				int fullSize = calculateFullStringSize(memory, startAddress, dataLength);
				
				if (fullSize >= data.getLength()) {
					// Need to resize or reapply - clear the existing data and apply with correct size
					Address endAddress = startAddress.add(fullSize - 1);
					
					// Clear the listing for the full range
					clearListing(startAddress, endAddress);
					
					// Create a fixed-length string by creating a char array
					DataType charType = new CharDataType();
					DataType arrayType = new ArrayDataType(charType, fullSize, charType.getLength());
					
					// Apply the char array (which Ghidra will display as a string)
					createData(startAddress, arrayType);
					
					resizedCount++;
					println("Resized string at " + startAddress + " from " + data.getLength() + 
							" to " + fullSize + " bytes: \"" + strInstance.getStringValue() + "\"");
				}
				
				processedCount++;
				monitor.incrementProgress(1);
				
			} catch (Exception e) {
				printerr("Error processing string at " + data.getAddress() + ": " + e.getMessage());
			}
		}
		
		println("\n=== Summary ===");
		println("Strings processed: " + processedCount);
		println("Strings resized: " + resizedCount);
		println("Done!");
	}

	/**
	 * Calculate the full size of a string including null terminator and any padding bytes
	 * (consecutive 0x00 bytes after the string)
	 */
	private int calculateFullStringSize(Memory memory, Address startAddress, int baseLength) {
		int fullSize = baseLength;
		Address currentAddr = startAddress.add(baseLength);
		
		try {
			// Look ahead for consecutive null bytes (padding)
			while (memory.contains(currentAddr)) {
				byte b = memory.getByte(currentAddr);
				if (b == 0x00) {
					fullSize++;
					currentAddr = currentAddr.add(1);
				} else {
					// Hit a non-null byte, stop
					break;
				}
			}
		} catch (MemoryAccessException e) {
			// End of memory or inaccessible, return what we have
		}
		
		return fullSize;
	}

}
