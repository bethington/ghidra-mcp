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
// RemoveOrphanedFunctions.java
// Removes functions that don't have proper padding (NOP 0x90 or INT3 0xCC) before them
// Functions created after NULL byte sequences are likely erroneous
// Whitelisted: thunk functions, functions starting with "_", functions in FunctionsTodo.txt
//@author Ben Ethington
//@category Diablo 2

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RemoveOrphanedFunctions extends GhidraScript {

	// Configuration - adjust these thresholds as needed
	private static final boolean DRY_RUN = false;               // Set to false to actually delete
	private static final boolean REQUIRE_NO_XREFS = true;      // Must have zero callers
	private static final int MIN_PADDING_BYTES = 1;            // Minimum padding bytes to look for
	
	// Valid padding bytes - functions should be preceded by these
	private static final byte NOP_BYTE = (byte) 0x90;
	private static final byte INT3_BYTE = (byte) 0xCC;
	
	// Whitelist file - functions at these addresses are protected
	private static final String WHITELIST_FILE = "FunctionsTodo.txt";

	// Set of whitelisted addresses (lowercase hex without 0x prefix)
	private Set<String> whitelistedAddresses;

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("No program loaded!");
			return;
		}

		// Load whitelisted addresses from FunctionsTodo.txt
		whitelistedAddresses = loadWhitelistedAddresses();
		println("Loaded " + whitelistedAddresses.size() + " whitelisted addresses from " + WHITELIST_FILE);

		FunctionManager functionManager = currentProgram.getFunctionManager();
		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		Memory memory = currentProgram.getMemory();

		List<Function> functionsToRemove = new ArrayList<>();
		int totalFunctions = 0;
		int whitelistedCount = 0;
		int checkedCount = 0;
		int orphanedCount = 0;
		int noPaddingCount = 0;

		println("=== RemoveOrphanedFunctions ===");
		println("Configuration:");
		println("  DRY_RUN: " + DRY_RUN);
		println("  REQUIRE_NO_XREFS: " + REQUIRE_NO_XREFS);
		println("  MIN_PADDING_BYTES: " + MIN_PADDING_BYTES);
		println("  Valid padding: 0x90 (NOP) or 0xCC (INT3)");
		println("  Whitelist: thunk functions (except thunk_* prefix), functions starting with '_', addresses in " + WHITELIST_FILE);
		println("");

		monitor.setMessage("Scanning functions...");

		FunctionIterator functions = functionManager.getFunctions(true);
		while (functions.hasNext()) {
			if (monitor.isCancelled()) {
				println("Operation cancelled by user");
				return;
			}

			Function func = functions.next();
			totalFunctions++;

			String name = func.getName();
			Address entryPoint = func.getEntryPoint();
			String addressHex = entryPoint.toString().toLowerCase();

			// Whitelist Check 1: Thunk functions (but NOT those with "thunk_" prefix - those can be evaluated)
			if (func.isThunk() && !name.toLowerCase().startsWith("thunk_")) {
				whitelistedCount++;
				continue;
			}

			// Whitelist Check 2: Functions starting with "_"
			if (name.startsWith("_")) {
				whitelistedCount++;
				continue;
			}

			// Whitelist Check 3: Functions in FunctionsTodo.txt
			if (whitelistedAddresses.contains(addressHex)) {
				whitelistedCount++;
				continue;
			}

			checkedCount++;

			// Check 1: Cross-references (callers) - skip if has real callers
			if (REQUIRE_NO_XREFS) {
				ReferenceIterator refIter = referenceManager.getReferencesTo(entryPoint);
				boolean hasCallers = false;
				while (refIter.hasNext()) {
					Reference ref = refIter.next();
					// Only count CALL references as real callers (not jumps)
					if (ref.getReferenceType().isCall()) {
						hasCallers = true;
						break;
					}
				}
				if (hasCallers) {
					continue;  // Has real CALL references, keep it
				}
				orphanedCount++;
			}

			// Check 2: Look for valid padding (NOP or INT3) before the function
			if (hasValidPadding(memory, entryPoint)) {
				continue;  // Has proper NOP/INT3 padding, keep it
			}
			noPaddingCount++;

			// This function has no valid padding and no callers - mark for removal
			functionsToRemove.add(func);
		}

		println("\n=== Analysis Results ===");
		println("Total functions scanned: " + totalFunctions);
		println("Whitelisted (thunk/_prefix/FunctionsTodo): " + whitelistedCount);
		println("Functions checked: " + checkedCount);
		println("Orphaned (no CALL xrefs): " + orphanedCount);
		println("No valid NOP/INT3 padding: " + noPaddingCount);
		println("Functions matching removal criteria: " + functionsToRemove.size());

		if (functionsToRemove.isEmpty()) {
			println("\nNo functions to remove.");
			return;
		}

		// Show first 30 functions that would be removed
		println("\nFirst " + Math.min(30, functionsToRemove.size()) + " functions to remove:");
		for (int i = 0; i < Math.min(30, functionsToRemove.size()); i++) {
			Function f = functionsToRemove.get(i);
			String paddingInfo = describePaddingBefore(memory, f.getEntryPoint());
			println("  " + f.getName() + " at " + f.getEntryPoint() + " - " + paddingInfo);
		}

		if (DRY_RUN) {
			println("\n*** DRY RUN MODE - No functions were removed ***");
			println("Set DRY_RUN = false in the script to actually remove functions.");
		}
		else {
			println("\nRemoving " + functionsToRemove.size() + " functions...");
			int removedCount = 0;
			for (Function func : functionsToRemove) {
				if (monitor.isCancelled()) {
					println("Operation cancelled. Removed " + removedCount + " functions.");
					return;
				}
				try {
					functionManager.removeFunction(func.getEntryPoint());
					removedCount++;
				}
				catch (Exception e) {
					println("Failed to remove " + func.getName() + ": " + e.getMessage());
				}
			}
			println("Successfully removed " + removedCount + " functions.");
		}

		println("\nDone!");
	}

	/**
	 * Check if the function has valid padding (NOP 0x90 or INT3 0xCC) immediately before it
	 */
	private boolean hasValidPadding(Memory memory, Address entryPoint) {
		try {
			// Look at bytes immediately before the function entry
			for (int offset = 1; offset <= MIN_PADDING_BYTES; offset++) {
				Address checkAddr = entryPoint.subtract(offset);
				if (!memory.contains(checkAddr)) {
					return false;  // Can't read before this address
				}
				
				byte b = memory.getByte(checkAddr);
				// Must be NOP (0x90) or INT3 (0xCC) to count as valid padding
				if (b != NOP_BYTE && b != INT3_BYTE) {
					return false;  // Not valid padding
				}
			}
			return true;  // All checked bytes are valid padding
			
		}
		catch (MemoryAccessException e) {
			return false;  // Can't read memory, consider it invalid
		}
	}

	/**
	 * Describe what padding exists before the function for logging
	 */
	private String describePaddingBefore(Memory memory, Address entryPoint) {
		try {
			StringBuilder sb = new StringBuilder("preceded by: ");
			for (int offset = 1; offset <= 4; offset++) {
				Address checkAddr = entryPoint.subtract(offset);
				if (!memory.contains(checkAddr)) {
					break;
				}
				byte b = memory.getByte(checkAddr);
				int unsigned = b & 0xFF;
				if (offset > 1) sb.append(" ");
				sb.append(String.format("%02X", unsigned));
			}
			return sb.toString();
		}
		catch (MemoryAccessException e) {
			return "can't read memory";
		}
	}

	/**
	 * Load whitelisted function addresses from FunctionsTodo.txt
	 * Extracts addresses in format "@ xxxxxxxx" (hex addresses)
	 */
	private Set<String> loadWhitelistedAddresses() {
		Set<String> addresses = new HashSet<>();
		
		// Try to find FunctionsTodo.txt in the script's directory or workspace
		File scriptDir = getSourceFile().getParentFile().getFile(false);
		File whitelistFile = new File(scriptDir.getParentFile(), WHITELIST_FILE);
		
		if (!whitelistFile.exists()) {
			// Try current working directory
			whitelistFile = new File(WHITELIST_FILE);
		}
		
		if (!whitelistFile.exists()) {
			println("Warning: " + WHITELIST_FILE + " not found. No address whitelist loaded.");
			println("  Searched: " + scriptDir.getParentFile().getAbsolutePath());
			return addresses;
		}
		
		println("Loading whitelist from: " + whitelistFile.getAbsolutePath());
		
		// Pattern to match "@ xxxxxxxx" (hex address)
		Pattern addressPattern = Pattern.compile("@\\s*([0-9a-fA-F]+)");
		
		try (BufferedReader reader = new BufferedReader(new FileReader(whitelistFile))) {
			String line;
			while ((line = reader.readLine()) != null) {
				Matcher matcher = addressPattern.matcher(line);
				while (matcher.find()) {
					String addr = matcher.group(1).toLowerCase();
					addresses.add(addr);
				}
			}
		}
		catch (Exception e) {
			println("Error reading " + WHITELIST_FILE + ": " + e.getMessage());
		}
		
		return addresses;
	}

}
