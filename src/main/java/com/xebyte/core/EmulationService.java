package com.xebyte.core;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Register;
import ghidra.util.Msg;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/**
 * MCP endpoints for targeted function emulation via Ghidra's P-code emulator.
 *
 * <p>Designed for API hash resolution: emulate a hash function with controlled
 * inputs (candidate API name string in memory, hash parameters in registers)
 * and read the computed hash from the output register. No full process needed —
 * the emulator runs the function's P-code in isolation.</p>
 *
 * <h3>Typical agent workflow for API hash resolution</h3>
 * <pre>{@code
 * 1. decompile_function(hash_func_addr) → understand calling convention
 * 2. get_function_variables(hash_func) → identify input/output registers
 * 3. emulate_function(hash_func_addr, registers={ECX: string_ptr},
 *        memory=[{addr: string_ptr, data: "CreateProcessW\0"}])
 *    → returns {EAX: 0x7C0DFCAA}
 * 4. Compare 0x7C0DFCAA against target hash → match!
 * 5. batch_set_comments(hash_call_addr, "Resolved: CreateProcessW")
 * }</pre>
 *
 * <h3>Batch mode for brute-forcing</h3>
 * <pre>{@code
 * emulate_hash_batch(hash_func_addr, register_template={ECX: "${STRING_PTR}"},
 *     candidates=["CreateProcessW", "VirtualAlloc", "LoadLibraryA", ...],
 *     target_hash=0x7C0DFCAA, result_register="EAX")
 *   → returns {matched: "CreateProcessW", hash: 0x7C0DFCAA, iterations: 42}
 * }</pre>
 *
 * @since 5.4.0
 */
@McpToolGroup(value = "emulation",
        description = "Targeted function emulation for hash resolution, crypto analysis, " +
                "and controlled execution of isolated code paths")
public class EmulationService {

    private static final int DEFAULT_TIMEOUT_MS = 10_000;
    private static final int MAX_STEPS = 100_000;
    private static final int MAX_CANDIDATES = 10_000;
    // Scratch memory for writing candidate strings during emulation
    private static final long SCRATCH_BASE = 0x7FFE0000L;
    private static final int SCRATCH_SIZE = 0x10000;

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public EmulationService(ProgramProvider programProvider,
                            ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // ========================================================================
    // Single-function emulation
    // ========================================================================

    /**
     * Emulate a function with controlled inputs and return the final state.
     *
     * <p>Sets up the P-code emulator with the specified register values and
     * memory contents, runs the function until RET or step limit, and returns
     * all register values at completion.</p>
     */
    @McpTool(path = "/emulate_function", method = "POST",
            description = "Emulate a single function with controlled register/memory inputs. " +
                    "Returns final register state after execution. Ideal for understanding " +
                    "hash functions, crypto routines, or any pure-computation code path.",
            category = "emulation")
    public Response emulateFunction(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                    description = "Entry point address of the function to emulate") String addressStr,
            @Param(value = "registers", source = ParamSource.BODY, fieldsJson = true,
                    description = "Initial register values as JSON: {\"EAX\": \"0x1234\", \"ECX\": \"0x7FFE0000\"}") String registersJson,
            @Param(value = "memory", source = ParamSource.BODY, fieldsJson = true,
                    description = "Memory regions to pre-populate as JSON array: [{\"address\": \"0x7FFE0000\", \"data\": \"base64...\"}] " +
                            "or [{\"address\": \"0x7FFE0000\", \"string\": \"CreateProcessW\\u0000\"}]") String memoryJson,
            @Param(value = "max_steps", source = ParamSource.BODY, defaultValue = "10000",
                    description = "Maximum P-code steps before timeout") int maxSteps,
            @Param(value = "return_registers", source = ParamSource.BODY, defaultValue = "",
                    description = "Comma-separated register names to return (empty = all general-purpose)") String returnRegisters,
            @Param(value = "program", defaultValue = "") String programName) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address entryAddr = ServiceUtils.parseAddress(program, addressStr);
        if (entryAddr == null) return Response.err(ServiceUtils.getLastParseError());

        Function func = program.getFunctionManager().getFunctionAt(entryAddr);
        if (func == null) return Response.err("No function at address: " + addressStr);

        try {
            EmulatorHelper emu = new EmulatorHelper(program);
            try {
                // Set up stack pointer
                Address stackAddr = program.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(0x7FFF0000L);
                emu.writeRegister("ESP", stackAddr.getOffset());
                emu.writeRegister("EBP", stackAddr.getOffset());

                // Write a return address to the stack (so RET has somewhere to go)
                long returnSentinel = 0xDEADBEEFL;
                byte[] retAddrBytes = ByteBuffer.allocate(4)
                        .order(ByteOrder.LITTLE_ENDIAN)
                        .putInt((int) returnSentinel).array();
                emu.writeMemory(stackAddr, retAddrBytes);

                // Apply user-specified register values
                if (registersJson != null && !registersJson.isEmpty()) {
                    Map<String, Object> regs = JsonHelper.parseJson(registersJson);
                    for (Map.Entry<String, Object> entry : regs.entrySet()) {
                        String regName = entry.getKey();
                        long value = parseLongValue(String.valueOf(entry.getValue()));
                        emu.writeRegister(regName, value);
                    }
                }

                // Apply user-specified memory contents
                if (memoryJson != null && !memoryJson.isEmpty()) {
                    List<Map<String, String>> regions = ServiceUtils.convertToMapList(
                            JsonHelper.parseJson(memoryJson).get("regions"));
                    if (regions == null) {
                        // Try parsing as a direct array
                        regions = ServiceUtils.convertToMapList(memoryJson);
                    }
                    if (regions != null) {
                        for (Map<String, String> region : regions) {
                            String addrStr = String.valueOf(region.get("address"));
                            Address memAddr = ServiceUtils.parseAddress(program, addrStr);
                            if (memAddr == null) continue;

                            if (region.containsKey("string")) {
                                // Write a null-terminated string
                                String str = String.valueOf(region.get("string"));
                                byte[] strBytes = (str + "\0").getBytes("UTF-8");
                                emu.writeMemory(memAddr, strBytes);
                            } else if (region.containsKey("data")) {
                                // Write base64-encoded bytes
                                String b64 = String.valueOf(region.get("data"));
                                byte[] data = Base64.getDecoder().decode(b64);
                                emu.writeMemory(memAddr, data);
                            } else if (region.containsKey("hex")) {
                                // Write hex-encoded bytes
                                String hex = String.valueOf(region.get("hex"));
                                byte[] data = hexToBytes(hex);
                                emu.writeMemory(memAddr, data);
                            }
                        }
                    }
                }

                // Run emulation
                int effectiveMaxSteps = Math.min(maxSteps, MAX_STEPS);
                emu.setBreakpoint(program.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(returnSentinel));

                boolean success = emu.run(entryAddr, null, new ghidra.util.task.ConsoleTaskMonitor());

                // Collect results
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", success);
                result.put("function", func.getName());
                result.put("entry_address", entryAddr.toString());

                Address pc = emu.getExecutionAddress();
                result.put("final_pc", pc != null ? pc.toString() : "unknown");
                result.put("hit_return", pc != null && pc.getOffset() == returnSentinel);

                // Read registers
                Map<String, String> regValues = new LinkedHashMap<>();
                if (returnRegisters != null && !returnRegisters.isEmpty()) {
                    for (String rn : returnRegisters.split(",")) {
                        rn = rn.trim();
                        try {
                            BigInteger val = emu.readRegister(rn);
                            regValues.put(rn, "0x" + val.toString(16));
                        } catch (Exception e) {
                            regValues.put(rn, "error: " + e.getMessage());
                        }
                    }
                } else {
                    // Return common general-purpose registers
                    for (String rn : new String[]{"EAX", "EBX", "ECX", "EDX",
                            "ESI", "EDI", "ESP", "EBP", "EIP"}) {
                        try {
                            BigInteger val = emu.readRegister(rn);
                            regValues.put(rn, "0x" + val.toString(16));
                        } catch (Exception ignored) {
                            // Register may not exist for this architecture
                        }
                    }
                }
                result.put("registers", regValues);

                String lastError = emu.getLastError();
                if (lastError != null && !lastError.isEmpty()) {
                    result.put("emulation_error", lastError);
                }

                return Response.ok(result);
            } finally {
                emu.dispose();
            }
        } catch (Exception e) {
            return Response.err("Emulation failed: " + e.getMessage());
        }
    }

    // ========================================================================
    // Batch hash resolution
    // ========================================================================

    /**
     * Brute-force API hash resolution by emulating a hash function with
     * a list of candidate API name strings.
     *
     * <p>For each candidate, writes the string to scratch memory, sets the
     * string pointer register, emulates the hash function, reads the result
     * register, and compares against the target hash. Stops on first match
     * or after exhausting all candidates.</p>
     */
    @McpTool(path = "/emulate_hash_batch", method = "POST",
            description = "Brute-force API hash resolution. Emulates a hash function with " +
                    "each candidate API name and returns the one that produces the target hash. " +
                    "Ideal for resolving ROR13, CRC32, djb2, FNV, and custom hash algorithms.",
            category = "emulation")
    public Response emulateHashBatch(
            @Param(value = "hash_function_address", paramType = "address", source = ParamSource.BODY,
                    description = "Address of the hash computation function") String hashFuncAddr,
            @Param(value = "string_register", source = ParamSource.BODY,
                    description = "Register that receives the pointer to the API name string (e.g., ECX, RCX, EDI)") String stringRegister,
            @Param(value = "result_register", source = ParamSource.BODY, defaultValue = "EAX",
                    description = "Register that contains the computed hash after emulation (e.g., EAX, RAX)") String resultRegister,
            @Param(value = "target_hash", source = ParamSource.BODY,
                    description = "Target hash value to match (hex string like 0x7C0DFCAA)") String targetHashStr,
            @Param(value = "candidates", source = ParamSource.BODY, fieldsJson = true,
                    description = "JSON array of candidate API name strings: [\"CreateProcessW\", \"VirtualAlloc\", ...]") String candidatesJson,
            @Param(value = "initial_registers", source = ParamSource.BODY, fieldsJson = true, defaultValue = "",
                    description = "Additional register values to set before each emulation (JSON object)") String initialRegistersJson,
            @Param(value = "wide_string", source = ParamSource.BODY, defaultValue = "false",
                    description = "Write candidate strings as UTF-16LE (wide) instead of ASCII") boolean wideString,
            @Param(value = "program", defaultValue = "") String programName) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address entryAddr = ServiceUtils.parseAddress(program, hashFuncAddr);
        if (entryAddr == null) return Response.err(ServiceUtils.getLastParseError());

        Function func = program.getFunctionManager().getFunctionAt(entryAddr);
        if (func == null) return Response.err("No function at address: " + hashFuncAddr);

        long targetHash;
        try {
            targetHash = parseLongValue(targetHashStr);
        } catch (Exception e) {
            return Response.err("Invalid target_hash: " + targetHashStr);
        }

        // Parse candidates
        List<String> candidates = new ArrayList<>();
        if (candidatesJson != null && !candidatesJson.isEmpty()) {
            try {
                Object parsed = JsonHelper.parseJson("{\"c\":" + candidatesJson + "}").get("c");
                if (parsed instanceof List<?> list) {
                    for (Object item : list) {
                        candidates.add(String.valueOf(item));
                    }
                }
            } catch (Exception e) {
                return Response.err("Invalid candidates JSON: " + e.getMessage());
            }
        }
        if (candidates.isEmpty()) {
            return Response.err("No candidates provided");
        }
        if (candidates.size() > MAX_CANDIDATES) {
            return Response.err("Too many candidates (max " + MAX_CANDIDATES + ")");
        }

        // Parse additional registers
        Map<String, Long> extraRegs = new LinkedHashMap<>();
        if (initialRegistersJson != null && !initialRegistersJson.isEmpty()) {
            Map<String, Object> parsed = JsonHelper.parseJson(initialRegistersJson);
            for (Map.Entry<String, Object> entry : parsed.entrySet()) {
                extraRegs.put(entry.getKey(), parseLongValue(String.valueOf(entry.getValue())));
            }
        }

        try {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("function", func.getName());
            result.put("target_hash", "0x" + Long.toHexString(targetHash));
            result.put("total_candidates", candidates.size());

            Address scratchAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(SCRATCH_BASE);
            Address stackAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(0x7FFF0000L);
            long returnSentinel = 0xDEADBEEFL;

            List<Map<String, String>> matches = new ArrayList<>();
            int tested = 0;

            for (String candidate : candidates) {
                tested++;
                EmulatorHelper emu = new EmulatorHelper(program);
                try {
                    // Set up stack
                    emu.writeRegister("ESP", stackAddr.getOffset());
                    emu.writeRegister("EBP", stackAddr.getOffset());
                    byte[] retBytes = ByteBuffer.allocate(4)
                            .order(ByteOrder.LITTLE_ENDIAN)
                            .putInt((int) returnSentinel).array();
                    emu.writeMemory(stackAddr, retBytes);

                    // Write candidate string to scratch memory
                    byte[] strBytes;
                    if (wideString) {
                        strBytes = (candidate + "\0").getBytes("UTF-16LE");
                    } else {
                        strBytes = (candidate + "\0").getBytes("US-ASCII");
                    }
                    emu.writeMemory(scratchAddr, strBytes);

                    // Set string pointer register
                    emu.writeRegister(stringRegister, SCRATCH_BASE);

                    // Set additional registers
                    for (Map.Entry<String, Long> entry : extraRegs.entrySet()) {
                        emu.writeRegister(entry.getKey(), entry.getValue());
                    }

                    // Set breakpoint at return sentinel
                    emu.setBreakpoint(program.getAddressFactory()
                            .getDefaultAddressSpace().getAddress(returnSentinel));

                    // Run
                    emu.run(entryAddr, null, new ghidra.util.task.ConsoleTaskMonitor());

                    // Read result register
                    BigInteger hashResult = emu.readRegister(resultRegister);
                    long computedHash = hashResult.longValue() & 0xFFFFFFFFL; // mask to 32-bit

                    if (computedHash == (targetHash & 0xFFFFFFFFL)) {
                        Map<String, String> match = new LinkedHashMap<>();
                        match.put("api_name", candidate);
                        match.put("computed_hash", "0x" + Long.toHexString(computedHash));
                        match.put("iteration", String.valueOf(tested));
                        matches.add(match);
                        // Continue to find ALL matches (some hash functions have collisions)
                    }
                } finally {
                    emu.dispose();
                }
            }

            result.put("tested", tested);
            result.put("matches", matches);
            result.put("resolved", !matches.isEmpty());
            if (!matches.isEmpty()) {
                result.put("best_match", matches.get(0).get("api_name"));
            }

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("Batch emulation failed: " + e.getMessage());
        }
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private static long parseLongValue(String s) {
        if (s == null || s.isEmpty()) return 0;
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return Long.parseUnsignedLong(s.substring(2), 16);
        }
        return Long.parseLong(s);
    }

    private static byte[] hexToBytes(String hex) {
        hex = hex.replace(" ", "").replace("0x", "");
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
