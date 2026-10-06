package com.xebyte.core;

import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import java.util.*;
import java.util.concurrent.Callable;

@McpToolGroup(value = "function", description = "Calling convention, stack-depth and localized call prototype overrides")
public class OverrideService {
    private final ProgramProvider provider;
    private final ThreadingStrategy threading;

    public OverrideService(ProgramProvider provider, ThreadingStrategy threading) {
        this.provider = provider;
        this.threading = threading;
    }

    private Response execute(String programName, String transaction, Operation operation) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(provider, programName);
        if (pe.hasError()) return pe.error();
        try {
            Callable<Response> action = () -> Response.ok(operation.apply(pe.program()));
            return transaction == null ? threading.executeRead(action)
                : threading.executeWrite(pe.program(), transaction, action);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    @FunctionalInterface
    private interface Operation { Object apply(Program program) throws Exception; }

    static Address requireAddress(Program program, String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Address is required");
        Address address = ServiceUtils.parseAddress(program, value);
        if (address == null) throw new IllegalArgumentException(ServiceUtils.getLastParseError());
        return address;
    }

    static String resolveConvention(Program program, String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Calling convention is required");
        Set<String> names = new TreeSet<>();
        names.add(CompilerSpec.CALLING_CONVENTION_default);
        for (PrototypeModel model : program.getCompilerSpec().getCallingConventions()) names.add(model.getName());
        String name = value.trim();
        if (names.contains(name)) return name;
        for (String candidate : names) {
            if (candidate.equalsIgnoreCase(name) || candidate.equalsIgnoreCase("__" + name)) return candidate;
        }
        throw new IllegalArgumentException("Unsupported calling convention '" + name + "'; supported: " + names);
    }

    @McpTool(path = "/set_function_calling_convention", method = "POST", description = "Change only a function's calling convention at its exact entry address. Preserves its prototype and custom variable storage; Ghidra recomputes dynamic storage and implicit parameters. Accepts default and unprefixed aliases; call-site overrides are unchanged.", category = "function", access = ToolAccess.WRITE)
    public Response setFunctionCallingConvention(
            @Param(value = "function_address", source = ParamSource.BODY, paramType = "address", description = "Exact function entry address, optionally space-qualified") String address,
            @Param(value = "calling_convention", source = ParamSource.BODY, description = "Supported convention from list_calling_conventions, default, or an unprefixed alias") String convention,
            @Param(value = "program", defaultValue = "", description = "Target program name") String programName) {
        return execute(programName, "Set function calling convention", program -> {
            Address entry = requireAddress(program, address);
            Function function = program.getFunctionManager().getFunctionAt(entry);
            if (function == null) throw new IllegalArgumentException("No function at entry address " + entry);
            function.setCallingConvention(resolveConvention(program, convention));
            return JsonHelper.mapOf("status", "success", "address", entry.toString(),
                "calling_convention", function.getCallingConventionName(),
                "custom_storage_enabled", function.hasCustomVariableStorage());
        });
    }

    @McpTool(path = "/get_stack_depth_change", description = "Read an explicit instruction stack-depth override, not inferred depth or callee stack purge. has_override=false means none exists.", category = "function", access = ToolAccess.READ_ONLY)
    public Response getStackDepthChange(
            @Param(value = "address", paramType = "address", description = "Instruction address; stale overrides can also be inspected") String address,
            @Param(value = "program", defaultValue = "", description = "Target program name") String programName) {
        return execute(programName, null, program -> {
            Address at = requireAddress(program, address);
            Integer change = CallDepthChangeInfo.getStackDepthChange(program, at);
            return JsonHelper.mapOf("address", at.toString(), "has_override", change != null, "stack_depth_change", change);
        });
    }

    @McpTool(path = "/set_stack_depth_change", method = "POST", description = "Set an explicit signed 32-bit stack-pointer byte delta at an exact instruction address. Zero is a valid override; this is not an absolute stack depth.", category = "function", access = ToolAccess.WRITE)
    public Response setStackDepthChange(
            @Param(value = "address", source = ParamSource.BODY, paramType = "address", description = "Exact instruction address") String address,
            @Param(value = "stack_depth_change", source = ParamSource.BODY, description = "Signed 32-bit byte delta, including zero") int change,
            @Param(value = "program", defaultValue = "", description = "Target program name") String programName) {
        return execute(programName, "Set stack depth change", program -> {
            Address at = requireAddress(program, address);
            if (program.getListing().getInstructionAt(at) == null) throw new IllegalArgumentException("No instruction at " + at);
            CallDepthChangeInfo.setStackDepthChange(program, at, change);
            return JsonHelper.mapOf("status", "success", "address", at.toString(), "stack_depth_change", change);
        });
    }

    @McpTool(path = "/remove_stack_depth_change", method = "POST", description = "Remove an explicit stack-depth override, restoring inferred behavior. Also removes stale overrides after an instruction has been cleared.", category = "function", access = ToolAccess.WRITE)
    public Response removeStackDepthChange(
            @Param(value = "address", source = ParamSource.BODY, paramType = "address", description = "Address of the override, including a cleared instruction") String address,
            @Param(value = "program", defaultValue = "", description = "Target program name") String programName) {
        return execute(programName, "Remove stack depth change", program -> {
            Address at = requireAddress(program, address);
            boolean removed = CallDepthChangeInfo.removeStackDepthChange(program, at);
            return JsonHelper.mapOf("status", "success", "address", at.toString(), "removed", removed);
        });
    }

    static Function requireCaller(Program program, Address address) {
        Instruction instruction = program.getListing().getInstructionAt(address);
        if (instruction == null) throw new IllegalArgumentException("No instruction at call_address " + address);
        boolean call = instruction.getFlowType().isCall();
        if (!call) {
            for (PcodeOp op : instruction.getPcode()) {
                if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) { call = true; break; }
            }
        }
        if (!call) throw new IllegalArgumentException("Instruction is not a call at " + address);
        Function caller = program.getFunctionManager().getFunctionContaining(address);
        if (caller == null) throw new IllegalArgumentException("No caller containing " + address);
        return caller;
    }

    static DataTypeSymbol findOverride(Function caller, Address address) {
        Namespace space = HighFunction.findOverrideSpace(caller);
        if (space == null) return null;
        for (Symbol symbol : caller.getProgram().getSymbolTable().getSymbols(address)) {
            if (symbol.getSymbolType() != SymbolType.LABEL || !space.equals(symbol.getParentNamespace())
                    || !symbol.getName().startsWith("prt_")) continue;
            DataTypeSymbol override = HighFunctionDBUtil.readOverride(symbol);
            if (override != null) return override;
        }
        return null;
    }

    @McpTool(path = "/get_call_site_prototype", description = "Read a localized prototype override at an exact direct/indirect CALL instruction, not the callee entry or its normal signature.", category = "function", access = ToolAccess.READ_ONLY)
    public Response getCallSitePrototype(
            @Param(value = "call_address", paramType = "address", description = "Exact CALL instruction address") String address,
            @Param(value = "program", defaultValue = "", description = "Target program name") String programName) {
        return execute(programName, null, program -> {
            Address at = requireAddress(program, address);
            Function caller = requireCaller(program, at);
            DataTypeSymbol override = findOverride(caller, at);
            Map<String, Object> out = JsonHelper.mapOf("call_address", at.toString(), "caller", caller.getName(), "has_override", override != null);
            if (override != null) out.put("prototype", ((ghidra.program.model.listing.FunctionSignature) override.getDataType()).getPrototypeString(true));
            return out;
        });
    }

    @McpTool(path = "/set_call_site_prototype", method = "POST", description = "Set/replace a prototype override for ONE direct or indirect CALL. The declaration name is a placeholder, not a rename. Caller/callee signatures and other call sites remain unchanged.", category = "function", access = ToolAccess.WRITE)
    public Response setCallSitePrototype(
            @Param(value = "call_address", source = ParamSource.BODY, paramType = "address", description = "Exact CALL instruction address, not callee entry") String address,
            @Param(value = "prototype", source = ParamSource.BODY, description = "Full C declaration, with optional calling convention and varargs") String prototype,
            @Param(value = "program", defaultValue = "", description = "Target program name") String programName) {
        return execute(programName, "Set call-site prototype", program -> {
            if (prototype == null || prototype.isBlank()) throw new IllegalArgumentException("Prototype is required");
            Address at = requireAddress(program, address);
            Function caller = requireCaller(program, at);
            String[] parts = FunctionService.extractCallingConvention(prototype);
            // The non-interactive parser searches the program manager, which may not
            // contain unused built-ins yet (notably void in a freshly imported binary).
            for (String builtin : List.of("void", "char", "short", "int", "long", "float", "double")) {
                program.getDataTypeManager().resolve(ServiceUtils.resolveDataType(program.getDataTypeManager(), builtin),
                    ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);
            }
            FunctionDefinitionDataType signature = new FunctionSignatureParser(program.getDataTypeManager(), null).parse(null, parts[1]);
            if (signature == null) throw new IllegalArgumentException("Failed to parse prototype");
            if (!parts[0].isEmpty()) signature.setCallingConvention(resolveConvention(program, parts[0]));
            DataTypeSymbol previous = findOverride(caller, at);
            // Match Ghidra's Edit Signature Override: older versions do not replace the old symbol.
            if (previous != null && !previous.getSymbol().delete()) throw new IllegalArgumentException("Could not remove previous override");
            HighFunctionDBUtil.writeOverride(caller, at, signature);
            if (previous != null) previous.cleanupUnusedOverride();
            return JsonHelper.mapOf("status", "success", "call_address", at.toString(), "caller", caller.getName(), "prototype", signature.getPrototypeString(true));
        });
    }
}
