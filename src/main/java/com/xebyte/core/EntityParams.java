package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.Set;

/**
 * Tool parameters typed as Ghidra entities: {@code Program}, {@code Address} and
 * {@code Function}. A tool declares {@code @Param("program") Program program} or
 * {@code @Param("address") Address address}; the scanner reads the caller's string
 * as for any parameter and this resolves it before the tool runs, refusing with the message the
 * tool used to produce itself. The program resolves first, since the others are looked up in it.
 *
 * <p>Resolution is per call, through the server's {@link ProgramProvider}, so a program opened
 * after startup is found like any other.
 */
final class EntityParams {

    private static final Set<Class<?>> ENTITY_TYPES =
        Set.of(Program.class, Address.class, Function.class);

    private EntityParams() {}

    static boolean isEntity(Class<?> type) {
        return ENTITY_TYPES.contains(type);
    }

    /**
     * Replace each entity argument's raw string with the entity, or throw a {@link Refusal}.
     *
     * @return the function the call acts on when exactly one Function parameter resolved, else null
     */
    static Function resolve(AnnotationScanner.ParamBinding[] bindings, Object[] args, ProgramProvider provider) {
        Program program = null;
        boolean needsProgram = false;
        for (int i = 0; i < bindings.length; i++) {
            if (bindings[i] == null || !isEntity(bindings[i].javaType())) {
                continue;
            }
            if (bindings[i].javaType() == Program.class) {
                program = ServiceUtils.requireProgram(provider, text(args[i]));
                args[i] = program;
            } else {
                needsProgram = true;
            }
        }
        if (!needsProgram) {
            return null;
        }
        if (program == null) {
            program = ServiceUtils.requireProgram(provider, null);
        }
        for (int i = 0; i < bindings.length; i++) {
            AnnotationScanner.ParamBinding b = bindings[i];
            if (b == null || !isEntity(b.javaType()) || b.javaType() == Program.class) {
                continue;
            }
            String raw = text(args[i]);
            if (raw == null || raw.isBlank()) {
                if (Param.NO_DEFAULT.equals(b.param().defaultValue())) {
                    throw new Refusal(b.param().value() + " is required");
                }
                args[i] = null;
                continue;
            }
            args[i] = entity(b.javaType(), raw.trim(), program);
        }
        Function only = null;
        for (int i = 0; i < bindings.length; i++) {
            if (bindings[i] != null && bindings[i].javaType() == Function.class && args[i] != null) {
                if (only != null) {
                    return null;
                }
                only = (Function) args[i];
            }
        }
        return only;
    }

    private static Object entity(Class<?> type, String raw, Program program) {
        if (type == Address.class) {
            Address address = ServiceUtils.parseAddress(program, raw);
            if (address == null) {
                throw new Refusal(ServiceUtils.getLastParseError());
            }
            return address;
        }
        ServiceUtils.FunctionOrError found = ServiceUtils.getFunctionOrError(program, raw);
        if (found.function() == null) {
            throw new Refusal(found.message());
        }
        return found.function();
    }

    private static String text(Object raw) {
        return raw == null ? null : String.valueOf(raw);
    }
}
