package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.Locale;

/**
 * How an address is spelled wherever it is a key or a value an agent reads: bare lowercase
 * hex in the program's default space, {@code <space>:<hex>} in any other.
 *
 * <p>Bare hex alone collides as soon as a program has a second space: an overlay function at
 * {@code 0x1000} and the default-space function at {@code 0x1000} are two functions with one
 * spelling. The default space stays bare, so a single-space program reads exactly as plain
 * hex. {@link ServiceUtils#parseAddress} reads both forms. {@code get_functions}, the
 * decompilation checkout and {@code ghidra://function} URIs all use this rule, so they agree.
 */
public final class AddressKeys {

    private AddressKeys() {
    }

    /** {@code a}'s key in {@code program}; bare hex when there is no program to ask. */
    public static String of(Address a, Program program) {
        String hex = a.toString(false);
        if (program == null) {
            return hex;
        }
        return a.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())
                ? hex : a.getAddressSpace().getName() + ":" + hex;
    }

    /**
     * An address for reading and grepping: {@code 0x}-prefixed in the default space, the
     * qualified key in any other ({@code ovl1:00001000}).
     */
    public static String display(Address a, Program program) {
        String key = of(a, program);
        return key.indexOf(':') >= 0 ? key : "0x" + key;
    }

    /** {@code func}'s entry key. */
    public static String of(Function func) {
        return of(func.getEntryPoint(), func.getProgram());
    }

    /**
     * A key in canonical form: lowercase hex without {@code 0x}, the space prefix kept. For an
     * address typed by a caller ({@code ram:0x1000} in a single-space program) use
     * {@link #canonical}, which knows which space is the default.
     */
    public static String normalize(String raw) {
        if (raw == null) {
            return "";
        }
        String t = raw.trim();
        int colon = t.lastIndexOf(':');
        String space = colon >= 0 ? t.substring(0, colon) : "";
        String hex = colon >= 0 ? t.substring(colon + 1) : t;
        if (hex.startsWith("0x") || hex.startsWith("0X")) {
            hex = hex.substring(2);
        }
        hex = hex.toLowerCase(Locale.ROOT);
        return space.isEmpty() ? hex : space + ":" + hex;
    }

    /** A caller's address in {@code program}'s key form; {@link #normalize} when it does not parse. */
    public static String canonical(Program program, String raw) {
        Address a = raw == null ? null : ServiceUtils.parseAddress(program, raw.trim());
        return a != null ? of(a, program) : normalize(raw);
    }

    /** The space part of a key, empty for the default space. */
    public static String space(String key) {
        String k = normalize(key);
        int colon = k.lastIndexOf(':');
        return colon >= 0 ? k.substring(0, colon) : "";
    }

    /** The offset part of a key, 0 when it does not parse. */
    public static long offset(String key) {
        String k = normalize(key);
        String hex = k.substring(k.lastIndexOf(':') + 1);
        if (hex.isEmpty()) {
            return 0L;
        }
        try {
            return Long.parseUnsignedLong(hex, 16);
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    /** The function at the key's address, else the one containing it. */
    public static Function function(Program program, String key) {
        Address addr = ServiceUtils.parseAddress(program, key);
        if (addr == null) {
            return null;
        }
        Function at = program.getFunctionManager().getFunctionAt(addr);
        return at != null ? at : program.getFunctionManager().getFunctionContaining(addr);
    }
}
