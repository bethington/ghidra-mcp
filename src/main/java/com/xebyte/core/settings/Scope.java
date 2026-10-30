package com.xebyte.core.settings;

import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * Where a setting's value comes from, lowest precedence first. Scope is never part of a key:
 * {@code tools.autoload} is one key that can be set at any scope its registry entry allows.
 */
public enum Scope {
    /** The registry's default. */
    DEFAULT("default"),
    /** The server process's environment ({@code GHIDRA_MCP_<KEY>}): the operator's scope. */
    SERVER("server"),
    /** The project's {@code /.ghidra-mcp} archive; versioned with a shared project. */
    PROJECT("project"),
    /** This machine's copy of the project; never leaves it. */
    LOCAL("local"),
    /** One program's options. */
    PROGRAM("program"),
    /** One bridge session (its flags and environment); resolved by the bridge. */
    SESSION("session"),
    /** One tool call's own argument. */
    CALL("call");

    private final String wireName;

    Scope(String wireName) {
        this.wireName = wireName;
    }

    public String wireName() {
        return wireName;
    }

    public static Scope parse(String name) {
        for (Scope s : values()) {
            if (s.wireName.equalsIgnoreCase(name.trim())) {
                return s;
            }
        }
        throw new SettingRefusedException("Unknown scope '" + name + "'. Scopes: " + names() + ".");
    }

    public static String names() {
        return Arrays.stream(values()).map(Scope::wireName).collect(Collectors.joining(", "));
    }
}
