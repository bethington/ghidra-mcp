package com.xebyte.core;

import java.lang.annotation.*;

/**
 * Marks a service method as an MCP tool endpoint.
 * Used by {@link AnnotationScanner} to discover endpoints via reflection
 * and generate JSON schemas for dynamic tool discovery.
 *
 * <p>Example:
 * <pre>{@code
 * @McpTool(path = "/find_functions", method = "GET",
 *          description = "List all function names with pagination", access = ToolAccess.READ_ONLY)
 * public Response getAllFunctionNames(
 *     @Param(value = "offset", defaultValue = "0") int offset,
 *     @Param(value = "limit", defaultValue = "100") int limit,
 *     @Param("program") String programName) { ... }
 * }</pre>
 *
 * @since 4.3.0
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface McpTool {

    /** HTTP path for this endpoint (e.g., "/find_functions"). */
    String path();

    /** HTTP method: "GET" or "POST". */
    String method() default "GET";

    /** Human-readable description of what this tool does. */
    String description() default "";

    /** Tool category for grouping (e.g., "listing", "function", "analysis"). */
    String category() default "";

    /**
     * What this tool does to state, which becomes MCP's {@code readOnlyHint} /
     * {@code destructiveHint}. Declaring it is not cosmetic: clients refuse to
     * run a non-read-only MCP tool unattended (Claude Code prompts for every
     * one while planning, and will not parallelise them). Left
     * {@link ToolAccess#UNSPECIFIED} no hints are emitted at all.
     */
    ToolAccess access() default ToolAccess.UNSPECIFIED;

    /**
     * Bridge-only HTTP route: still registered and callable, but omitted from
     * {@code /mcp/schema} so no MCP tool is generated and the model never sees
     * it. Use for endpoints the bridge invokes automatically (e.g. checkout
     * refresh after writes) — listing them invites the agent to reason about
     * staleness the bridge already handles.
     */
    boolean internal() default false;
    /**
     * Whether {@code dry_run} can preview this tool. The scanner implements a dry run as
     * "call the tool inside a program transaction, then roll it back", which only undoes
     * changes to the program database. A tool whose effect is elsewhere (saving, closing,
     * checking in, files on disk, the server, an external service, a debugger) declares
     * false: a dry run is refused before anything happens. Found when
     * {@code checkin_program(dry_run=true)} saved, closed and checked in for real.
     */
    boolean dryRun() default true;
}
