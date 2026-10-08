package com.xebyte.core;

import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionCascade;
import com.xebyte.core.partition.PartitionContext;
import com.xebyte.core.partition.Partitioner;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Structural partitioning of a program into compartments, with the evidence.
 *
 * <p>An agent has to be able to rule out whole regions before decompiling any of
 * them. On a Windows driver the two library compartments were 42% of the binary and
 * were identifiable from their referenced strings alone.
 *
 * <p>Nothing here interprets. Slugs are machine-generated ({@code c05}, never
 * {@code crypto}) and every partition carries the rule that formed it plus the
 * evidence, because a group seeded by a class name at member-density 1.00 is a very
 * different claim from a fixed address band. Naming is left to whoever reads the
 * evidence afterwards.
 *
 * <p><b>Threading:</b> runs on the calling HTTP worker thread — one full pass over
 * every instruction in the program. Do <em>not</em> wrap this in
 * {@code threadingStrategy.executeRead}; in GUI mode that hops onto the EDT. Same
 * rule as {@link TypeReferenceService}.
 *
 * @since 7.2.0
 */
public class PartitionService {

    private static final int MAX_PARTITIONS_REPORTED = 400;
    private static final int SAMPLE_TOKENS = 5;

    private final ProgramProvider programProvider;

    public PartitionService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    @McpTool(path = "/partition_program",
        description = "Group a program's functions into compartments so you can decide which "
            + "regions to ignore before reading any of them — on a driver DLL the two library "
            + "compartments were 42% of the binary and identifiable from their referenced "
            + "strings alone. Uses a cascade of structural strategies (class names in log "
            + "strings, peripheral register pages, linker literal locality, address banding); "
            + "each reports whether it applied and why, and every partition carries the "
            + "evidence that formed it. Slugs are machine-generated and assert nothing about "
            + "content. Read-only: reports the partitioning, does not write the Program Tree. "
            + "Runs off the EDT; costs one pass over every instruction.",
        category = "analysis", access = ToolAccess.READ_ONLY)
    public Response partitionProgram(
            @Param(value = "band_size", defaultValue = "20",
                   description = "Functions per file for the address-band fallback.") int bandSize,
            @Param(value = "min_size", defaultValue = "1",
                   description = "Omit partitions smaller than this from the response.") int minSize,
            @Param(value = "strategies", defaultValue = "",
                   description = "Comma-separated subset of strategy names to run "
                       + "(qualified-name, mmio-page, literal-locality, address-band). "
                       + "Omit to run the full cascade.") String strategies,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit for the active program).") String programName) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<Partitioner> chain = buildChain(bandSize, strategies);
        if (chain.isEmpty()) {
            return Response.err("No known strategy named in 'strategies': " + strategies);
        }

        long started = System.nanoTime();
        PartitionContext.EligibilityScan scan = PartitionContext.scanEligibility(program);
        if (scan.eligible() == 0) {
            if (scan.noInstructionAtEntry() > 0) {
                int candidate = scan.eligible() + scan.noInstructionAtEntry();
                return Response.err(String.format(
                        "Program has no eligible functions: %d of %d have no instruction at "
                                + "their entry (imported but never analyzed). Run analysis, or "
                                + "create a decompile tree with disassemble_missing=true.",
                        scan.noInstructionAtEntry(), candidate));
            }
            return Response.err(
                    "Program has no eligible functions (all external or thunk)");
        }
        PartitionContext ctx = new PartitionContext(program);
        PartitionCascade.Result result = new PartitionCascade(chain).run(ctx);
        long elapsedMs = (System.nanoTime() - started) / 1_000_000L;

        List<Partition> ranked = new ArrayList<>(result.partitions());
        ranked.sort(Comparator.comparingInt(Partition::size).reversed());

        List<Map<String, Object>> rows = new ArrayList<>();
        for (Partition p : ranked) {
            if (p.size() < minSize) continue;
            if (rows.size() >= MAX_PARTITIONS_REPORTED) break;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("slug", p.slug());
            row.put("method", p.method());
            row.put("functions", p.size());
            row.put("confidence", p.confidence());
            row.put("first_address", ServiceUtils.addressToJson(p.members().get(0).getEntryPoint(), program));
            row.putAll(p.evidence());
            row.put("sample", sampleNames(p));
            rows.add(row);
        }

        PartitionContext.LiteralIndex li = ctx.literals();
        Map<String, Object> signal = new LinkedHashMap<>();
        signal.put("functions_referencing_strings", li.functionsWithStrings());
        signal.put("functions_referencing_high_constants", li.functionsWithPages());

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("program", program.getName());
        out.put("eligible_functions", ctx.size());
        out.put("assigned_functions", result.assignedFunctions());
        out.put("partitions", rows);
        out.put("partition_count", result.partitions().size());
        out.put("partitions_reported", rows.size());
        out.put("signal_coverage", signal);
        out.put("strategies", result.strategyLog());
        out.put("elapsed_ms", elapsedMs);
        return Response.ok(out);
    }

    private List<Partitioner> buildChain(int bandSize, String strategies) {
        List<String> wanted = new ArrayList<>();
        if (strategies != null && !strategies.isBlank()) {
            for (String s : strategies.split(",")) {
                String t = s.trim();
                if (!t.isEmpty()) {
                    wanted.add(t);
                }
            }
        }
        return PartitionCascade.buildChain(bandSize, wanted);
    }

    /** A few member names, so a row is recognisable without opening the compartment. */
    private List<String> sampleNames(Partition p) {
        List<String> out = new ArrayList<>();
        for (Function f : p.members()) {
            if (out.size() >= SAMPLE_TOKENS) break;
            out.add(f.getName());
        }
        return out;
    }
}
