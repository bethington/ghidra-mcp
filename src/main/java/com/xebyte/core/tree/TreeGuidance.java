package com.xebyte.core.tree;

import java.util.Locale;

/**
 * The prose an agent reads inside a tree.
 *
 * <p>Kept in one class rather than inlined into the writers because it is the
 * part most likely to be wrong, and because it is read far more often than it is
 * written: a caveat here is paid once per sweep and consulted on every visit.
 *
 * <p>Two of the caveats below cost a real session to discover and are emitted
 * <em>conditionally</em>, so a tree that cannot hit them does not carry the
 * warning as noise.
 *
 * @since 7.2.0
 */
public final class TreeGuidance {

    private TreeGuidance() {
    }

    /**
     * The contract: what this tree is, what it is not, and how to tell whether to
     * trust it.
     *
     * @param strippedBinary  most function names are Ghidra's own, so name-based
     *                        search will find nothing
     * @param hasPeripherals  at least one compartment was formed from MMIO pages,
     *                        so the negative-literal rendering matters here
     */
    public static String agentsMd(String programName, String treeId, String rootPath,
            boolean strippedBinary, boolean hasPeripherals) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Reading this tree\n\n");
        sb.append("A decompilation of `").append(programName).append("` as files, so you can ")
                .append("Grep a whole binary instead of asking about one function at a time.\n\n");

        sb.append("## It is generated output\n\n");
        sb.append("Read-only. Anything you edit here is overwritten by the next sweep or ")
                .append("refresh, and nothing you write here reaches Ghidra. To change the ")
                .append("program, use the MCP write tools (`rename_function`, `set_comment`, ")
                .append("`set_function_prototype`, …); the tree follows.\n\n");

        sb.append("## Is it current?\n\n");
        sb.append("`STATUS.md` answers that with no Ghidra call. `state: clean` is exactly the ")
                .append("last sweep's output; `spliced` has been kept current block by block since ")
                .append("(`spliced_since_sweep` counts them); `dirty` means a writer did not finish ")
                .append("(crash, kill, or still running) and the tree is partial; `stale` means it ")
                .append("is known to diverge from the program (`last_error` says why) — resweep. ")
                .append("`decompile_tree_status` reports `in_sync`: swept, not stale, and no ")
                .append("change still queued or being spliced in.\n\n");
        sb.append("A rename or comment made through MCP splices the affected blocks in place, ")
                .append("so the tree normally keeps up. A bulk change (`reanalyze`, a script) ")
                .append("marks the tree stale instead — resweep rather than trusting it.\n\n");

        sb.append("## The tree is the corpus; the resource is the microscope\n\n");
        sb.append("Every function block carries what `get_functions` returns for it, one "
                + "`// key: value` header line per fact, ending at `// ----` (the C follows): "
                + "`signature:`, `return_type:`, `tags:`, `plate:`, `calls:` / `callers:` "
                + "(`name@address`), `refs:` (every address used, pool values as "
                + "`value<word`), `param:`, `local:`, `label:`, `comment:`, `xref:`, `jump:`. Grep "
                + "a header line (`// callers:.*Foo`, `// refs:.*0x40020000`) and the block "
                + "answers without another tool round-trip. Read the `uri:` resource for "
                + "call-site context. Disassembly, p-code and type layouts are MCP tools, not "
                + "files.\n\n");

        sb.append("## Searching\n\n");
        sb.append("- `Grep <pattern> ").append(rootPath).append("/modules`\n");
        sb.append("- `Glob ").append(rootPath).append("/modules/*/*.c`\n");
        sb.append("- `index/by-address.tsv` maps every address to the file holding it, ")
                .append("including functions whose decompilation failed. The `ifp` column ")
                .append("is a short hash of DB-cheap inputs (name, prototype, comments, ")
                .append("refs) — used to detect change without re-decompiling.\n");
        sb.append("- Every address a function uses is on its `// refs:` line, however the C ")
                .append("spells it: data references, memory the code reads and writes (so a register ")
                .append("reached as base + offset is there as itself), and literal-pool values, written ")
                .append("`0x40020000<0x08016e58` (the value, then the pool word it was loaded from). ")
                .append("`grep -rn 0x40003c0c modules/` finds every function that touches a register; ")
                .append("the nearest `// fn:` line above a hit names the function.\n");
        if (strippedBinary) {
            sb.append("\n**This binary is stripped — do not search for function names.** ")
                    .append("Almost every name here is Ghidra's own `FUN_<addr>`, so grepping ")
                    .append("for a symbol you expect (`memcpy`, `__libc_start_main`) finds ")
                    .append("nothing even when the code is present. Search for **strings and ")
                    .append("constants** instead; that is also the evidence the compartments ")
                    .append("were built from.\n");
        }
        if (hasPeripherals) {
            sb.append("\n**Peripheral addresses may not appear as hex.** When the code block is ")
                    .append("marked writable (firmware loaders often do), the decompiler treats every ")
                    .append("literal-pool load as a variable: `iVar2 = DAT_08016e58;` where the pool ")
                    .append("word holds `0x40020000`. Mark flash read-only with `set_memory_block` and ")
                    .append("resweep; the loads then fold into constants or the labels at their ")
                    .append("targets (measured on one firmware: 1123 pool reads became 4). A register ")
                    .append("reached as base + offset still prints as the base plus `0xc0c`; its own ")
                    .append("address is on the block's `// refs:` line.\n");
        }

        sb.append("\n## Compartments\n\n");
        sb.append("`modules/<slug>/` groups functions that structural evidence says belong ")
                .append("together. **Slugs are machine-generated and mean nothing** — `c05` is ")
                .append("not a claim about content. Each compartment's `README.md` states the ")
                .append("rule that formed it, its confidence, and the evidence; ")
                .append("`modules/index.md` carries the whole strategy log, including which ")
                .append("strategies did not apply to this binary and why.\n\n");
        sb.append("Confidence is not decoration. A compartment formed from a class name at ")
                .append("member-density 1.00 is a strong claim; an `address-band` compartment ")
                .append("is no claim at all — it means no strategy found evidence and the ")
                .append("functions are merely adjacent.\n");
        return sb.toString();
    }

    /**
     * One line telling a reader what a compartment's grouping does and does not
     * assert. The band case is the important one: without it, "no structural
     * evidence" reads as a defect rather than as the expected outcome for code
     * that carries no signal.
     */
    public static String interpretation(String method, double confidence) {
        String m = method == null ? "" : method;
        switch (m) {
            case "qualified-name":
                return "These functions reference the same `Class::Method` name in trace "
                        + "strings. Member density (below) is how solid that is: a solid "
                        + "address run was closed over, a scattered one was not.";
            case "mmio-page":
                return "These functions touch exactly this set of peripheral register pages "
                        + "and no others — i.e. one driver. Two pages usually means two "
                        + "register banks of the same peripheral, not two devices.";
            case "literal-locality":
                return "These functions reference neighbouring constants, which usually means "
                        + "one object file: linkers concatenate .rodata in the same order as "
                        + ".text. Check `evidence_backed_members` against "
                        + "`members_by_containment` — the second group were swept in by "
                        + "address and are a weaker claim than the boundary itself.";
            case "address-band":
                return "**No structural evidence.** No strategy found a signal here, so these "
                        + "functions are grouped by address order alone. Do not infer that "
                        + "they are related. See `modules/index.md` for which strategies were "
                        + "tried and why each did not apply.";
            case "pinned":
                return "Pinned by an agent or human via `/decompile_tree_pin_module`. "
                        + "These functions are never reclassified by the cascade — the pin "
                        + "survives resweeps because it lives on the program, not the tree.";
            default:
                return String.format(Locale.ROOT,
                        "Grouped by `%s` at confidence %.2f; see the evidence below.",
                        m, confidence);
        }
    }
}
