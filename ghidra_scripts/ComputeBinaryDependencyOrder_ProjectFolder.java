// Computes a dependency-based documentation order for binaries in the current program's folder.
//
// MCP-friendly: no UI prompts and minimal output.
//
// For each program in the selected folder:
// - Extract external library names via ExternalManager
// - Build internal dependency edges between programs in the same folder
// - Topologically sort to suggest an order where dependencies are processed first

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;

import java.util.*;

public class ComputeBinaryDependencyOrder_ProjectFolder extends GhidraScript {

    @Override
    public void run() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            println("Error: No project is open.");
            return;
        }

        String folderPath = "/LoD/1.07";
        try {
            if (currentProgram != null) {
                DomainFile curDf = currentProgram.getDomainFile();
                if (curDf != null && curDf.getParent() != null) {
                    folderPath = curDf.getParent().getPathname();
                }
            }
        } catch (Exception ignored) {
        }

        DomainFolder folder = project.getProjectData().getFolder(folderPath);
        if (folder == null) {
            println("Error: Folder not found: " + folderPath);
            return;
        }

        List<DomainFile> programs = new ArrayList<>();
        for (DomainFile f : folder.getFiles()) {
            if ("Program".equals(f.getContentType())) {
                programs.add(f);
            }
        }

        if (programs.isEmpty()) {
            println("No programs found in folder: " + folderPath);
            return;
        }

        Map<String, DomainFile> byName = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (DomainFile f : programs) {
            byName.put(f.getName(), f);
        }

        Map<String, SortedSet<String>> internalDeps = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        println("Dependency Order (imports) for " + folderPath);
        println("Programs: " + programs.size());

        for (DomainFile df : programs) {
            if (monitor.isCancelled()) {
                println("Cancelled.");
                return;
            }

            String progName = df.getName();
            SortedSet<String> deps = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);

            Program program = null;
            try {
                program = (Program) df.getDomainObject(this, true, false, monitor);
                ExternalManager em = program.getExternalManager();
                String[] names = em.getExternalLibraryNames();
                if (names != null) {
                    for (String lib : names) {
                        if (lib == null) continue;
                        String norm = lib.trim();
                        if (norm.isEmpty()) continue;

                        DomainFile match = byName.get(norm);
                        if (match != null) {
                            deps.add(match.getName());
                        }
                    }
                }
            } catch (Exception e) {
                println("ERROR: " + df.getName() + ": " + e.getMessage());
            } finally {
                if (program != null) {
                    program.release(this);
                }
            }

            internalDeps.put(progName, deps);
        }

        // Topological sort
        List<String> topo = topoSort(byName.keySet(), internalDeps);

        println("\nSuggested order (deps first):");
        int i = 1;
        for (String p : topo) {
            println(String.format("%2d. %s", i++, p));
        }

        if (topo.size() != byName.size()) {
            println("\nWARNING: Not all programs ordered (cycle/missing).");
            SortedSet<String> missing = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            missing.addAll(byName.keySet());
            missing.removeAll(topo);
            println("Unordered: " + String.join(", ", missing));
        }

        println("\nInternal deps (A -> imports {B..}):");
        for (String p : internalDeps.keySet()) {
            SortedSet<String> deps = internalDeps.get(p);
            if (deps == null || deps.isEmpty()) {
                continue;
            }
            println(p + " -> " + String.join(", ", deps));
        }
    }

    private List<String> topoSort(Set<String> nodes, Map<String, SortedSet<String>> deps) {
        Map<String, Integer> indegree = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String, SortedSet<String>> reverse = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        for (String n : nodes) {
            indegree.put(n, 0);
            reverse.put(n, new TreeSet<>(String.CASE_INSENSITIVE_ORDER));
        }

        for (String a : nodes) {
            SortedSet<String> ds = deps.get(a);
            if (ds == null) continue;
            for (String b : ds) {
                if (!indegree.containsKey(b)) continue;
                reverse.get(b).add(a);
                indegree.put(a, indegree.get(a) + 1);
            }
        }

        ArrayDeque<String> q = new ArrayDeque<>();
        for (Map.Entry<String, Integer> e : indegree.entrySet()) {
            if (e.getValue() == 0) q.add(e.getKey());
        }

        List<String> out = new ArrayList<>();
        while (!q.isEmpty()) {
            String n = q.removeFirst();
            out.add(n);
            for (String dep : reverse.get(n)) {
                indegree.put(dep, indegree.get(dep) - 1);
                if (indegree.get(dep) == 0) q.add(dep);
            }
        }

        return out;
    }
}
