package com.xebyte.core;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Programs opened on demand from a Ghidra project, held in a bounded, write-through cache.
 *
 * <p>Both servers serve programs this way. It began as the GUI provider's cache; the
 * headless server only ever found programs someone had explicitly loaded, keyed by bare
 * filename, and never matched a project path -- so the same request that worked in the
 * GUI answered "Program not found" headless for a program sitting in the project.
 *
 * <p><b>Resolution</b> ({@link #getProgram}), in order, each tier resolved on its own:
 * <ol>
 *   <li>{@link #liveSessionPrograms()} -- what a UI session has open (GUI: every
 *       CodeBrowser; headless: none). First, because the cache can hold an orphaned
 *       Program whose DomainFile a checkout/checkin cycle severed while the CodeBrowser
 *       holds the live one; writes to the orphan fail to save.</li>
 *   <li>the cache;</li>
 *   <li>the project, opening on demand.</li>
 * </ol>
 * A bare name is first resolved to a path by the project, so it means the same file
 * whatever happens to be open; a name several project files share raises
 * {@link AmbiguousProgramException} rather than guessing. Only a name the project does not
 * know falls back to the open programs: exact name, then a unique substring.
 *
 * <p><b>Bounded.</b> At most {@link #MAX_CACHED_PROGRAMS} on-demand programs stay open;
 * the least recently used is saved and released. Without a cap a long run held a
 * consumer reference per program until Ghidra ran out of memory, and more than ~5
 * shared-server programs open at once crashes it.
 *
 * <p><b>Write-through.</b> Write endpoints mutate a program in memory and never save.
 * Releasing a handle the provider holds alone disposes the program, so every release
 * saves first ({@link ProgramSaves#saveIfChanged}) -- except where the caller asked to
 * discard.
 */
public abstract class ProjectProgramProvider implements ProgramProvider {

    /** Max on-demand programs held open. {@code GHIDRA_MCP_MAX_CACHED_PROGRAMS}, min 2. */
    public static final int MAX_CACHED_PROGRAMS = resolveMaxCachedPrograms();

    // Keyed by project path; a program with no DomainFile (an import not yet saved, a
    // test double) by name. Path, not name: the same DLL name can exist in every version folder.
    private final Map<String, Program> cache = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAccessNanos = new ConcurrentHashMap<>();
    // Why a program is open read-only: the writable open's failure, kept so a caller can
    // be told (a stale SLEIGH language opens read-only and every edit is then lost).
    private final Map<Program, Exception> readOnlyReasons =
        Collections.synchronizedMap(new java.util.WeakHashMap<>());
    private final boolean okToUpgrade;
    protected final Object consumer;
    protected final TaskMonitor monitor = new ConsoleTaskMonitor();

    /**
     * @param consumer    the DomainObject consumer our references are held under; null
     *                    means this provider
     * @param okToUpgrade whether opening may upgrade a program's stored format. The GUI
     *                    passes false: an upgrade needs an exclusive checkout, which it
     *                    must not take silently. Headless passes true.
     */
    protected ProjectProgramProvider(Object consumer, boolean okToUpgrade) {
        this.consumer = consumer != null ? consumer : this;
        this.okToUpgrade = okToUpgrade;
    }

    private static int resolveMaxCachedPrograms() {
        String raw = System.getenv("GHIDRA_MCP_MAX_CACHED_PROGRAMS");
        if (raw != null && !raw.isBlank()) {
            try {
                return Math.max(2, Integer.parseInt(raw.trim()));
            } catch (NumberFormatException ignored) {
                // default below
            }
        }
        return 8;
    }

    // ------------------------------------------------------------------ hooks

    /** The project programs are opened from; null when none is open. */
    protected abstract Project project();

    /** Programs a live UI session holds, consulted before the cache. None headless. */
    protected List<Program> liveSessionPrograms() {
        return List.of();
    }

    /** Called once a program has been opened into the cache. */
    protected void onOpened(Program program) {}

    /** Called after the provider released its handle on a program. */
    protected void onReleased(Program program) {}

    @Override
    public Project getProject() {
        return project();
    }

    // ------------------------------------------------------------- resolution

    /** The cache key for a program: its project path, or its name when it has none. */
    public static String keyFor(Program program) {
        DomainFile df = program.getDomainFile();
        return df != null ? df.getPathname() : program.getName();
    }

    @Override
    public Program getProgram(String name) {
        return inProjectScope(resolve(name), name);
    }

    private Program resolve(String name) {
        if (name == null || name.trim().isEmpty()) {
            return getCurrentProgram();
        }
        String wanted = name.trim();
        if (!wanted.startsWith("/")) {
            // A bare name is answered by the project, not by whatever happens to be
            // open: with /fw/gnutrue open and /other/gnutrue not, "gnutrue" matched
            // the open one, so the same request meant a different binary depending on
            // what an earlier call had opened. Throws when the project has several.
            DomainFile unique = findDomainFile(wanted);
            if (unique != null) {
                wanted = unique.getPathname();
            }
        }
        Program hit = matchExact(liveSessionPrograms(), wanted);
        if (hit != null) {
            return hit;
        }
        hit = matchExact(cache.values(), wanted);
        if (hit != null) {
            touch(keyFor(hit));
            return hit;
        }
        // The project before any substring guess: "gnu" must open the file named gnu,
        // not resolve to an already-open "gnutrue".
        hit = openFromProject(wanted);
        if (hit != null) {
            return hit;
        }
        return matchSubstring(Arrays.asList(getAllOpenPrograms()), name.trim());
    }

    /**
     * The one open program {@code wanted} names, or null: an exact path, then an exact
     * name, then -- only when unique -- a name substring.
     *
     * @throws AmbiguousProgramException when it names more than one
     */
    public static Program match(Collection<Program> programs, String wanted) {
        Program exact = matchExact(programs, wanted);
        return exact != null ? exact : matchSubstring(programs, wanted);
    }

    private static Program matchExact(Collection<Program> programs, String wanted) {
        if (wanted == null || wanted.isBlank() || programs.isEmpty()) {
            return null;
        }
        String s = wanted.trim();
        if (s.startsWith("/")) {
            for (Program p : programs) {
                DomainFile df = p.getDomainFile();
                if (df != null && df.getPathname().equals(s)) {
                    return p;
                }
            }
            for (Program p : programs) {
                DomainFile df = p.getDomainFile();
                if (df != null && df.getPathname().equalsIgnoreCase(s)) {
                    return p;
                }
            }
            return null;
        }
        return unique(programs, s, p -> p.getName().equalsIgnoreCase(s));
    }

    private static Program matchSubstring(Collection<Program> programs, String wanted) {
        if (wanted == null || wanted.isBlank() || wanted.trim().startsWith("/")) {
            return null;
        }
        String lower = wanted.trim().toLowerCase();
        return unique(programs, wanted.trim(), p -> p.getName().toLowerCase().contains(lower));
    }

    private static Program unique(Collection<Program> programs, String wanted,
            java.util.function.Predicate<Program> test) {
        Set<Program> hits = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Program p : programs) {
            if (test.test(p)) {
                hits.add(p);
            }
        }
        if (hits.size() > 1) {
            List<String> names = new ArrayList<>();
            for (Program p : hits) names.add(keyFor(p));
            Collections.sort(names);
            throw new AmbiguousProgramException(wanted, names);
        }
        return hits.isEmpty() ? null : hits.iterator().next();
    }

    @Override
    public Program[] getAllOpenPrograms() {
        List<Program> all = new ArrayList<>(liveSessionPrograms());
        Set<Program> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        seen.addAll(all);
        for (Program p : cache.values()) {
            if (seen.add(p)) {
                all.add(p);
            }
        }
        return all.toArray(new Program[0]);
    }

    /** An open program with exactly this name (case-insensitive), never a substring hit. */
    protected Program openProgramNamed(String name) {
        if (name == null || name.isEmpty()) {
            return null;
        }
        for (Program p : getAllOpenPrograms()) {
            if (p.getName().equals(name)) return p;
        }
        for (Program p : getAllOpenPrograms()) {
            if (p.getName().equalsIgnoreCase(name)) return p;
        }
        return null;
    }

    // ---------------------------------------------------------------- opening

    /**
     * Open a program from the project by path or filename, or return the cached one.
     *
     * @return the program, or null when there is no project or no such file
     * @throws AmbiguousProgramException when a filename matches several project files
     */
    public Program openFromProject(String nameOrPath) {
        DomainFile df = findDomainFile(nameOrPath);
        if (df == null) {
            return null;
        }
        try {
            return openDomainFile(df);
        } catch (Exception e) {
            Msg.error(this, "Failed to open " + df.getPathname() + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * The project file {@code ident} names: an exact path, or a unique filename anywhere
     * (exact case preferred over case-insensitive). A file at the root gets no priority:
     * /x and /sub/x make "x" ambiguous.
     *
     * @throws AmbiguousProgramException when a filename matches several files
     */
    public DomainFile findDomainFile(String ident) {
        Project project = project();
        if (project == null || ident == null || ident.isBlank()) {
            return null;
        }
        String s = ident.trim();
        ProjectData data = project.getProjectData();
        if (data == null) {
            return null;
        }
        if (s.startsWith("/")) {
            return data.getFile(s);
        }
        List<DomainFile> exactCase = new ArrayList<>();
        List<DomainFile> anyCase = new ArrayList<>();
        collectByName(data.getRootFolder(), s, exactCase, anyCase);
        List<DomainFile> hits = exactCase.isEmpty() ? anyCase : exactCase;
        if (hits.size() > 1) {
            List<String> paths = new ArrayList<>();
            for (DomainFile f : hits) paths.add(f.getPathname());
            Collections.sort(paths);
            throw new AmbiguousProgramException(s, paths);
        }
        return hits.isEmpty() ? null : hits.get(0);
    }

    private void collectByName(DomainFolder folder, String name,
            List<DomainFile> exactCase, List<DomainFile> anyCase) {
        if (folder == null) {
            return;
        }
        try {
            for (DomainFile f : folder.getFiles()) {
                if (f.getName().equals(name)) exactCase.add(f);
                if (f.getName().equalsIgnoreCase(name)) anyCase.add(f);
            }
            for (DomainFolder sub : folder.getFolders()) {
                collectByName(sub, name, exactCase, anyCase);
            }
        } catch (Exception e) {
            Msg.warn(this, "Error searching folder " + folder.getPathname() + ": " + e.getMessage());
        }
    }

    /**
     * Open {@code df} into the cache: writable if possible, else read-only.
     *
     * @throws Exception the writable attempt's failure, when read-only fails too
     */
    public Program openDomainFile(DomainFile df) throws Exception {
        String key = df.getPathname();
        Program cached = cache.get(key);
        if (cached != null && !cached.isClosed()) {
            touch(key);
            return cached;
        }
        Program program;
        try {
            // Returns the SAME instance a CodeBrowser already has open, if any.
            program = (Program) df.getDomainObject(consumer, okToUpgrade, false, monitor);
        } catch (Exception writable) {
            Msg.warn(this, "Opening " + key + " writable failed (" + writable.getMessage()
                + "); trying read-only");
            try {
                program = (Program) df.getImmutableDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);
            } catch (Exception readOnly) {
                writable.addSuppressed(readOnly);
                throw writable;
            }
            if (program != null) {
                readOnlyReasons.put(program, writable);
            }
        }
        if (program == null) {
            throw new IllegalStateException("getDomainObject returned null for " + key);
        }
        cachePut(key, program);
        onOpened(program);
        Msg.info(this, "Opened program from project: " + key);
        return program;
    }

    /**
     * Hold an already-open program -- an import, a restore, a test's ProgramBuilder
     * program -- under the same bound and write-through rules as an on-demand open.
     */
    public void trackOpenProgram(Program program) {
        if (program != null) {
            cachePut(keyFor(program), program);
        }
    }

    private void cachePut(String key, Program program) {
        Program displaced = cache.put(key, program);
        if (displaced != null && displaced != program) {
            // Two instances for one key: a re-import, or an orphan a checkout cycle left
            // behind. Holding both leaks a consumer reference and the DB buffers behind it.
            release(key, displaced, true);
        }
        touch(key);
        evictExcess(program);
    }

    // ---------------------------------------------------------------- closing

    @Override
    public boolean closeProgram(Program program, boolean save) {
        if (program == null) {
            return false;
        }
        boolean found = false;
        for (Map.Entry<String, Program> e : new ArrayList<>(cache.entrySet())) {
            if (e.getValue() == program && cache.remove(e.getKey(), program)) {
                lastAccessNanos.remove(e.getKey());
                release(e.getKey(), program, save);
                found = true;
            }
        }
        return found;
    }

    @Override
    public boolean releaseCachedProgram(String nameOrPath, boolean save) {
        if (nameOrPath == null || nameOrPath.isBlank()) {
            return false;
        }
        String s = nameOrPath.trim();
        boolean released = false;
        for (Map.Entry<String, Program> e : new ArrayList<>(cache.entrySet())) {
            Program p = e.getValue();
            DomainFile df = p.getDomainFile();
            boolean hit = e.getKey().equalsIgnoreCase(s) || p.getName().equalsIgnoreCase(s)
                || (df != null && df.getPathname().equalsIgnoreCase(s));
            if (hit && cache.remove(e.getKey(), p)) {
                lastAccessNanos.remove(e.getKey());
                release(e.getKey(), p, save);
                released = true;
            }
        }
        return released;
    }

    /**
     * Drop the cached handle for this exact project path, without saving: callers are
     * clearing the way for a move or a delete of that file.
     */
    @Override
    public boolean closeProgramByPath(String path) {
        if (path == null || path.isBlank()) {
            return false;
        }
        boolean released = false;
        for (Map.Entry<String, Program> e : new ArrayList<>(cache.entrySet())) {
            DomainFile df = e.getValue().getDomainFile();
            if (df != null && df.getPathname().equalsIgnoreCase(path.trim())
                    && cache.remove(e.getKey(), e.getValue())) {
                lastAccessNanos.remove(e.getKey());
                release(e.getKey(), e.getValue(), false);
                released = true;
            }
        }
        return released;
    }

    /** Save (unless discarding) and release everything this provider holds. */
    public void releaseAll() {
        for (Map.Entry<String, Program> e : new ArrayList<>(cache.entrySet())) {
            release(e.getKey(), e.getValue(), true);
        }
        cache.clear();
        lastAccessNanos.clear();
    }

    private void release(String key, Program program, boolean save) {
        try {
            if (save) {
                ProgramSaves.saveIfChanged(program, monitor);
            }
            program.release(consumer);
            onReleased(program);
            Msg.info(this, "Released program: " + key);
        } catch (Exception e) {
            Msg.warn(this, "Error releasing program " + key + ": " + e.getMessage());
        }
    }

    // ------------------------------------------------------ project operations

    /** What an import produced. {@code reusedExisting}: the project already had the file. */
    public record Imported(Program program, boolean reusedExisting) {}

    /**
     * Import a binary into {@code folder} and open it, or open the file already there.
     *
     * <p>A file of the same name already in the folder is opened instead of re-imported:
     * a second import would fail on the duplicate name, and repeated imports are how a
     * scripted setup stays idempotent. The caller learns which happened.
     *
     * <p>The importer's own references are dropped once the file is saved, and the saved
     * file is opened through {@link #openDomainFile} like any other: the program then has
     * exactly one reference, the cache's, which eviction and close manage. With no project
     * the program stays in memory under the provider's consumer.
     *
     * @param languageId     empty to auto-detect the format; set for raw binaries
     * @param compilerSpecId empty for the language's default; only read with a language
     */
    public Imported importFile(java.io.File file, String folder, String languageId,
            String compilerSpecId) throws Exception {
        Project project = project();
        String dest = folder == null || folder.isBlank() ? "/" : folder.trim();
        String language = languageId == null ? "" : languageId.trim();
        String compiler = compilerSpecId == null ? "" : compilerSpecId.trim();

        if (project != null) {
            ghidra.framework.model.DomainFolder target = project.getProjectData().getFolder(dest);
            DomainFile existing = target != null ? target.getFile(file.getName()) : null;
            if (existing != null) {
                return new Imported(openDomainFile(existing), true);
            }
        }

        ghidra.app.util.importer.MessageLog log = new ghidra.app.util.importer.MessageLog();
        ghidra.app.util.opinion.LoadResults<Program> results;
        if (language.isEmpty()) {
            results = ghidra.app.util.importer.AutoImporter.importByUsingBestGuess(
                file, project, dest, consumer, log, monitor);
            if (results == null) {
                throw new java.io.IOException("no loader recognised " + file.getName()
                    + "; for a raw binary pass a language (e.g. 'ARM:LE:32:Cortex'). " + log);
            }
        } else {
            ghidra.program.model.lang.Language lang = ghidra.program.util.DefaultLanguageService
                .getLanguageService().getLanguage(new ghidra.program.model.lang.LanguageID(language));
            ghidra.program.model.lang.CompilerSpec spec = compiler.isEmpty()
                ? lang.getDefaultCompilerSpec()
                : lang.getCompilerSpecByID(new ghidra.program.model.lang.CompilerSpecID(compiler));
            ghidra.app.util.opinion.Loaded<Program> loaded = ghidra.app.util.importer.AutoImporter
                .importAsBinary(file, project, dest, lang, spec, consumer, log, monitor);
            if (loaded == null) {
                throw new java.io.IOException("import as " + language + " produced nothing. " + log);
            }
            results = new ghidra.app.util.opinion.LoadResults<>(loaded);
        }

        if (project == null) {
            Program program = results.getPrimaryDomainObject(consumer);
            results.close();
            trackOpenProgram(program);
            return new Imported(program, false);
        }
        DomainFile saved;
        try {
            // Without the save the DomainFile is a transient proxy, and every later save
            // fails with "Location does not exist for a save operation!".
            results.save(monitor);
            saved = results.getPrimary().getSavedDomainFile();
        } finally {
            results.close();
        }
        return new Imported(openDomainFile(saved), false);
    }

    /**
     * Whether the open project is bound to a Ghidra Server: which repository, where
     * ({@code serverInfo}, host:port, null when it cannot be read), and whether connected.
     */
    public record ServerBinding(boolean bound, String repository, String serverInfo, boolean connected) {}

    /** The open project's server binding, or null with no project. */
    public ServerBinding serverBinding() {
        Project project = project();
        if (project == null) {
            return null;
        }
        try {
            ghidra.framework.client.RepositoryAdapter repo = project.getProjectData().getRepository();
            if (repo == null) {
                return new ServerBinding(false, null, null, false);
            }
            String where = null;
            try {
                // toString, not a typed read: getServerInfo()'s return type changed
                // between Ghidra 12.0.x point builds (String on some, ServerInfo on
                // others), and a typed use broke the CI build once.
                Object info = repo.getServerInfo();
                where = info != null ? info.toString() : null;
            } catch (Exception e) {
                // disconnected, or the probe itself failed: report the binding without it
            }
            return new ServerBinding(true, repo.getName(), where, repo.isConnected());
        } catch (Exception e) {
            return new ServerBinding(false, null, null, false);
        }
    }

    /**
     * Why an open may have failed, as far as the server binding explains it. The recurring
     * case (#119): a checkout on a standalone server connection syncs nothing into a
     * local-only project, so the file the caller checked out is simply not there.
     */
    public String describeServerBinding() {
        ServerBinding b = serverBinding();
        if (b == null) {
            return "No project is open.";
        }
        if (!b.bound()) {
            return "Project is local-only (not bound to a Ghidra Server). A file checked out "
                + "on a separate server connection does not appear here: open a shared project "
                + "via /open_project with a ghidra://host[:port]/repo URL instead.";
        }
        return "Project is bound to a Ghidra Server (repo '" + b.repository() + "'"
            + (b.connected() ? "" : ", currently disconnected") + ")";
    }

    /** Why {@code program} was opened read-only, or null when it opened writable. */
    public Exception readOnlyReason(Program program) {
        return readOnlyReasons.get(program);
    }

    /** Up to {@code max} program paths in the project, for "did you mean" diagnostics. */
    public List<String> programPaths(int max) {
        List<String> out = new ArrayList<>();
        Project project = project();
        if (project != null) {
            collectProgramPaths(project.getProjectData().getRootFolder(), out, max);
        }
        return out;
    }

    private static void collectProgramPaths(DomainFolder folder, List<String> out, int max) {
        for (DomainFile f : folder.getFiles()) {
            if (out.size() >= max) return;
            if ("Program".equals(f.getContentType())) {
                out.add(f.getPathname());
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            if (out.size() >= max) return;
            collectProgramPaths(sub, out, max);
        }
    }

    // --------------------------------------------------------------- eviction

    private void touch(String key) {
        if (key != null) {
            lastAccessNanos.put(key, System.nanoTime());
        }
    }

    /**
     * The least-recently-accessed key whose program is not protected, or null when
     * nothing is evictable. Pure, so it can be tested offline.
     */
    public static String pickLruVictim(Map<String, Program> programs,
            Map<String, Long> accessNanos, Set<Program> protectedPrograms) {
        String victim = null;
        long oldest = Long.MAX_VALUE;
        for (Map.Entry<String, Program> e : programs.entrySet()) {
            if (protectedPrograms.contains(e.getValue())) {
                continue;
            }
            long t = accessNanos.getOrDefault(e.getKey(), 0L);
            if (t < oldest) {
                oldest = t;
                victim = e.getKey();
            }
        }
        return victim;
    }

    /** Release LRU programs down to the cap. Never the one just opened, never the current one. */
    private void evictExcess(Program justOpened) {
        Set<Program> protectedPrograms = new HashSet<>();
        if (justOpened != null) protectedPrograms.add(justOpened);
        Program current = getCurrentProgram();
        if (current != null) protectedPrograms.add(current);
        while (cache.size() > MAX_CACHED_PROGRAMS) {
            String victim = pickLruVictim(cache, lastAccessNanos, protectedPrograms);
            if (victim == null) {
                break; // everything left is protected
            }
            Program p = cache.remove(victim);
            lastAccessNanos.remove(victim);
            if (p != null) {
                release(victim, p, true);
                Msg.info(this, "Evicted idle program (cap " + MAX_CACHED_PROGRAMS + "): " + victim);
            }
        }
    }

    // ------------------------------------------------------------ scope guard

    /**
     * Apply the opt-in project-folder scope ({@code GHIDRA_MCP_PROJECT_FOLDER}): a
     * program outside it reads as not found. Off by default.
     */
    private Program inProjectScope(Program resolved, String requested) {
        if (resolved == null) {
            return null;
        }
        SecurityConfig sc = SecurityConfig.getInstance();
        if (sc.hasProjectFolderScope()) {
            DomainFile df = resolved.getDomainFile();
            String path = df != null ? df.getPathname() : null;
            if (!sc.isPathInProjectScope(path)) {
                Msg.warn(this, "Project-folder scope guard: refusing program at '" + path
                    + "' (request='" + requested + "', scope='" + sc.getProjectFolderScope() + "')");
                return null;
            }
        }
        return resolved;
    }
}
