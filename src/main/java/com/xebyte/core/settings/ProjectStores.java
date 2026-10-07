package com.xebyte.core.settings;

import ghidra.framework.data.CheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.options.Options;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/** The stores backed by a Ghidra project or program. */
public final class ProjectStores {

    /** Options list every store keeps its values under. */
    public static final String OPTIONS_NAME = "GhidraMCP";

    /** The project-shared store's file, at the project root. */
    public static final String ARCHIVE_PATH = "/.ghidra-mcp";

    private ProjectStores() {}

    /** True for the settings archive, which listings and write tools leave alone. */
    public static boolean isSettingsArchive(DomainFile file) {
        return file != null && ARCHIVE_PATH.equals(file.getPathname());
    }

    /** True for the options group the program scope keeps its values in, or one under it. */
    public static boolean isSettingsOptions(String group) {
        return group != null && (group.equals(OPTIONS_NAME) || group.startsWith(OPTIONS_NAME + "."));
    }

    // ------------------------------------------------------------------- program

    /** One program's options, under {@value #OPTIONS_NAME}. Writes join or open a transaction. */
    public static ScopeStore program(Program program) {
        return new ScopeStore() {
            @Override
            public Optional<String> read(SettingKey key) {
                Options opts = program.getOptions(OPTIONS_NAME);
                return opts.contains(key.key()) ? Optional.ofNullable(opts.getString(key.key(), null))
                    : Optional.empty();
            }

            @Override
            public void write(SettingKey key, String raw) {
                edit("Set " + key.key(), opts -> opts.setString(key.key(), raw));
            }

            @Override
            public void remove(SettingKey key) {
                edit("Unset " + key.key(), opts -> opts.removeOption(key.key()));
            }

            private void edit(String what, Consumer<Options> change) {
                int tx = program.startTransaction(what);
                boolean ok = false;
                try {
                    change.accept(program.getOptions(OPTIONS_NAME));
                    ok = true;
                } finally {
                    program.endTransaction(tx, ok);
                }
            }
        };
    }

    // --------------------------------------------------------------------- local

    /**
     * This machine's project settings: a properties file in the project's {@code .rep}
     * directory. Not Ghidra's project saveable data, which only a GUI project ever saves.
     */
    public static ScopeStore local(Project project) {
        Path file = project.getProjectLocator().getProjectDir().toPath().resolve("ghidra-mcp-settings.properties");
        return new ScopeStore() {
            /** The file's contents as of {@link #loadedAt}; guardrail checks read on every call. */
            private Properties loaded;
            private FileTime loadedAt;

            @Override
            public synchronized Optional<String> read(SettingKey key) {
                return Optional.ofNullable(load().getProperty(key.key()));
            }

            @Override
            public synchronized void write(SettingKey key, String raw) {
                Properties p = load();
                p.setProperty(key.key(), raw);
                store(p);
            }

            @Override
            public synchronized void remove(SettingKey key) {
                Properties p = load();
                if (p.remove(key.key()) != null) {
                    store(p);
                }
            }

            private Properties load() {
                Properties p = new Properties();
                if (!Files.isRegularFile(file)) {
                    return p;
                }
                try {
                    FileTime modified = Files.getLastModifiedTime(file);
                    if (modified.equals(loadedAt)) {
                        p.putAll(loaded);
                        return p;
                    }
                    try (InputStream in = Files.newInputStream(file)) {
                        p.load(in);
                    }
                    loaded = (Properties) p.clone();
                    loadedAt = modified;
                } catch (IOException e) {
                    throw new SettingRefusedException("Cannot read local settings: " + e.getMessage());
                }
                return p;
            }

            private void store(Properties p) {
                try {
                    Path tmp = Files.createTempFile(file.getParent(), "ghidra-mcp-settings", ".tmp");
                    try (OutputStream out = Files.newOutputStream(tmp)) {
                        p.store(out, "GhidraMCP local settings; this machine only");
                    }
                    Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                    loadedAt = null;
                } catch (IOException e) {
                    throw new SettingRefusedException("Cannot write local settings: " + e.getMessage());
                }
            }
        };
    }

    // ------------------------------------------------------------------- project

    /**
     * Settings shared by everyone using the project: options on the {@value #ARCHIVE_PATH}
     * data-type archive. Created on first write; on a shared project it is added to version
     * control, and each write checks it out, saves and checks it back in, so a second instance
     * of the same repository reads the value once it refreshes.
     */
    public static ScopeStore shared(Project project) {
        return new SharedStore(project);
    }

    private static final class SharedStore implements ScopeStore {
        private final Project project;
        private final TaskMonitor monitor = TaskMonitor.DUMMY;
        /** Values of the archive version last read, keyed by that version's identity. */
        private volatile String cachedStamp;
        private volatile Map<String, String> cached = Map.of();

        SharedStore(Project project) {
            this.project = project;
        }

        private ProjectData data() {
            return project.getProjectData();
        }

        private static String stamp(DomainFile f) {
            return f.getLastModifiedTime() + ":" + f.getLatestVersion() + ":" + f.getVersion();
        }

        @Override
        public synchronized Optional<String> read(SettingKey key) {
            DomainFile f = data().getFile(ARCHIVE_PATH);
            if (f == null) {
                return Optional.empty();
            }
            String stamp = stamp(f);
            if (!stamp.equals(cachedStamp)) {
                cached = readAll(f);
                cachedStamp = stamp;
            }
            return Optional.ofNullable(cached.get(key.key()));
        }

        private Map<String, String> readAll(DomainFile f) {
            Map<String, String> out = new ConcurrentHashMap<>();
            try {
                DomainObject o = f.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);
                try {
                    Options opts = o.getOptions(OPTIONS_NAME);
                    for (String name : opts.getOptionNames()) {
                        String v = opts.getString(name, null);
                        if (v != null) {
                            out.put(name, v);
                        }
                    }
                } finally {
                    o.release(this);
                }
            } catch (Exception e) {
                throw new SettingRefusedException("Cannot read project settings: " + e.getMessage());
            }
            return out;
        }

        @Override
        public void write(SettingKey key, String raw) {
            edit("set " + key.key() + "=" + raw, opts -> opts.setString(key.key(), raw));
        }

        @Override
        public void remove(SettingKey key) {
            edit("unset " + key.key(), opts -> opts.removeOption(key.key()));
        }

        private synchronized void edit(String what, Consumer<Options> change) {
            String comment = "GhidraMCP settings: " + what;
            try {
                DomainFile f = data().getFile(ARCHIVE_PATH);
                if (f == null) {
                    DataTypeArchiveDB created = new DataTypeArchiveDB(
                        data().getRootFolder(), ARCHIVE_PATH.substring(1), this);
                    try {
                        apply(created, what, change);
                        created.save(comment, monitor);
                    } finally {
                        created.release(this);
                    }
                    f = data().getFile(ARCHIVE_PATH);
                    if (project.getRepository() != null && f != null) {
                        f.addToVersionControl(comment, false, monitor);
                    }
                    return;
                }
                boolean checkOutHere = f.isVersioned() && !f.isCheckedOut();
                if (checkOutHere && !f.checkout(false, monitor)) {
                    throw new SettingRefusedException("Could not check out " + ARCHIVE_PATH + ".");
                }
                DomainObject o = f.getDomainObject(this, false, false, monitor);
                try {
                    apply(o, what, change);
                    o.save(comment, monitor);
                } finally {
                    o.release(this);
                }
                if (checkOutHere) {
                    f.checkin(new CheckinHandler() {
                        @Override public boolean keepCheckedOut() { return false; }
                        @Override public String getComment() { return comment; }
                        @Override public boolean createKeepFile() { return false; }
                    }, monitor);
                }
            } catch (SettingRefusedException e) {
                throw e;
            } catch (Exception e) {
                throw new SettingRefusedException("Cannot write project settings: " + e.getMessage());
            } finally {
                cachedStamp = null;
            }
        }

        private static void apply(DomainObject o, String what, Consumer<Options> change) {
            int tx = o.startTransaction(what);
            boolean ok = false;
            try {
                change.accept(o.getOptions(OPTIONS_NAME));
                ok = true;
            } finally {
                o.endTransaction(tx, ok);
            }
        }
    }
}
