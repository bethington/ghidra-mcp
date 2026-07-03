package com.xebyte.headless;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

/**
 * Filesystem-name and path-containment guards for headless GZF/GAR endpoints.
 *
 * <p>The export / archive / import / restore endpoints accept caller-supplied
 * names ({@code output_name}, {@code target_name}, {@code project_name}) and
 * default-derive others from project paths. Without validation a name carrying
 * path separators or {@code ..} segments lets the write escape its intended
 * output directory (path traversal). These helpers are the single choke point
 * for that validation so every endpoint enforces the same rule.
 *
 * <p>Pure static logic — no Ghidra dependencies — so it is exercised offline by
 * {@code com.xebyte.offline.HeadlessPathsTest}.
 */
public final class HeadlessPaths {

    private HeadlessPaths() {
    }

    /**
     * Reject a name that is null, empty, or carries any path component.
     *
     * <p>A safe name is a plain filename: no {@code ..} traversal segment,
     * no {@code /}, and no {@code \\}. The name is split into path segments
     * (on either separator) and any {@code ..} segment — leading
     * ({@code "../x"}), trailing ({@code "a/.."}), or bare ({@code ".."}) — is
     * categorised as traversal before the separator check, so a pure-traversal
     * form is reported as traversal rather than as a separator violation.
     *
     * @return {@code null} when the name is safe, otherwise a human-readable
     *     error message naming the offending input.
     */
    public static String validateFilename(String name) {
        if (name == null || name.isEmpty()) {
            return "name must not be empty";
        }
        // Normalise both separators and inspect each segment so a ".." anywhere
        // (leading, trailing, or bare) is caught regardless of position.
        String normalised = name.replace('\\', '/');
        for (String segment : normalised.split("/", -1)) {
            if (segment.equals("..")) {
                return "name must not contain traversal segments: " + name;
            }
        }
        if (name.indexOf('/') >= 0 || name.indexOf('\\') >= 0) {
            return "name must not contain path separators: " + name;
        }
        return null;
    }

    /**
     * Reduce a (possibly project-path-shaped) identifier to a safe basename.
     *
     * <p>Used to derive default output filenames from a program name like
     * {@code /Vanilla/1.13d/D2Common.dll} so the slashes never leak into a
     * filesystem path. Returns {@code "program"} when nothing usable remains.
     */
    public static String safeBasename(String ident) {
        if (ident == null || ident.isEmpty()) {
            return "program";
        }
        // Normalise both separators, drop everything up to the last one.
        String normalised = ident.replace('\\', '/');
        int slash = normalised.lastIndexOf('/');
        String base = slash >= 0 ? normalised.substring(slash + 1) : normalised;
        // A trailing-slash or dot-only remainder is not a usable basename.
        if (base.isEmpty() || base.equals(".") || base.equals("..")) {
            return "program";
        }
        return base;
    }

    /**
     * Confirm that {@code child} resolves to a location inside {@code dir}.
     *
     * <p>Canonicalises both paths (resolving {@code ..}, symlinks, and relative
     * segments) and verifies the child sits at or beneath the directory using
     * element-wise {@link Path#startsWith(Path)} rather than string-prefix
     * matching, so a sibling like {@code exports-evil} is not mistaken for a
     * child of {@code exports}. This is the defence-in-depth backstop behind
     * {@link #validateFilename}: even a name that slipped the string check
     * cannot escape the directory.
     *
     * @return {@code true} when {@code child} is contained in {@code dir}.
     */
    public static boolean isWithin(File dir, File child) {
        if (dir == null || child == null) {
            return false;
        }
        try {
            Path dirPath = dir.getCanonicalFile().toPath();
            Path childPath = child.getCanonicalFile().toPath();
            return childPath.startsWith(dirPath);
        } catch (IOException e) {
            return false;
        }
    }
}
