package com.xebyte.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * Language-variant selection gate for decompiler output.
 *
 * <p>Ghidra's import dialog picks a SLEIGH language out of five columns:
 * processor, endian, size, <em>variant</em>, compiler. The first three come off
 * the file header and are rarely wrong; the variant is the column the loader
 * <em>guesses</em>, and it is the one that silently changes what the bytes mean.
 * The canonical case is PowerPC: {@code PowerPC:BE:32:default} and
 * {@code PowerPC:BE:64:VLE-32addr} (VLE) decode the same bytes into different
 * instruction streams, so a VLE image opened as classic PowerPC decompiles into
 * C that is syntactically perfect, confidently wrong, and carries no marker
 * saying so. Nothing downstream can detect it: the decompiler reports success,
 * the pseudocode reads plausibly, and a documentation pass will happily write
 * prose about instructions the CPU never executes.
 *
 * <p>Until 7.0.0 this server never surfaced the variant at all. A caller could
 * decompile a thousand functions without once learning which of eleven PowerPC
 * dialects produced them. The fix is deliberately a <em>gate</em> rather than an
 * advisory field: when the loaded processor/endian/size bucket holds more than
 * one variant, the decompile tools refuse to answer until the caller names the
 * variant it believes it is reading. Naming it is cheap; being wrong about it is
 * not detectable by reading the output.
 *
 * <p>This class is deliberately free of Ghidra imports so the whole decision
 * table is exercised offline by {@code LanguageVariantsTest}. The Ghidra-facing
 * half (enumerating the variants a processor actually offers) lives in
 * {@link ServiceUtils#languageVariantChoices} and {@link ServiceUtils#variantGate}.
 *
 * @since 7.0.0
 */
public final class LanguageVariants {

    private LanguageVariants() {}

    /** No variant was supplied and the processor offers more than one. */
    public static final String VARIANT_REQUIRED = "variant_required";
    /** A real variant was supplied, but not the one the program is loaded under. */
    public static final String VARIANT_MISMATCH = "variant_mismatch";
    /** The supplied variant is not one this processor offers at all. */
    public static final String UNKNOWN_VARIANT = "unknown_variant";

    /**
     * A machine-readable refusal. {@code error} is the stable code callers branch
     * on, {@code message} states what is wrong, {@code suggestion} states what to
     * do about it.
     */
    public record Rejection(String error, String message, String suggestion) {}

    /** Trim to a non-null string. */
    public static String normalize(String value) {
        return value == null ? "" : value.trim();
    }

    /**
     * Whether a caller-supplied selection is spelled as a full SLEIGH language id
     * ({@code PowerPC:BE:64:VLE-32addr}) rather than a bare variant name
     * ({@code e200}). Both spellings are accepted: {@code get_language_metadata}
     * reports the full id, and echoing back the thing you were just shown is the
     * first thing anyone tries.
     */
    public static boolean looksLikeLanguageId(String requested) {
        return normalize(requested).indexOf(':') >= 0;
    }

    /** The variant column of a full language id, or the value itself when already bare. */
    public static String variantToken(String requested) {
        String v = normalize(requested);
        int idx = v.lastIndexOf(':');
        return idx >= 0 ? v.substring(idx + 1).trim() : v;
    }

    /**
     * The variant names on offer, de-duplicated, in the order given, with the
     * loaded variant guaranteed present.
     *
     * <p>The loaded variant is unioned in rather than assumed: the enumeration
     * skips deprecated languages, and a program imported under one (or under a
     * language from a processor module that has since been removed) would
     * otherwise be told its own variant does not exist, which is a refusal with
     * no legal answer.
     */
    public static List<String> variantNames(Collection<String> available, String loadedVariant) {
        LinkedHashSet<String> names = new LinkedHashSet<>();
        if (available != null) {
            for (String a : available) {
                String n = normalize(a);
                if (!n.isEmpty()) names.add(n);
            }
        }
        String loaded = normalize(loadedVariant);
        if (!loaded.isEmpty()) {
            boolean present = false;
            for (String n : names) {
                if (n.equalsIgnoreCase(loaded)) {
                    present = true;
                    break;
                }
            }
            if (!present) names.add(loaded);
        }
        return new ArrayList<>(names);
    }

    /** Whether this processor/endian/size bucket offers a genuine choice. */
    public static boolean isAmbiguous(Collection<String> available, String loadedVariant) {
        return variantNames(available, loadedVariant).size() > 1;
    }

    /**
     * Decide whether a decompile may proceed under the caller's variant
     * selection. Returns {@code null} when it may.
     *
     * <p>The decision table:
     * <ul>
     *   <li>Nothing requested, one variant exists: proceed. There is no choice to
     *       confirm, so demanding one would be ceremony.</li>
     *   <li>Nothing requested, several variants exist: {@link #VARIANT_REQUIRED}.</li>
     *   <li>Requested matches what is loaded: proceed.</li>
     *   <li>Requested is a real variant of this processor but not the loaded one:
     *       {@link #VARIANT_MISMATCH}. Never softened to a warning. The decompiler
     *       decodes with the language the program was imported under and cannot be
     *       asked for another, so answering anyway returns output for a different
     *       question than the one asked, under a label the caller chose.</li>
     *   <li>Requested is not a variant of this processor: {@link #UNKNOWN_VARIANT}.</li>
     * </ul>
     *
     * <p>A mismatch is checked even when the processor has only one variant. A
     * caller that asks for {@code VLE} on an x86 program has mistaken which
     * program it is talking to, and that is worth catching where it is cheapest
     * to fix.
     */
    public static Rejection check(String languageId, String loadedVariant,
                                  Collection<String> availableVariants, String requested) {
        String id = normalize(languageId);
        String loaded = normalize(loadedVariant);
        List<String> names = variantNames(availableVariants, loaded);
        String req = normalize(requested);

        if (req.isEmpty()) {
            if (names.size() <= 1) return null;
            return new Rejection(VARIANT_REQUIRED, requiredMessage(names), confirmSuggestion(id, loaded));
        }

        // A full-id spelling is compared whole. Comparing only its variant column
        // would let "PowerPC:BE:64:default" satisfy a 32-bit program, which is a
        // bigger mistake than the one this gate exists to catch.
        if (looksLikeLanguageId(req)) {
            if (req.equalsIgnoreCase(id)) return null;
            return new Rejection(VARIANT_MISMATCH, idMismatchMessage(req, id),
                                 switchSuggestion(id, loaded, variantToken(req)));
        }

        if (req.equalsIgnoreCase(loaded)) return null;

        for (String n : names) {
            if (n.equalsIgnoreCase(req)) {
                return new Rejection(VARIANT_MISMATCH, mismatchMessage(req, loaded, id),
                                     switchSuggestion(id, loaded, req));
            }
        }
        return new Rejection(UNKNOWN_VARIANT, unknownMessage(req, names), confirmSuggestion(id, loaded));
    }

    // ------------------------------------------------------------------
    // Message text
    // ------------------------------------------------------------------

    /** Comma-joined variant names, for embedding in prose. */
    public static String joinVariants(Collection<String> names) {
        return String.join(", ", names);
    }

    private static String requiredMessage(List<String> names) {
        return "This program's processor offers " + names.size() + " language variants ("
                + joinVariants(names) + ") at its endian/size, and decompiler output is only "
                + "meaningful under the one the code was actually built for: the same bytes decode "
                + "into different instructions under PowerPC 'default' and PowerPC VLE, and the "
                + "wrong choice yields pseudocode that is plausible, confident and wrong. Re-send "
                + "with variant=<one of the names above>.";
    }

    private static String confirmSuggestion(String languageId, String loadedVariant) {
        return "This program is loaded as '" + loadedVariant + "' (" + languageId + "). Pass "
                + "variant=" + loadedVariant + " once you have confirmed that is the variant this "
                + "binary actually targets: check the ELF/PE machine flags, the vendor's core "
                + "documentation, or whether disassembly at known entry points is coherent. If it "
                + "is the wrong variant, decompiling under it produces wrong C, so fix the program "
                + "first by re-importing with import_file(language=\"processor:endian:size:variant\") "
                + "or by changing it in Ghidra under Language > Set Language.";
    }

    private static String mismatchMessage(String requested, String loadedVariant, String languageId) {
        return "Requested variant '" + requested + "' but this program is loaded as '"
                + loadedVariant + "' (" + languageId + "). The decompiler always decodes with the "
                + "language the program was imported under, so returning output here would answer a "
                + "different question than the one asked.";
    }

    private static String idMismatchMessage(String requested, String languageId) {
        return "Requested language '" + requested + "' but this program is loaded as '"
                + languageId + "'. The decompiler always decodes with the language the program was "
                + "imported under, so returning output here would answer a different question than "
                + "the one asked.";
    }

    private static String switchSuggestion(String languageId, String loadedVariant, String requestedVariant) {
        return "Either decompile what is actually loaded by re-sending variant=" + loadedVariant
                + ", or make '" + requestedVariant + "' real first by re-importing the file with "
                + "import_file(language=...) or changing the program's language in Ghidra under "
                + "Language > Set Language. This endpoint will not reinterpret " + languageId
                + " bytes under another variant.";
    }

    private static String unknownMessage(String requested, List<String> names) {
        return "Unknown variant '" + requested + "' for this program's processor. Known variants: "
                + joinVariants(names) + ". Variant names are case-insensitive, and a full SLEIGH "
                + "language id (processor:endian:size:variant) is also accepted.";
    }

    /** Lowercase key for case-insensitive comparison in callers that need one. */
    public static String key(String value) {
        return normalize(value).toLowerCase(Locale.ROOT);
    }
}
