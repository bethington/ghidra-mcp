package com.xebyte.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * Language-variant labelling and mismatch check for decompiler output.
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
 * <p><b>Why this is a label and not a mandatory parameter.</b> The first cut
 * made {@code variant=} <em>required</em> whenever the processor offered a
 * choice, so the caller had to state which dialect it believed it was reading.
 * Two things sank that. First, it fires on x86 — every bucket has a second row
 * ({@code System Management Mode} at 32-bit, {@code compat32} at 64-bit), so
 * every ordinary PE and ELF would have had to answer a question about a mode
 * nothing loads. Second, and worse, the confirmation is unenforceable: the
 * refusal has to enumerate the legal values or it is an outage, which means it
 * names the answer, and the caller — usually a model — re-sends the value it
 * was just shown and records a confirmation it never performed. This repository
 * already learned that shape from the eviction guard, whose refusal text must
 * never name {@code allow_evict} because a model read the suggestion and used
 * the override within one turn. Here the override <em>is</em> the parameter, so
 * the same fix is not available.
 *
 * <p>What survives is the half that carries information rather than ceremony:
 * <ul>
 *   <li>Every response carrying decompiler C is <b>stamped</b> with
 *       {@code language_id} and {@code variant}, so pseudocode can be audited
 *       after the fact for the dialect that produced it.</li>
 *   <li>When the processor genuinely offers more than one <em>decoder</em>, the
 *       response also carries an <b>advisory</b> ({@code variant_ambiguous} plus
 *       the candidate names) alongside the code. Visible at the moment the C is
 *       handed over, and nobody is refused.</li>
 *   <li>A caller that <em>does</em> name a variant and names the wrong one is
 *       <b>refused</b> ({@link #VARIANT_MISMATCH}). That refusal is never
 *       ceremony: the caller volunteered a belief and the program contradicts
 *       it. Answering anyway would return one dialect's output under a label the
 *       caller chose, which is worse than no answer because the label makes it
 *       look checked.</li>
 * </ul>
 *
 * <p>This is detection by the reader, not prevention. Nothing here stops a
 * caller from decompiling a VLE image as classic PowerPC and never looking at
 * the stamp; what would prevent that is a coherence heuristic on the loaded
 * program, which is a different and much larger feature.
 *
 * <p>This class is deliberately free of Ghidra imports so the whole decision
 * table is exercised offline by {@code LanguageVariantsTest}. The Ghidra-facing
 * half (enumerating the variants and decoders a processor actually offers) lives
 * in {@link ServiceUtils#languageVariantChoices} and {@link ServiceUtils#variantGate}.
 *
 * @since 7.0.0
 */
public final class LanguageVariants {

    private LanguageVariants() {}

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
     * ({@code PowerISA-VLE-64-32addr}). Both spellings are accepted:
     * {@code get_language_metadata} reports the full id, and echoing back the
     * thing you were just shown is the first thing anyone tries.
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

    /**
     * Whether this processor/endian/size bucket offers a genuine <em>decoding</em>
     * choice, judged by the number of distinct SLEIGH decoders ({@code .sla}
     * files) its variants load rather than by the number of rows.
     *
     * <p>Measured against Ghidra 12.1.2's own {@code .ldefs}: 30 of 83
     * processor/endian/size buckets hold more than one variant row, but only
     * <b>19</b> hold more than one decoder, covering 96 of 177 non-deprecated
     * languages instead of 124. The 11 that drop out are the ones where the
     * variants are the same decoder configured differently — all three x86
     * buckets ({@code x86.sla} for {@code default} and {@code System Management
     * Mode}, {@code x86-64.sla} for {@code default} and {@code compat32}), plus
     * MIPS/64, tricore, Z80, Z180, HC05, HC08 and HCS08. The ones that stay are
     * the ones worth saying something about: PowerPC/BE/32 (eleven variants, ten
     * decoders, VLE among them), PowerPC/LE/32, both ARM/32 buckets, PIC-16,
     * PIC-24, MIPS/32, AARCH64, SuperH, 68000, RISCV and Dalvik.
     *
     * <p>Honest about its own limit: this is a proxy for plausibility, not a
     * proof of identity. {@code x86-16.pspec} sets {@code addrsize}/{@code opsize}
     * context defaults and {@code mips64micro.pspec} sets {@code RELP}, so those
     * same-decoder variants <em>do</em> decode differently — they are simply
     * modes no PE/ELF loader auto-selects, which is why they are not worth an
     * advisory on every response. A distinct {@code .sla} means the loader chose
     * between two different decoder programs, and that is a guess. The cases this
     * proxy lets through are covered by the stamp, which ships unconditionally.
     *
     * @param decoders one decoder identifier per variant on offer; blanks ignored
     */
    public static boolean isAmbiguous(Collection<String> decoders) {
        LinkedHashSet<String> distinct = new LinkedHashSet<>();
        if (decoders != null) {
            for (String d : decoders) {
                String n = key(d);
                if (!n.isEmpty()) distinct.add(n);
            }
        }
        return distinct.size() > 1;
    }

    /**
     * The sentence that rides along with accepted pseudocode on an ambiguous
     * processor. Built from the actual candidates: an earlier version hard-coded
     * the PowerPC/VLE example into every message, which told an ARM caller about
     * a processor it was not using.
     */
    public static String ambiguityNotice(Collection<String> names, String loadedVariant) {
        List<String> all = variantNames(names, loadedVariant);
        return "This processor offers " + all.size() + " SLEIGH variants at this endian/size ("
                + joinVariants(all) + ") that do not all decode the same bytes into the same "
                + "instructions, and this output was produced under '" + normalize(loadedVariant)
                + "' — the variant Ghidra's loader chose at import, which is a guess. If that is "
                + "not the dialect this binary targets the C above is plausible and wrong; re-import "
                + "with import_file(language=...) or change it under Language > Set Language. Pass "
                + "variant= on this call to have that assumption checked instead of assumed.";
    }

    /**
     * Decide whether a decompile may proceed under the caller's variant
     * selection. Returns {@code null} when it may.
     *
     * <p>The decision table:
     * <ul>
     *   <li>Nothing requested: proceed. The caller stated no belief, so there is
     *       nothing to contradict; the response is stamped with what actually ran
     *       and, on an ambiguous processor, carries the advisory.</li>
     *   <li>Requested matches what is loaded: proceed. The caller's belief is
     *       confirmed, and the stamp records it.</li>
     *   <li>Requested is a real variant of this processor but not the loaded one:
     *       {@link #VARIANT_MISMATCH}. Never softened to a warning. The decompiler
     *       decodes with the language the program was imported under and cannot be
     *       asked for another, so answering anyway returns output for a different
     *       question than the one asked, under a label the caller chose.</li>
     *   <li>Requested is not a variant of this processor: {@link #UNKNOWN_VARIANT}.</li>
     * </ul>
     *
     * <p>A mismatch is checked even when the processor has only one variant. A
     * caller that asks for VLE on an x86 program has mistaken which program it is
     * talking to, and that is worth catching where it is cheapest to fix.
     */
    public static Rejection check(String languageId, String loadedVariant,
                                  Collection<String> availableVariants, String requested) {
        String id = normalize(languageId);
        String loaded = normalize(loadedVariant);
        List<String> names = variantNames(availableVariants, loaded);
        String req = normalize(requested);

        // No claim, no contradiction. The label on the way out is what tells the
        // caller which dialect produced the code.
        if (req.isEmpty()) return null;

        // A full-id spelling is compared whole. Comparing only its variant column
        // would let "PowerPC:BE:64:default" satisfy a 32-bit program, which is a
        // bigger mistake than the one this check exists to catch.
        if (looksLikeLanguageId(req)) {
            if (req.equalsIgnoreCase(id)) return null;
            // The suggestion carries the caller's own spelling, not its variant
            // column: variantToken("PowerPC:BE:64:VLE-32addr") is "VLE-32addr",
            // which is not a variant name Ghidra 12.1.2 offers (the picker calls
            // it PowerISA-VLE-64-32addr), so echoing the token back would name
            // something import_file would reject.
            return new Rejection(VARIANT_MISMATCH, idMismatchMessage(req, id),
                                 switchSuggestion(id, loaded, req));
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

    private static String confirmSuggestion(String languageId, String loadedVariant) {
        return "This program is loaded as '" + loadedVariant + "' (" + languageId + "). Omit "
                + "variant= to decompile what is loaded, or pass variant=" + loadedVariant + " to "
                + "assert that is the variant this binary targets. If it is the wrong variant, "
                + "decompiling under it produces wrong C, so fix the program first by re-importing "
                + "with import_file(language=\"processor:endian:size:variant\") or by changing it in "
                + "Ghidra under Language > Set Language.";
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

    private static String switchSuggestion(String languageId, String loadedVariant, String requested) {
        return "Either decompile what is actually loaded by re-sending variant=" + loadedVariant
                + " (or omitting variant= entirely), or make '" + requested + "' real first by "
                + "re-importing the file with import_file(language=...) or changing the program's "
                + "language in Ghidra under Language > Set Language. This endpoint will not "
                + "reinterpret " + languageId + " bytes under another variant.";
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
