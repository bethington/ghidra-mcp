package com.xebyte.core;

import java.util.ArrayList;
import java.util.List;

/**
 * The services both servers expose, built once from a provider and a threading strategy.
 *
 * <p>The GUI plugin, the headless server and the offline test factory each used to
 * construct these sixteen by hand, with the same inter-service wiring
 * ({@link DocumentationHashService#setFunctionService}, and {@link AnalysisService} and
 * {@link FunctionBundleService} sharing one {@link FunctionService}). Three copies of a
 * dependency graph drift; one does not.
 *
 * <p>Mode-specific services are not here: {@link DebuggerService} and
 * {@link PromptPolicyService} need a GUI tool, and {@code HeadlessManagementService}
 * owns the headless project lifecycle. Callers add them with {@link #plus}.
 *
 * <p>{@code tools/audit_server_scope.py} reads this record's components to derive which
 * server serves which endpoint, so a service added here is picked up by both servers and
 * by the catalog's {@code servers} field with no further edit.
 */
public record CoreServices(
        ListingService listing,
        CommentService comment,
        SymbolLabelService symbolLabel,
        FunctionService function,
        XrefCallGraphService xrefCallGraph,
        DataTypeService dataType,
        DocumentationHashService documentationHash,
        AnalysisService analysis,
        MalwareSecurityService malwareSecurity,
        ProgramScriptService programScript,
        EmulationService emulation,
        FunctionBundleService functionBundle) {

    public static CoreServices build(ProgramProvider provider, ThreadingStrategy ts) {
        FunctionService function = new FunctionService(provider, ts);
        DocumentationHashService documentationHash =
            new DocumentationHashService(provider, ts, new BinaryComparisonService());
        documentationHash.setFunctionService(function);
        return new CoreServices(
            new ListingService(provider),
            new CommentService(provider, ts),
            new SymbolLabelService(provider, ts),
            function,
            new XrefCallGraphService(provider, ts),
            new DataTypeService(provider, ts),
            documentationHash,
            new AnalysisService(provider, ts, function),
            new MalwareSecurityService(provider, ts),
            new ProgramScriptService(provider, ts),
            new EmulationService(provider, ts),
            new FunctionBundleService(provider, ts, function));
    }

    /** Every shared service, in declaration order. */
    public List<Object> all() {
        return List.of(listing, comment, symbolLabel, function, xrefCallGraph, dataType,
            documentationHash, analysis, malwareSecurity, programScript, emulation,
            functionBundle);
    }

    /** The shared services plus a server's own, ready to hand to {@link AnnotationScanner}. */
    public Object[] plus(Object... extras) {
        List<Object> out = new ArrayList<>(all());
        out.addAll(List.of(extras));
        return out.toArray();
    }
}
