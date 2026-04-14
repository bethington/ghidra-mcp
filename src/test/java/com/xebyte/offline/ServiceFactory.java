package com.xebyte.offline;

import com.xebyte.core.AnalysisService;
import com.xebyte.core.BinaryComparisonService;
import com.xebyte.core.CommentService;
import com.xebyte.core.DataTypeService;
import com.xebyte.core.DocumentationHashService;
import com.xebyte.core.FunctionService;
import com.xebyte.core.ListingService;
import com.xebyte.core.MalwareSecurityService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.SymbolLabelService;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.core.XrefCallGraphService;

/**
 * Builds the full set of service instances that {@link com.xebyte.core.ServerManager}
 * normally constructs at plugin startup — but with stub collaborators so the
 * result is safe to scan offline.
 *
 * This mirrors the order and wiring in
 * {@code ServerManager.registerTool(...)} so the offline tests exercise the
 * same surface the running plugin exposes.
 */
public final class ServiceFactory {

    private ServiceFactory() {}

    /** Build all services wired with stub collaborators, ready for scanning. */
    public static Object[] buildAllServices() {
        ProgramProvider provider = new StubProgramProvider();
        ThreadingStrategy ts = new NoopThreadingStrategy();

        ListingService listingService = new ListingService(provider);
        CommentService commentService = new CommentService(provider, ts);
        SymbolLabelService symbolLabelService = new SymbolLabelService(provider, ts);
        FunctionService functionService = new FunctionService(provider, ts);
        XrefCallGraphService xrefCallGraphService = new XrefCallGraphService(provider, ts);
        DataTypeService dataTypeService = new DataTypeService(provider, ts);
        DocumentationHashService documentationHashService =
            new DocumentationHashService(provider, ts, new BinaryComparisonService());
        documentationHashService.setFunctionService(functionService);
        AnalysisService analysisService = new AnalysisService(provider, ts, functionService);
        MalwareSecurityService malwareSecurityService = new MalwareSecurityService(provider, ts);
        ProgramScriptService programScriptService = new ProgramScriptService(provider, ts);

        return new Object[] {
            listingService,
            functionService,
            commentService,
            symbolLabelService,
            xrefCallGraphService,
            dataTypeService,
            analysisService,
            documentationHashService,
            malwareSecurityService,
            programScriptService,
        };
    }

    /** Convenience: build a {@link StubProgramProvider}. */
    public static ProgramProvider stubProvider() {
        return new StubProgramProvider();
    }
}
