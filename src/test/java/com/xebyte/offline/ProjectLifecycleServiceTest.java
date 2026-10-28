package com.xebyte.offline;

import com.xebyte.core.ProjectLifecycleService;
import com.xebyte.core.Response;
import com.xebyte.headless.HeadlessProgramProvider;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * The GZF and GAR tools, now served by both servers: the argument checks that come before
 * any project work, so a provider with no project reaches them.
 */
public class ProjectLifecycleServiceTest {

    private final ProjectLifecycleService service = new ProjectLifecycleService(new HeadlessProgramProvider());

    private static String message(Response r) {
        assertTrue(r.toString(), r instanceof Response.Err);
        return ((Response.Err) r).message();
    }

    @Test
    public void exportNeedsAProgramName() {
        assertEquals("program_name required", message(service.exportProgram("", "/tmp", "")));
    }

    @Test
    public void importNeedsAGzfPath() {
        assertEquals("gzf_path required", message(service.importProgram("", "/", "", false)));
    }

    @Test
    public void restoreNeedsAnArchivePath() {
        assertEquals("gar_path required", message(service.restoreProject("", "/tmp", "p")));
    }

    @Test
    public void archiveWithNoProjectSaysToOpenOne() {
        assertTrue(message(service.archiveProject("/tmp", "")).contains("No project open"));
    }

    @Test
    public void anOutputNameCannotEscapeTheOutputDirectory() {
        assertTrue(message(service.exportProgram("p", "/tmp", "../x.gzf")).contains("invalid output_name"));
        assertTrue(message(service.archiveProject("/tmp", "../x.gar")).contains("invalid output_name")
            || message(service.archiveProject("/tmp", "../x.gar")).contains("No project open"));
    }
}
