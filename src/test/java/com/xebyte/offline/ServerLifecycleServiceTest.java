package com.xebyte.offline;

import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.Response;
import com.xebyte.core.ServerLifecycle;
import com.xebyte.core.ServerLifecycleService;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * /exit_ghidra on both servers: save, answer, then stop. The GUI saved and reported;
 * headless exited and left the saving to its shutdown hook, after the caller had
 * already been told it was done.
 */
public class ServerLifecycleServiceTest {

    private static ProgramScriptService savingTwo() {
        ProgramScriptService programs = mock(ProgramScriptService.class);
        when(programs.saveAllOpenPrograms()).thenReturn(Response.ok(Map.of("saved_count", 2)));
        return programs;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ok(Response r) {
        assertTrue(r.toString(), r instanceof Response.Ok);
        return (Map<String, Object>) ((Response.Ok) r).data();
    }

    @Test
    public void savesThenRespondsThenExitsAfterTheResponseIsOut() throws Exception {
        List<String> order = new ArrayList<>();
        ProgramScriptService programs = mock(ProgramScriptService.class);
        when(programs.saveAllOpenPrograms()).thenAnswer(inv -> {
            order.add("save");
            return Response.ok(Map.of("saved_count", 2));
        });
        CountDownLatch exited = new CountDownLatch(1);
        AtomicBoolean exitedBeforeReturn = new AtomicBoolean();
        AtomicBoolean returned = new AtomicBoolean();
        ServerLifecycle lifecycle = new ServerLifecycle() {
            @Override public void prepare() { order.add("prepare"); }
            @Override public Map<String, Object> saveExtras() { return Map.of("traces", 1); }
            @Override public void exit() {
                exitedBeforeReturn.set(!returned.get());
                exited.countDown();
            }
        };

        Map<String, Object> out = ok(new ServerLifecycleService(programs, lifecycle).exit());
        returned.set(true);

        assertEquals(List.of("prepare", "save"), order);
        assertEquals(true, out.get("success"));
        @SuppressWarnings("unchecked")
        Map<String, Object> save = (Map<String, Object>) out.get("save");
        assertEquals("the programs' own result, integers intact", Map.of("saved_count", 2), save.get("programs"));
        assertEquals("what the server adds is reported beside them", 1, save.get("traces"));
        assertTrue("the process must stop, but only afterwards", exited.await(5, TimeUnit.SECONDS));
        assertFalse("the response must be out before the process ends", exitedBeforeReturn.get());
    }

    @Test
    public void aFailedPrepareRefusesAndNeverExits() throws Exception {
        CountDownLatch exited = new CountDownLatch(1);
        ServerLifecycle lifecycle = new ServerLifecycle() {
            @Override public void prepare() { throw new IllegalStateException("prompt policy unavailable"); }
            @Override public void exit() { exited.countDown(); }
        };
        Response r = new ServerLifecycleService(savingTwo(), lifecycle).exit();
        assertEquals("prompt policy unavailable", ((Response.Err) r).message());
        assertFalse(exited.await(1, TimeUnit.SECONDS));
    }

    @Test
    public void aServerWithNothingExtraReportsJustThePrograms() throws Exception {
        CountDownLatch exited = new CountDownLatch(1);
        Map<String, Object> out = ok(new ServerLifecycleService(savingTwo(), exited::countDown).exit());
        @SuppressWarnings("unchecked")
        Map<String, Object> save = (Map<String, Object>) out.get("save");
        assertEquals(java.util.Set.of("programs"), save.keySet());
        assertTrue(exited.await(5, TimeUnit.SECONDS));
    }
}
