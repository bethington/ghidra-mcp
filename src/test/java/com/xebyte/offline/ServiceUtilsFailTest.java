package com.xebyte.offline;

import com.xebyte.core.Response;
import com.xebyte.core.ServiceUtils;
import org.junit.Test;

import java.util.concurrent.ExecutionException;

import static org.junit.Assert.*;

/** Offline coverage for {@link ServiceUtils#fail(Throwable)} and friends. */
public class ServiceUtilsFailTest {

    @Test
    public void failureMessageUsesCauseOfExecutionException() {
        Exception cause = new IllegalStateException("inner detail");
        assertEquals("inner detail",
                ServiceUtils.failureMessage(new ExecutionException(cause)));
    }

    @Test
    public void failureMessageFallsBackToSimpleClassNameWhenMessageNull() {
        assertEquals("NullPointerException",
                ServiceUtils.failureMessage(new NullPointerException()));
    }

    @Test
    public void failBareReturnsErrWithFailureMessage() {
        Response r = ServiceUtils.fail(new NullPointerException());
        assertTrue(r instanceof Response.Err);
        assertEquals("NullPointerException", ((Response.Err) r).message());
    }

    @Test
    public void failWithWhatPrefixesFailed() {
        Response r = ServiceUtils.fail("Rename", new IllegalArgumentException("bad name"));
        assertTrue(r instanceof Response.Err);
        assertEquals("Rename failed: bad name", ((Response.Err) r).message());
    }

    @Test
    public void failWithWhatUsesClassNameWhenMessageNull() {
        Response r = ServiceUtils.fail("list_class_members", new RuntimeException());
        assertTrue(r instanceof Response.Err);
        assertEquals("list_class_members failed: RuntimeException",
                ((Response.Err) r).message());
    }
}
