package com.xebyte.offline;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.xebyte.core.ProgramScriptService;
import java.io.IOException;
import org.junit.Test;

/**
 * Offline coverage for {@code open_program}'s failure message.
 *
 * <p>A program built against an older SLEIGH language revision opens read-ONLY but
 * refuses a read-write open. Before this, the caller got the bare Ghidra string
 * {@code "Minor language change 4.6 -> 4.7"}, which names the symptom and not the
 * cure -- and the FrontEnd open path structurally cannot perform the cure, since
 * it passes {@code okToUpgrade=false} and an upgrade also needs an exclusive
 * checkout. On the diablo2 shared project this presented as "every binary opens
 * read-only and my edits vanish" across 579 programs.
 */
public class ProgramOpenFailureMessageTest {

    @Test
    public void minorLanguageChangeMessageNamesTheRemedy() {
        String message = ProgramScriptService.describeOpenFailure(
                new IOException("Minor language change 4.6 -> 4.7"),
                "/Vanilla/1.01/D2Game.dll");

        assertTrue("must preserve Ghidra's own diagnosis",
                message.contains("Minor language change 4.6 -> 4.7"));
        assertTrue("must name the tool that can actually fix it",
                message.contains("scripts/upgrade_project_language.py"));
        assertTrue("must scope the suggested command to the right folder",
                message.contains("--folder /Vanilla/1.01"));
        assertTrue("must explain why this endpoint cannot do it",
                message.contains("exclusive checkout"));
    }

    @Test
    public void majorLanguageChangeIsAlsoRecognised() {
        String message = ProgramScriptService.describeOpenFailure(
                new IOException("Major language change 4.6 -> 5.0"), "/Vanilla/1.02/Fog.dll");
        assertTrue(message.contains("scripts/upgrade_project_language.py"));
    }

    @Test
    public void olderGhidraVersionWordingIsRecognised() {
        String message = ProgramScriptService.describeOpenFailure(
                new IOException("this file was created with an older version of Ghidra"),
                "/Vanilla/1.03/Storm.dll");
        assertTrue(message.contains("scripts/upgrade_project_language.py"));
    }

    @Test
    public void unrelatedFailuresArePassedThroughUntouched() {
        // Decorating every failure would bury the real cause of unrelated errors
        // under upgrade advice that does not apply.
        String message = ProgramScriptService.describeOpenFailure(
                new IOException("File not found"), "/Vanilla/1.01/Nope.dll");
        assertEquals("File not found", message);
    }

    @Test
    public void nullExceptionMessageDoesNotProduceNullText() {
        String message = ProgramScriptService.describeOpenFailure(
                new IllegalStateException(), "/Vanilla/1.01/D2Game.dll");
        assertTrue(message != null && !message.isEmpty());
        assertTrue(message.contains("IllegalStateException"));
    }

    @Test
    public void rootLevelProgramYieldsRootFolderInTheSuggestion() {
        String message = ProgramScriptService.describeOpenFailure(
                new IOException("Minor language change 4.6 -> 4.7"), "/D2Game.dll");
        assertTrue("a top-level file must not suggest an empty --folder",
                message.contains("--folder /"));
    }

    @Test
    public void pathWithSpacesIsHandled() {
        // "Diablo II.exe" exists in all 25 Vanilla folders.
        String message = ProgramScriptService.describeOpenFailure(
                new IOException("Minor language change 4.6 -> 4.7"),
                "/Vanilla/1.09d/Diablo II.exe");
        assertTrue(message.contains("--folder /Vanilla/1.09d"));
    }
}
