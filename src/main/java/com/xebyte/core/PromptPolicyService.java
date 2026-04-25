package com.xebyte.core;

import ghidra.util.Msg;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.Component;
import java.awt.Container;
import java.awt.Window;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Scoped automation prompt handler for known Ghidra dialogs produced by MCP
 * deploy/regression workflows.
 *
 * This is intentionally narrow: it only runs for a short explicit window and
 * only responds to exact known prompts. Unknown dialogs are left untouched so
 * normal interactive Ghidra work retains its safety prompts.
 */
public class PromptPolicyService {
    private final Object lock = new Object();
    private final Set<Window> handledWindows = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
    private final List<Map<String, Object>> actions = new ArrayList<>();
    private Timer timer;
    private long enabledUntilMillis = 0;
    private String reason = "";

    public void enableFor(String reason, int seconds) {
        int durationSeconds = Math.max(1, Math.min(seconds, 300));
        synchronized (lock) {
            this.reason = reason != null ? reason : "automation";
            this.enabledUntilMillis = System.currentTimeMillis() + durationSeconds * 1000L;
        }
        SwingUtilities.invokeLater(this::ensureTimer);
    }

    public void disable() {
        synchronized (lock) {
            enabledUntilMillis = 0;
            reason = "";
            handledWindows.clear();
        }
        SwingUtilities.invokeLater(() -> {
            if (timer != null) {
                timer.stop();
            }
        });
    }

    public Map<String, Object> status() {
        synchronized (lock) {
            long remaining = Math.max(0, enabledUntilMillis - System.currentTimeMillis());
            return JsonHelper.mapOf(
                "enabled", remaining > 0,
                "remaining_ms", remaining,
                "reason", reason,
                "actions", new ArrayList<>(actions)
            );
        }
    }

    @McpTool(path = "/prompt_policy", method = "POST",
            description = "Temporarily enable, disable, or query scoped automation prompt handling",
            category = "system")
    public Response configure(
            @Param(value = "action", source = ParamSource.BODY, defaultValue = "status",
                    description = "One of: enable, disable, status") String action,
            @Param(value = "reason", source = ParamSource.BODY, defaultValue = "automation",
                    description = "Short reason recorded in prompt-policy logs") String reason,
            @Param(value = "seconds", source = ParamSource.BODY, defaultValue = "120",
                    description = "How long to keep the prompt policy active") int seconds) {
        if ("enable".equalsIgnoreCase(action)) {
            enableFor(reason, seconds);
        } else if ("disable".equalsIgnoreCase(action)) {
            disable();
        }
        return Response.ok(status());
    }

    private void ensureTimer() {
        if (timer == null) {
            timer = new Timer(250, e -> scanDialogs());
            timer.setRepeats(true);
        }
        if (!timer.isRunning()) {
            timer.start();
        }
        scanDialogs();
    }

    private boolean isEnabled() {
        synchronized (lock) {
            return System.currentTimeMillis() < enabledUntilMillis;
        }
    }

    private void scanDialogs() {
        if (!isEnabled()) {
            if (timer != null) {
                timer.stop();
            }
            handledWindows.clear();
            return;
        }
        handledWindows.removeIf(window -> !window.isDisplayable());
        for (Window window : Window.getWindows()) {
            if (!(window instanceof JDialog dialog) || !dialog.isShowing()) {
                continue;
            }
            if (handledWindows.contains(dialog)) {
                continue;
            }
            maybeHandle(dialog);
        }
    }

    private void maybeHandle(JDialog dialog) {
        String title = dialog.getTitle() != null ? dialog.getTitle() : "";
        String text = collectText(dialog.getContentPane()).toLowerCase();

        if (title.equals("Save Tool Changes?") && text.contains("tool chest")) {
            if (selectRadio(dialog.getContentPane(), "None") && clickButton(dialog.getContentPane(), "OK")) {
                record(dialog, "selected None and clicked OK");
            }
            return;
        }

        if (title.equals("Save Modified Files")) {
            if (clickButton(dialog.getContentPane(), "Save")) {
                record(dialog, "clicked Save");
            }
            return;
        }

        if (title.equals("Analyze?")
                && text.contains("has not been analyzed")
                && (text.contains("benchmark.dll") || text.contains("benchmarkdebug.exe"))) {
            if (clickButton(dialog.getContentPane(), "No (Don't ask again)")) {
                record(dialog, "clicked No (Don't ask again)");
            }
        }
    }

    private void record(JDialog dialog, String action) {
        handledWindows.add(dialog);
        Map<String, Object> entry = JsonHelper.mapOf(
            "title", dialog.getTitle(),
            "action", action,
            "time_ms", System.currentTimeMillis(),
            "reason", reason
        );
        synchronized (lock) {
            actions.add(entry);
            if (actions.size() > 50) {
                actions.remove(0);
            }
        }
        Msg.info(this, "GhidraMCP prompt policy: " + entry);
    }

    private String collectText(Component component) {
        StringBuilder builder = new StringBuilder();
        collectText(component, builder);
        return builder.toString();
    }

    private void collectText(Component component, StringBuilder builder) {
        if (component instanceof JLabel label && label.getText() != null) {
            builder.append(' ').append(label.getText());
        }
        if (component instanceof AbstractButton button && button.getText() != null) {
            builder.append(' ').append(button.getText());
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                collectText(child, builder);
            }
        }
    }

    private boolean selectRadio(Component component, String text) {
        if (component instanceof AbstractButton button
                && !(component instanceof JButton)
                && text.equals(stripMnemonic(button.getText()))) {
            button.setSelected(true);
            return true;
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                if (selectRadio(child, text)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean clickButton(Component component, String text) {
        if (component instanceof JButton button && text.equals(stripMnemonic(button.getText()))) {
            button.doClick();
            return true;
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                if (clickButton(child, text)) {
                    return true;
                }
            }
        }
        return false;
    }

    private String stripMnemonic(String text) {
        return text == null ? "" : text.replace("&", "").trim();
    }
}
