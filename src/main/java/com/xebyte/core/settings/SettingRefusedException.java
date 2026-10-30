package com.xebyte.core.settings;

/**
 * A settings read or write that cannot be done, with a message fit to show an agent: it states
 * the fact (unknown key, wrong scope, a guardrail that would loosen) and never names the
 * operator's override, because a refusal that names its escape hatch gets the hatch used.
 */
public class SettingRefusedException extends RuntimeException {
    public SettingRefusedException(String message) {
        super(message);
    }
}
