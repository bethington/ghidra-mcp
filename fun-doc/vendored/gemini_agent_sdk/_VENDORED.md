# Vendored: gemini_agent_sdk

This is a verbatim copy of the `gemini_agent_sdk` package from
**[bethington/gemini-agent-sdk](https://github.com/bethington/gemini-agent-sdk)**.

| | |
| --- | --- |
| Upstream repo | https://github.com/bethington/gemini-agent-sdk |
| Pinned commit | `ad1b708935ff7416e3530e0f561720e8bf219298` |
| Pinned version | `0.2.0` |
| Vendored on | 2026-05-15 |

## Why vendored

The Gemini worker provider in `fun_doc.py` needs this SDK. It's
distributed GitHub-only — the obvious PyPI name `gemini-cli-sdk`
belongs to an unrelated project (`oneryalcin/gemini-cli-sdk`), so
`pip install` of the right package is awkward, and `pip install
git+https://...` is fragile in environments with broken libcurl /
locked-down HTTPS (we hit exactly that during setup). Vendoring makes
the Gemini provider work out of the box with no extra install step —
only the `gemini` *binary* itself still needs `npm install -g
@google/gemini-cli`.

## Do not hand-edit

Change the code upstream in the `gemini-agent-sdk` repo, then re-sync:

```bash
python -m scripts.sync_vendored_gemini --source /path/to/gemini-agent-sdk
```

The sync script refreshes these files and rewrites the pinned commit
above. Hand-edits here will be silently overwritten on the next sync.
