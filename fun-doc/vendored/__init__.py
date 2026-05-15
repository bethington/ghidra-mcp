"""Vendored third-party packages for fun-doc.

Code in this directory is a verbatim copy of an external package,
committed into the repo so fun-doc has zero install friction for an
otherwise-awkward dependency. Do not hand-edit vendored code — change
it upstream, then re-run the sync script.

Current contents:

  gemini_agent_sdk/  — copy of bethington/gemini-agent-sdk. The Gemini
    worker provider needs it; the package is GitHub-only (the obvious
    PyPI name `gemini-cli-sdk` belongs to an unrelated project) and
    git-install is fragile in some environments. Vendoring makes the
    Gemini provider work out of the box. Re-sync with:

        python -m scripts.sync_vendored_gemini

    See fun-doc/vendored/gemini_agent_sdk/_VENDORED.md for the pinned
    upstream commit.
"""
