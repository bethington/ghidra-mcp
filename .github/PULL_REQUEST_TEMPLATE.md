<!--
Target `dev`, not `main`. `dev` is the default branch.

If this is your first PR here, GitHub will hold the workflow runs until a
maintainer approves them. An empty check list means you are waiting on the
maintainer, not the other way round — say so in a comment if it sits.
-->

## What this changes

<!-- One or two sentences. What was broken or missing, and what it does now. -->

Fixes #

## Why

<!--
The problem, not just the diff. If there is a reproduction, put it here so the
next person can confirm the fix rather than trusting it.
-->

## Tests you ran

Tick what you ran and paste the result. **"Could not run — no Ghidra project set
up" is a completely acceptable answer.** Saying nothing is not.

- [ ] `uv run pytest tests/unit/` — Python unit tier, no Ghidra needed
- [ ] `mvn test -Dtest='com.xebyte.offline.*Test'` — offline Java tier, needs the
      Ghidra jars but no running server
- [ ] `powershell -File tests\pester\Run-Tests.ps1` — only if you touched
      `ghidra-mcp-setup.ps1`
- [ ] Live tier (`pytest tests/ -m readonly`, `mvn test`) — needs Ghidra running
      on port 8089 with a program loaded
- [ ] Could not run the live tier

```text
paste the output here
```

## If you touched an @McpTool or @Param annotation

Both generated artifacts have to be refreshed, or CI fails in two different
tiers:

- [ ] `mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true`
- [ ] `python -m tools.gen_readme_api_reference --write`
- [ ] Not applicable

## Checklist

- [ ] Branched from `dev` and targeting `dev`
- [ ] `CHANGELOG.md` updated, if this is user-visible
- [ ] No unrelated reformatting mixed into the diff

<!--
On review: small gaps are usually fixed in a follow-up maintainer commit rather
than bounced back to you, so a merge is not a claim the work was flawless and a
follow-up commit on top of yours is not a criticism. See CONTRIBUTING.md.
-->
