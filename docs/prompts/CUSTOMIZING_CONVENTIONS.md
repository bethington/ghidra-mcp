# Customizing Naming Conventions

Ghidra MCP ships with an opinionated convention layer: PascalCase function
names with verb-tier specificity, Hungarian prefixes on globals,
Algorithm/Parameters/Returns plate comments, the `g_` prefix on globals.
v7.3+ exposes the whole layer as `naming.*` settings (see
`get_settings` and the key table in `TOOL_USAGE_GUIDE.md`).

## Three layers

| Layer | How | Scope |
| --- | --- | --- |
| **Operator settings** | Server env (`GHIDRA_MCP_NAMING_…`), project/local/program stores, Ghidra Tool Option for mode | Shared rules for everyone on that scope |
| **GUI strict checkbox** | `Edit ▸ Tool Options ▸ GhidraMCP ▸ Strict Naming Enforcement` | Writes `naming.mode` at **local** scope (`enforce` when checked, `warn` when not) |
| **Per-call override** | `strict_mode` on rename / global / apply-type endpoints | One HTTP request |

`naming.mode` is a **guardrail**: agents may only tighten it (`off` → `warn` →
`enforce`). Every other `naming.*` key is **operator-only** — agents can read
them via `get_settings` but not `set_setting`.

`naming.override` controls whether a per-call `strict_mode` may be **lower**
than the resolved `naming.mode` (`allow`, default, or `deny`).

## Setting values

### Server environment

Each key maps to an environment variable: `GHIDRA_MCP_` + the key in
uppercase with dots as underscores. Examples:

```bash
export GHIDRA_MCP_NAMING_MODE=enforce
export GHIDRA_MCP_NAMING_FUNCTION_VERBS_ADD="+Sniff,-Process"
export GHIDRA_MCP_NAMING_PLATE_REQUIRED_SECTIONS="Algorithm,Parameters,Returns"
```

List keys accept comma-separated values. Use `+item` / `-item` at project,
local, or program scope to adjust list-delta keys without replacing the whole
list (same rules as `set_setting`).

### Project, local, and program scope

Use `set_setting` for **preference** keys only. Operator `naming.*` keys must
be set by the operator:

- **Project** — versioned with the shared Ghidra project (`.ghidra-mcp/settings`
  on the project; see `TOOL_USAGE_GUIDE.md`).
- **Local** — this machine only (including the Ghidra Tool Option checkbox for
  `naming.mode`).
- **Program** — one binary; pass `program=` on `set_setting` when the key allows
  program scope.

Headless/Docker operators typically use server env; GUI users use Tool Options
plus project/local stores.

## Key reference (`naming.*`)

| Key | Default | Meaning |
| --- | --- | --- |
| `naming.mode` | `enforce` | `off`, `warn`, or `enforce` |
| `naming.override` | `allow` | `allow` or `deny` per-call strictness below mode |
| `naming.function.min_length` | `8` | Minimum function name length (main part) |
| `naming.function.verbs_add` | (empty) | Extra allowed verbs (`+Sniff`) |
| `naming.function.verbs_remove` | (empty) | Built-in verbs to drop |
| `naming.function.verb_tiers` | (empty) | `Verb:tier` overrides (tier 1–3) |
| `naming.function.weak_nouns_add` | (empty) | Extra weak nouns |
| `naming.function.weak_nouns_remove` | (empty) | Built-in weak nouns to allow |
| `naming.hungarian.auto_fix` | `true` | Auto-fix struct field Hungarian prefixes |
| `naming.hungarian.prefixes` | (empty) | `type:prefix` extra mappings |
| `naming.global.validate` | `true` | Global name quality checks |
| `naming.global.require_g_prefix` | `true` | Require `g_` on globals |
| `naming.global.min_descriptor_length` | `2` | Min length after `g_` |
| `naming.plate.validate` | `true` | Plate structure validation |
| `naming.plate.required_sections` | `Algorithm,Parameters,Returns` | Required headings |
| `naming.plate.min_first_line_words` | `4` | Summary line word count |

## Examples

**Add a domain verb** (project scope, operator sets via project settings store or
server env):

```text
naming.function.verbs_add=+Sniff
```

**Relax enforcement for a team** (operator only):

```text
naming.mode=warn
```

**Block agents from loosening strictness per call**:

```text
naming.override=deny
```

**Custom plate sections**:

```text
naming.plate.required_sections=Purpose,InputOutput
```

## Per-call `strict_mode`

Rename and related write endpoints accept `strict_mode=off|warn|enforce` for
that request only. When `naming.override` is `deny`, a value below the
resolved `naming.mode` is refused. Raising strictness is always allowed.

## Defaults

Unset keys use the built-in defaults above — the same behavior as pre-v7.3
hardcoded rules. See `ConventionConfig.defaults()` in the Java sources for the
authoritative field-by-field baseline.
