# Customizing Naming Conventions

Ghidra MCP ships with an opinionated convention layer: PascalCase function
names with verb-tier specificity, Hungarian prefixes on globals,
Algorithm/Parameters/Returns plate comments, the `g_` prefix on globals.
That works well for the kind of reverse-engineering work the tool was
built for, but every project has its own house style. v5.11.2 makes the
whole layer customizable on three axes — drop one knob, turn off a whole
section, or replace the entire ruleset.

## Three places convention enforcement gets configured

| Layer | Lives at | Scope | Use when |
| --- | --- | --- | --- |
| **Ghidra Tool Option** (existing) | `Edit ▸ Tool Options ▸ GhidraMCP ▸ Strict Naming Enforcement` | Per Ghidra tool instance | You want a global on/off switch via the GUI. |
| **Project config file** (new) | `<ghidra-project>/.ghidra-mcp/conventions.json` | Per Ghidra project | Your project uses a different convention than the tool's defaults — e.g. snake_case fields, different Hungarian prefixes, no `g_` prefix. |
| **Per-call override** (new) | `strict_mode` query/body param on rename + global + apply-type endpoints | Per HTTP request | A specific automation needs to bypass enforcement for one call — e.g. propagating names from a trusted source. |

The layers compose: the file is loaded at plugin start, the Tool Option
overrides just the *mode* (strict vs. off), and a per-call `strict_mode`
parameter overrides the global setting for the duration of that one
request.

## File location

```
<your-ghidra-project>/                 ← whatever Project.getProjectDir() returns
└── .ghidra-mcp/
    └── conventions.json
```

The file is read once at plugin start (and again any time the Tool Option
is toggled). Missing file = built-in defaults; malformed JSON = built-in
defaults plus a warning in Ghidra's log.

## Schema

Every field is optional — provide only the sections you want to customize.

```json
{
  "strict_mode": "enforce",

  "function_naming": {
    "min_length": 8,
    "verbs_add":       ["Sniff", "Inject", "Patch"],
    "verbs_remove":    [],
    "verb_tier_overrides": { "Process": 1, "Render": 3 },
    "weak_nouns_add":  ["Widget", "Stuff"],
    "weak_nouns_remove": ["Data"]
  },

  "hungarian": {
    "auto_fix_struct_fields": true,
    "extra_prefixes": {
      "u8":  ["byte", "uchar"],
      "u16": ["ushort", "word"]
    }
  },

  "global_naming": {
    "validate": true,
    "require_g_prefix": true,
    "min_descriptor_length": 2
  },

  "plate_comments": {
    "validate": true,
    "required_sections": ["Algorithm", "Parameters", "Returns"],
    "min_first_line_words": 4
  }
}
```

### Field reference

#### `strict_mode` *(string, default `"enforce"`)*

- `"enforce"` — reject low-quality names with a structured rejection (no
  partial writes).
- `"warn"` — accept the write but return a warning in the response.
- `"off"` — skip validation entirely.

The Ghidra Tool Option overrides this. The per-call `strict_mode`
parameter overrides both.

#### `function_naming`

| Field | Effect |
| --- | --- |
| `min_length` (int) | Minimum length of the function-name body (after stripping any `MODULE_` prefix). Default 8. |
| `verbs_add` (list) | Extra verbs to accept in addition to the built-in 70+ verb whitelist. |
| `verbs_remove` (list) | Verbs to *remove* from the built-in whitelist. |
| `verb_tier_overrides` (map) | Reassign a verb's tier (1 = highly specific, 2 = medium, 3 = vague). Tier-3 verbs require ≥2 specifier tokens; demoting `Process` to Tier 1 lets `ProcessPacket` pass. |
| `weak_nouns_add` (list) | Extra tokens to treat as "weak" (contribute no specificity). `GetWidget` would then count as a weak-noun-only rejection. |
| `weak_nouns_remove` (list) | Remove tokens from the built-in weak-noun denylist. E.g. if your domain genuinely uses `Data` as a meaningful term. |

#### `hungarian`

| Field | Effect |
| --- | --- |
| `auto_fix_struct_fields` (bool) | When true, `add_struct_field("count", uint32)` auto-rewrites to `dwCount`. When false, the field name is preserved as supplied (snake_case projects want this off). |
| `extra_prefixes` (map) | Add prefix→type mappings. The map's keys are the prefix you want to teach the validator; values are lists of Ghidra type names that accept the prefix. |

#### `global_naming`

| Field | Effect |
| --- | --- |
| `validate` (bool) | Master toggle. When false, no global-name validation runs at all. |
| `require_g_prefix` (bool) | When false, `ItemList` is acceptable; only the Hungarian / descriptor checks run. |
| `min_descriptor_length` (int) | Minimum chars after the Hungarian prefix. Default 2 (so `g_pX` rejects, `g_pXY` passes). |

#### `plate_comments`

| Field | Effect |
| --- | --- |
| `validate` (bool) | Master toggle. When false, plate-comment validation is skipped at every write endpoint that previously enforced it. |
| `required_sections` (list) | Sections the validator looks for. A line is considered to start a section when it matches `^<Section>$` or `^<Section>:`. Default `["Algorithm", "Parameters", "Returns"]`. |
| `min_first_line_words` (int) | Plate-comment first line must contain at least this many whitespace-separated words. Default 4. |

## Worked example: a non-Hungarian C++ project

Goal: keep convention enforcement on, but switch to a project style that
uses `snake_case` member names, no `g_` prefix on globals, and a
`Purpose / Notes` plate-comment format.

```json
{
  "function_naming": {
    "verbs_add": ["Initialize", "Finalize", "Reset"]
  },
  "hungarian": {
    "auto_fix_struct_fields": false
  },
  "global_naming": {
    "require_g_prefix": false
  },
  "plate_comments": {
    "required_sections": ["Purpose", "Notes"]
  }
}
```

Drop that file at `<project>/.ghidra-mcp/conventions.json`, restart
Ghidra (or hit the Tool Option toggle to force a refresh), and:

- `add_struct_field("entry_count", uint32)` keeps the name as
  `entry_count` instead of rewriting to `dwEntry_count`.
- `rename_or_label(addr, "PlayerInventory")` succeeds — the `g_` prefix
  is no longer required.
- `set_global(addr, name=..., plate_comment="...")` validates against
  the `Purpose`/`Notes` sections instead of the default trio.

## Per-call `strict_mode` override

Five endpoints accept an optional `strict_mode` body parameter:

- `/rename_function_by_address`
- `/apply_data_type`
- `/set_global`
- `/rename_or_label`
- `/rename_global_variable`

Values:

- `"enforce"` — apply strict rejection for this one call, regardless of
  global setting.
- `"warn"` — accept the write and surface warnings.
- `"off"` — skip naming validation entirely for this one call.

Omit the parameter to inherit the project/global setting. Existing
callers that don't pass `strict_mode` see no behavior change.

```http
POST /set_global
Content-Type: application/json

{
  "address": "0x6fd5af00",
  "name": "ItemPriceTable",
  "type_name": "ItemRecord[100]",
  "plate_comment": "Per-class item price modifiers loaded from items.txt",
  "strict_mode": "off"
}
```

## Backwards compatibility

- A project with no `conventions.json` gets exactly the pre-v5.11.2
  hardcoded behavior.
- The existing `Strict Naming Enforcement` Tool Option still works and
  still wins over the file's `strict_mode` field — flipping the GUI
  checkbox to off is a quick way to silence enforcement without editing
  any files.
- Endpoint param signatures are additive — every new parameter is
  optional with a safe default, so existing automation keeps working
  unchanged.

## Troubleshooting

- *Convention file not picked up* — confirm it sits at `<ghidra-project
  directory>/.ghidra-mcp/conventions.json`, not under the binary's
  folder. Toggle the Tool Option off/on to force a reload.
- *Warnings about `verb_tier_overrides`* — tier values must be 1, 2, or
  3. Out-of-range entries are dropped with a warning in Ghidra's log.
- *Plate-comment validation refuses to turn off* — check that you wrote
  `"plate_comments": { "validate": false }` (note the underscore + plural
  on `plate_comments`).
