# 📚 Documentation Index

> **Complete navigation guide** for all Ghidra MCP documentation. Updated November 6, 2025.

**Quick Links**: [Getting Started](#-getting-started) | [API Reference](#-api--reference) | [Guides](#-guides) | [Analysis](#-analysis) | [Project Info](#-project-info)

---

## 📊 Project Status

- **Version**: 1.9.2
- **MCP Tools**: 111 tools (108 analysis + 3 lifecycle)
- **Build Status**: ✅ Production ready
- **Documentation Coverage**: 100%
- **Package**: com.xebyte

---

## 🚀 Getting Started

Start here if you're new to the project.

| Document | Purpose | Read Time | Priority |
|----------|---------|-----------|----------|
| [README.md](README.md) | Installation, setup, and project overview | 20-30 min | ⭐ START HERE |
| [START_HERE.md](START_HERE.md) | Quick navigation and learning paths | 5-10 min | ⭐ NEW USERS |
| [CLAUDE.md](CLAUDE.md) | AI assistant configuration and integration | 10-15 min | 🤖 AI Setup |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes | 5 min | 📋 Reference |
| [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) | Complete project organization guide | 15-20 min | 📂 Organization |

---

## 📖 API & Reference

Complete technical reference documentation.

| Document | Description | Audience |
|----------|-------------|----------|
| [docs/API_REFERENCE.md](docs/API_REFERENCE.md) | Complete MCP tools documentation (109 tools) | All users |
| [docs/GHIDRA_MCP_TOOLS_REFERENCE.md](docs/GHIDRA_MCP_TOOLS_REFERENCE.md) | Quick tools reference guide | Developers |
| [docs/TOOL_REFERENCE.md](docs/TOOL_REFERENCE.md) | Tool usage patterns and examples | Users |
| [docs/DATA_TYPE_TOOLS.md](docs/DATA_TYPE_TOOLS.md) | Advanced data structure analysis | Advanced |
| [docs/ERROR_CODES.md](docs/ERROR_CODES.md) | Error code reference | Troubleshooting |
| [docs/PERFORMANCE_BASELINES.md](docs/PERFORMANCE_BASELINES.md) | Performance metrics and optimization | Developers |

---

## 🎓 Guides

Comprehensive workflow and topic guides organized by category.

### 📘 Development & Setup

| Guide | Purpose | Level |
|-------|---------|-------|
| [docs/DEVELOPMENT_GUIDE.md](docs/DEVELOPMENT_GUIDE.md) | Development setup and workflows | Beginner |
| [docs/HYBRID_PROCESSOR_GUIDE.md](docs/HYBRID_PROCESSOR_GUIDE.md) | Hybrid function processor guide | Intermediate |
| [docs/D2_BINARY_ANALYSIS_INTEGRATION_GUIDE.md](docs/D2_BINARY_ANALYSIS_INTEGRATION_GUIDE.md) | Binary analysis integration | Advanced |
| [docs/D2_CONVENTION_SCRIPTS_README.md](docs/D2_CONVENTION_SCRIPTS_README.md) | Convention detection scripts | Intermediate |

### 🔧 Ordinal Import Restoration (5 files)

Fix broken ordinal-based imports in DLLs when function names change.

| Guide | Purpose | Time | When to Use |
|-------|---------|------|-------------|
| [docs/guides/ORDINAL_QUICKSTART.md](docs/guides/ORDINAL_QUICKSTART.md) | Fast ordinal fix (key steps only) | 15-30 min | ⭐ Start here |
| [docs/guides/ORDINAL_AUTO_FIX_WORKFLOW.md](docs/guides/ORDINAL_AUTO_FIX_WORKFLOW.md) | Automated ordinal restoration | 20-30 min | After quickstart |
| [docs/guides/ORDINAL_RESTORATION_TOOLKIT.md](docs/guides/ORDINAL_RESTORATION_TOOLKIT.md) | Complete ordinal fixing workflow | 45-60 min | Full details |
| [docs/guides/ORDINAL_LINKAGE_GUIDE.md](docs/guides/ORDINAL_LINKAGE_GUIDE.md) | Deep technical details | 30-45 min | Advanced |
| [docs/guides/ORDINAL_INDEX.md](docs/guides/ORDINAL_INDEX.md) | Quick reference lookup | As needed | Reference |

**Use Case**: Binary has "Ordinal_123" style imports instead of function names

### 🔬 Structure Discovery & Analysis

| Guide | Focus | Level |
|-------|-------|-------|
| [docs/guides/README_STRUCTURE_DISCOVERY.md](docs/guides/README_STRUCTURE_DISCOVERY.md) | Structure discovery overview | ⭐ Start |
| [docs/guides/STRUCTURE_DISCOVERY_MASTER_GUIDE.md](docs/guides/STRUCTURE_DISCOVERY_MASTER_GUIDE.md) | Complete methodology | Advanced |
| [docs/guides/STRUCTURE_DISCOVERY_PROMPT.md](docs/guides/STRUCTURE_DISCOVERY_PROMPT.md) | Discovery workflow | Intermediate |
| [docs/guides/STRUCTURE_APPLICATION_WORKFLOW.md](docs/guides/STRUCTURE_APPLICATION_WORKFLOW.md) | Apply structures | Intermediate |
| [docs/guides/STRING_DETECTION_GUIDE.md](docs/guides/STRING_DETECTION_GUIDE.md) | String analysis | All |
| [docs/guides/STRING_DETECTION_QUICK_REFERENCE.md](docs/guides/STRING_DETECTION_QUICK_REFERENCE.md) | String quick ref | Reference |

### 🐛 Troubleshooting & Fixes

| Guide | Problem Solved |
|-------|----------------|
| [docs/guides/REGISTER_REUSE_FIX_GUIDE.md](docs/guides/REGISTER_REUSE_FIX_GUIDE.md) | Fix decompilation register issues |
| [docs/guides/EBP_REGISTER_REUSE_SOLUTIONS.md](docs/guides/EBP_REGISTER_REUSE_SOLUTIONS.md) | EBP register reuse problems |
| [docs/guides/NORETURN_FIX_GUIDE.md](docs/guides/NORETURN_FIX_GUIDE.md) | No-return function issues |
| [docs/guides/CALL_RETURN_OVERRIDE_CLEANUP.md](docs/guides/CALL_RETURN_OVERRIDE_CLEANUP.md) | Clean call/return overrides |
| [docs/guides/ORPHANED_CALL_RETURN_OVERRIDES.md](docs/guides/ORPHANED_CALL_RETURN_OVERRIDES.md) | Fix orphaned overrides |
| [docs/troubleshooting/TROUBLESHOOTING_PLUGIN_LOAD.md](docs/troubleshooting/TROUBLESHOOTING_PLUGIN_LOAD.md) | Plugin loading problems |

### 📊 Data Analysis

| Guide | Purpose |
|-------|---------|
| [docs/guides/LIST_DATA_BY_XREFS_GUIDE.md](docs/guides/LIST_DATA_BY_XREFS_GUIDE.md) | Find data by cross-references |

---

## 🔬 Analysis

Binary analysis documentation for Diablo II and related binaries.

### 🎮 Diablo II Game Binaries (13 files)

Detailed analysis with structures, functions, and data references.

| Binary | File | Key Content |
|--------|------|-------------|
| **Game.exe** | [docs/analysis/GAME_EXE_BINARY_ANALYSIS.md](docs/analysis/GAME_EXE_BINARY_ANALYSIS.md) | ⭐ Main executable, entry point, initialization |
| **D2Client.dll** | [docs/analysis/D2CLIENT_BINARY_ANALYSIS.md](docs/analysis/D2CLIENT_BINARY_ANALYSIS.md) | Client-side game logic, UI, rendering |
| **D2Common.dll** | [docs/analysis/D2COMMON_BINARY_ANALYSIS.md](docs/analysis/D2COMMON_BINARY_ANALYSIS.md) | Shared structures (UnitAny, ItemData) |
| **D2Game.dll** | [docs/analysis/D2GAME_BINARY_ANALYSIS.md](docs/analysis/D2GAME_BINARY_ANALYSIS.md) | Game logic and simulation |
| **D2Net.dll** | [docs/analysis/D2NET_BINARY_ANALYSIS.md](docs/analysis/D2NET_BINARY_ANALYSIS.md) | Network communication |
| **D2Multi.dll** | [docs/analysis/D2MULTI_BINARY_ANALYSIS.md](docs/analysis/D2MULTI_BINARY_ANALYSIS.md) | Multiplayer functionality |
| **D2Win.dll** | [docs/analysis/D2WIN_BINARY_ANALYSIS.md](docs/analysis/D2WIN_BINARY_ANALYSIS.md) | Windows/UI integration |
| **D2GFX.dll** | [docs/analysis/D2GFX_BINARY_ANALYSIS.md](docs/analysis/D2GFX_BINARY_ANALYSIS.md) | Graphics rendering |
| **D2GDI.dll** | [docs/analysis/D2GDI_BINARY_ANALYSIS.md](docs/analysis/D2GDI_BINARY_ANALYSIS.md) | Graphics/GDI operations |
| **D2Sound.dll** | [docs/analysis/D2SOUND_BINARY_ANALYSIS.md](docs/analysis/D2SOUND_BINARY_ANALYSIS.md) | Audio system |
| **D2Lang.dll** | [docs/analysis/D2LANG_BINARY_ANALYSIS.md](docs/analysis/D2LANG_BINARY_ANALYSIS.md) | Language/string resources |
| **D2CMP.dll** | [docs/analysis/D2CMP_BINARY_ANALYSIS.md](docs/analysis/D2CMP_BINARY_ANALYSIS.md) | Compression algorithms |
| **D2Launch.exe** | [docs/analysis/D2LAUNCH_BINARY_ANALYSIS.md](docs/analysis/D2LAUNCH_BINARY_ANALYSIS.md) | Game launcher |
| **D2MCPClient.dll** | [docs/analysis/D2MCPCLIENT_BINARY_ANALYSIS.md](docs/analysis/D2MCPCLIENT_BINARY_ANALYSIS.md) | Network/MCP client |

### 📚 Support Libraries (5 files)

| Library | File | Purpose |
|---------|------|---------|
| **Storm.dll** | [docs/analysis/STORM_BINARY_ANALYSIS.md](docs/analysis/STORM_BINARY_ANALYSIS.md) | Blizzard Storm library (core engine) |
| **FOG.dll** | [docs/analysis/FOG_BINARY_ANALYSIS.md](docs/analysis/FOG_BINARY_ANALYSIS.md) | Fog of war, visibility |
| **BnClient.dll** | [docs/analysis/BNCLIENT_BINARY_ANALYSIS.md](docs/analysis/BNCLIENT_BINARY_ANALYSIS.md) | Battle.net client |
| **Smackw32.dll** | [docs/analysis/SMACKW32_BINARY_ANALYSIS.md](docs/analysis/SMACKW32_BINARY_ANALYSIS.md) | Video playback library |
| **PD2_Ext.dll** | [docs/analysis/PD2_EXT_BINARY_ANALYSIS.md](docs/analysis/PD2_EXT_BINARY_ANALYSIS.md) | ProjectD2 extensions |

**How to use**: Find your binary → Open analysis file → Search for function/structure → Review implementation

---

## 📋 Project Info

Project management, reports, and organizational documentation.

### 📊 Reports & Status

| Document | Content | Updated |
|----------|---------|---------|
| [docs/reports/PROJECT_CLEANUP_SUMMARY.md](docs/reports/PROJECT_CLEANUP_SUMMARY.md) | Project cleanup summary | Nov 2025 |
| [docs/reports/QUICKWIN_COMPLETION_REPORT.md](docs/reports/QUICKWIN_COMPLETION_REPORT.md) | Quick wins completion | 2025 |
| [docs/reports/SESSION_SUMMARY_BINARY_ANALYSIS.md](docs/reports/SESSION_SUMMARY_BINARY_ANALYSIS.md) | Binary analysis session | 2025 |
| [VERSION_FIX_COMPLETE.md](VERSION_FIX_COMPLETE.md) | Version fix completion | 2025 |
| [VERSION_MANAGEMENT_COMPLETE.md](VERSION_MANAGEMENT_COMPLETE.md) | Version management complete | 2025 |
| [CLEANUP_FINAL_REPORT.md](CLEANUP_FINAL_REPORT.md) | Final cleanup report | 2025 |

### 🛠️ Configuration & Standards

| Document | Purpose |
|----------|---------|
| [NAMING_CONVENTIONS.md](NAMING_CONVENTIONS.md) | Naming standards and conventions |
| [MAVEN_VERSION_MANAGEMENT.md](MAVEN_VERSION_MANAGEMENT.md) | Maven versioning guide |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |

### 📈 Improvements & Changes

| Document | Content |
|----------|---------|
| [IMPROVEMENTS.md](IMPROVEMENTS.md) | Project improvements log |
| [IMPROVEMENTS_QUICK_REFERENCE.md](IMPROVEMENTS_QUICK_REFERENCE.md) | Quick reference guide |
| [MCP_TOOLS_IMPROVEMENTS.md](MCP_TOOLS_IMPROVEMENTS.md) | MCP tools changelog |
| [GAME_EXE_IMPROVEMENTS.md](GAME_EXE_IMPROVEMENTS.md) | Game.exe analysis improvements |

### 🧠 AI & Strategy

| Document | Purpose |
|----------|---------|
| [docs/AGENT_ITERATION_STRATEGIES.md](docs/AGENT_ITERATION_STRATEGIES.md) | AI agent iteration strategies |
| [docs/prompts/](docs/prompts/) | AI analysis workflow prompts (8 files) |

---

## 🎯 Quick Navigation

### By Task

**"I want to get started"**
1. New user? → [README.md](README.md) (20 min)
2. Quick reference? → [START_HERE.md](START_HERE.md) (5 min)
3. AI assistant? → [CLAUDE.md](CLAUDE.md) (15 min)

**"I want to analyze a function"**
1. [docs/prompts/OPTIMIZED_FUNCTION_DOCUMENTATION.md](docs/prompts/OPTIMIZED_FUNCTION_DOCUMENTATION.md) ⭐
2. [docs/API_REFERENCE.md](docs/API_REFERENCE.md) (tool reference)

**"I want to discover structures"**
1. [docs/guides/README_STRUCTURE_DISCOVERY.md](docs/guides/README_STRUCTURE_DISCOVERY.md) ⭐
2. [docs/guides/STRUCTURE_DISCOVERY_MASTER_GUIDE.md](docs/guides/STRUCTURE_DISCOVERY_MASTER_GUIDE.md)
3. [docs/examples/punit/](docs/examples/punit/) (real examples)

**"I want to fix ordinal imports"**
1. [docs/guides/ORDINAL_QUICKSTART.md](docs/guides/ORDINAL_QUICKSTART.md) ⭐
2. [docs/guides/ORDINAL_AUTO_FIX_WORKFLOW.md](docs/guides/ORDINAL_AUTO_FIX_WORKFLOW.md)

**"I have a decompilation problem"**
1. Check [docs/guides/](docs/guides/) for fix guides (EBP, register reuse, noreturn)
2. [docs/troubleshooting/](docs/troubleshooting/)

**"I want to analyze a Diablo II binary"**
1. Find your DLL in [Analysis](#-analysis) section above
2. Open corresponding `*_BINARY_ANALYSIS.md`

### By File Type

- **Guides** → [docs/guides/](docs/guides/)
- **Prompts** → [docs/prompts/](docs/prompts/)
- **Examples** → [docs/examples/](docs/examples/)
- **Analysis** → [docs/analysis/](docs/analysis/)
- **API docs** → [docs/API_REFERENCE.md](docs/API_REFERENCE.md)

### By Binary Name

- **D2\*.dll** → [docs/analysis/](docs/analysis/) for `D2*_BINARY_ANALYSIS.md`
- **Game.exe** → [docs/analysis/GAME_EXE_BINARY_ANALYSIS.md](docs/analysis/GAME_EXE_BINARY_ANALYSIS.md)
- **Storm/FOG** → [docs/analysis/](docs/analysis/) for library analysis

---

## 📚 Additional Resources

### Examples & Case Studies

- **[docs/examples/punit/](docs/examples/punit/)** - UnitAny structure discovery (8 files)
- **[docs/examples/diablo2/](docs/examples/diablo2/)** - D2 structures (2 files)

### Conventions

- **[docs/conventions/](docs/conventions/)** - Calling conventions (5 files)
- Custom D2 conventions (d2call, d2regcall, d2mixcall)

### Code Reviews

- **[docs/code-reviews/](docs/code-reviews/)** - Code review documentation

### Archive

- **[docs/archive/](docs/archive/)** - Historical documentation

---

## 📖 Documentation Organization

```
Root Level (Frequently Accessed)
├── README.md                    # Start here
├── START_HERE.md               # Quick guide
├── CHANGELOG.md                # Version history
├── PROJECT_STRUCTURE.md        # Organization guide
└── DOCUMENTATION_INDEX.md      # This file

docs/ (Comprehensive Documentation)
├── API_REFERENCE.md            # Complete API (109 tools)
├── DEVELOPMENT_GUIDE.md        # Development setup
├── guides/                     # Workflow guides
├── analysis/                   # Binary analysis (18 files)
├── prompts/                    # AI workflows (8 files)
├── examples/                   # Case studies
├── conventions/                # Calling conventions
├── troubleshooting/           # Problem solving
├── reports/                    # Project reports
└── releases/                   # Version docs
```

---

## 🔄 Recent Changes

**November 6, 2025 - Documentation Reorganization**
- ✅ Created comprehensive `PROJECT_STRUCTURE.md`
- ✅ Consolidated `DOCUMENTATION_INDEX.md` (this file)
- ✅ Organized documentation by category and purpose
- ✅ Added quick navigation by task
- ✅ Updated all cross-references

**November 2025 - Project Cleanup**
- Removed 42 outdated files
- Organized docs/ subdirectories
- Consolidated duplicate documentation
- Created master documentation index

---

## 📝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Documentation standards
- File organization
- Naming conventions
- Pull request process

---

**Maintained by**: Ghidra MCP Team  
**Last Updated**: November 6, 2025  
**Version**: 1.8.1  
**Status**: ✅ Current

2. Find relevant analysis file in [docs/analysis/](docs/analysis/)
3. Search for your function
4. Use MCP tools to document (rename, type variables, add comments)

**Quick Path**: README.md → Pick analysis file → Use MCP tools

### "I want to FIX ORDINAL IMPORTS"

1. Read [docs/guides/ORDINAL_QUICKSTART.md](docs/guides/ORDINAL_QUICKSTART.md)
2. Run [docs/guides/ORDINAL_AUTO_FIX_WORKFLOW.md](docs/guides/ORDINAL_AUTO_FIX_WORKFLOW.md)
3. Verify results in Ghidra

**Time**: 15-60 minutes depending on import count

### "I want to DISCOVER STRUCTURES"

1. Read: [README.md](README.md) (structure discovery section)
2. Load binary in Ghidra
3. Use MCP tools to:
   - Find cross-references
   - Analyze assembly patterns
   - Create structures
   - Apply to functions

**Time**: 1-3 hours per structure

### "I want to DOCUMENT A BINARY"

1. Setup MCP server ([README.md](README.md))
2. Configure AI assistant ([CLAUDE.md](CLAUDE.md))
3. Load binary and use function documentation workflow
4. Reference [docs/analysis/](docs/analysis/) for patterns
5. Generate comprehensive analysis

**Time**: 2-8 hours depending on binary size

## Search Tips

### By File Type
- **Guides** → [docs/guides/](docs/guides/) (5 files)
- **Analysis** → [docs/analysis/](docs/analysis/) (18 files)
- **Reference** → [docs/reference/](docs/reference/) (5 files)

### By Binary Name
- D2* → Look in [docs/analysis/](docs/analysis/) for D2_BINARY_ANALYSIS.md
- FOG → FOG_BINARY_ANALYSIS.md
- Custom → Check [docs/analysis/](docs/analysis/) or create your own

### By Task
- **Setup** → README.md
- **Workflows** → [docs/guides/](docs/guides/)
- **Examples** → [docs/analysis/](docs/analysis/)
- **Reference** → [docs/reference/](docs/reference/)

## File Statistics

| Location | Files | Type | Purpose |
|----------|-------|------|---------|
| Root | 4 | Documentation | Essential guides |
| docs/guides/ | 5 | Workflow | How-to guides |
| docs/analysis/ | 18 | Reference | Binary analysis |
| docs/reference/ | 5 | Management | Project status |
| **Total** | **32** | **Mixed** | **Complete system** |

---

## Cleanup Status

✅ **Phase 1 Complete** (Nov 2025)
- Removed 42 outdated files
- Reduced root clutter by 27%
- Organized 29 remaining files

✅ **Phase 2 Complete** (Nov 2025)
- Created docs/ subdirectories
- Moved files to appropriate locations
- Updated documentation

⏳ **Phase 3 In Progress** (Nov 2025)
- Consolidated documentation
- Fixed formatting issues
- Updated .gitignore

## How to Use This Index

1. **Find what you need**: Use tables above
2. **Choose your path**: Pick a task from "Search Tips"
3. **Read the file**: Follow links to actual documentation
4. **Take action**: Apply what you learned

## Recent Changes (Nov 2025)

- Reorganized documentation into docs/ subdirectories
- Moved 29 markdown files to organized structure
- Fixed START_HERE.md formatting
- Created comprehensive index (this file)
- Updated .gitignore for build artifacts
- Removed 42 outdated files

## Version Info

- **Ghidra MCP**: Latest version (see pom.xml)
- **Documentation**: Current as of Nov 2025
- **Status**: Production-ready
- **Maintained**: Active development

---

## Quick Reference Card

```
📁 Root Level
├── README.md           - Start here for setup
├── CLAUDE.md           - AI configuration
├── CHANGELOG.md        - What's new
└── START_HERE.md       - Quick navigation

📁 docs/guides/         - Workflows
├── ORDINAL_*.md        - Fix ordinal imports
└── (Other workflows)

📁 docs/analysis/       - References  
├── D2*.md              - Diablo 2 analysis
├── FOG_*.md            - Other binaries
└── (18 total)

📁 docs/reference/      - Status & Management
├── CLEANUP_STATUS.md   - Current status
└── (Project files)
```

---

**Total Documentation**: 32 files  
**Total Size**: ~500 KB  
**Search Time**: < 2 minutes for any topic  
**Production Status**: Ready ✅  

👉 **Start exploring**: Pick a file from the tables above!
