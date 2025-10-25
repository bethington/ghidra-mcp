# Documentation Index

Complete documentation index for the Ghidra MCP Server project.

## 📋 Current Documentation Status

- **Version**: 1.7.3
- **Package**: com.xebyte
- **MCP Tools**: 109 tools (102 implemented + 7 ROADMAP v2.0)
- **Build Status**: ✅ Production ready
- **Documentation Coverage**: 100%
- **Last Updated**: 2025-10-25

## 📚 Core Documentation

| Document | Description | Status |
|----------|-------------|--------|
| [README.md](../README.md) | Main project overview and quick start | ✅ Current |
| [START_HERE.md](../START_HERE.md) | Getting started guide for new users | ✅ Current |
| [CHANGELOG.md](../CHANGELOG.md) | Complete version history and release notes | ✅ Current |
| [API_REFERENCE.md](API_REFERENCE.md) | Complete MCP tools documentation (109 tools) | ✅ Current |
| [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md) | Setup, workflows, and best practices | ✅ Current |
| [DATA_TYPE_TOOLS.md](DATA_TYPE_TOOLS.md) | Advanced data structure analysis tools | ✅ Current |
| [CLAUDE.md](../CLAUDE.md) | AI assistant configuration and project guidance | ✅ Current |

## 📂 Documentation Structure

```
├── README.md                      # Installation & project overview
├── START_HERE.md                  # Quick start guide
├── CHANGELOG.md                   # Version history
├── CLAUDE.md                      # AI configuration
│
├── docs/
│   ├── DOCUMENTATION_INDEX.md    # This file - central navigation
│   ├── API_REFERENCE.md          # Complete API documentation (109 tools)
│   ├── DEVELOPMENT_GUIDE.md      # Development setup and workflows
│   ├── DATA_TYPE_TOOLS.md        # Data structure tools guide
│   ├── GHIDRA_MCP_TOOLS_REFERENCE.md  # Tools reference
│   ├── HYBRID_PROCESSOR_GUIDE.md # Hybrid function processor
│   ├── AGENT_ITERATION_STRATEGIES.md  # AI agent strategies
│   │
│   ├── prompts/                  # AI analysis workflows (8 files)
│   │   ├── README.md             # Prompts overview
│   │   ├── OPTIMIZED_FUNCTION_DOCUMENTATION.md   # ⭐ Main workflow
│   │   ├── UNIFIED_ANALYSIS_PROMPT.md            # Comprehensive
│   │   ├── ENHANCED_ANALYSIS_PROMPT.md           # Advanced
│   │   ├── QUICK_START_PROMPT.md                 # Beginner
│   │   ├── DATA_DOCUMENTATION_TEMPLATE.md        # Data analysis
│   │   ├── PLATE_COMMENT_FORMAT_GUIDE.md         # Formatting
│   │   └── PLATE_COMMENT_EXAMPLES.md             # Examples
│   │
│   ├── guides/                   # Specialized topic guides (12 files)
│   │   ├── README_STRUCTURE_DISCOVERY.md         # ⭐ Structure guide
│   │   ├── STRUCTURE_DISCOVERY_MASTER_GUIDE.md   # Complete methodology
│   │   ├── STRUCTURE_DISCOVERY_PROMPT.md         # Discovery workflow
│   │   ├── STRUCTURE_APPLICATION_WORKFLOW.md     # Apply structures
│   │   ├── STRING_DETECTION_GUIDE.md             # String analysis
│   │   ├── STRING_DETECTION_QUICK_REFERENCE.md   # String quick ref
│   │   ├── REGISTER_REUSE_FIX_GUIDE.md          # Fix decompilation
│   │   ├── EBP_REGISTER_REUSE_SOLUTIONS.md      # EBP issues
│   │   ├── NORETURN_FIX_GUIDE.md                # No-return functions
│   │   ├── CALL_RETURN_OVERRIDE_CLEANUP.md      # Clean overrides
│   │   ├── ORPHANED_CALL_RETURN_OVERRIDES.md    # Fix orphaned
│   │   └── LIST_DATA_BY_XREFS_GUIDE.md          # Data by xrefs
│   │
│   ├── examples/                 # Real-world case studies
│   │   ├── punit/                # UnitAny structure (8 files)
│   │   │   ├── README_PUNIT_DOCS.md
│   │   │   ├── APPLY_UNITANY_STRUCT_GUIDE.md
│   │   │   ├── PUNIT_FUNCTIONS_DOCUMENTATION.md
│   │   │   ├── PUNIT_QUICK_REFERENCE.md
│   │   │   ├── PUNIT_FUNCTION_INDEX.md
│   │   │   ├── PUNIT_SEARCH_GUIDE.md
│   │   │   ├── PUNIT_STRUCT_APPLICATION_LOG.md
│   │   │   └── PUNIT_STRUCT_APPLICATION_SUMMARY.md
│   │   │
│   │   └── diablo2/              # Diablo II structures (2 files)
│   │       ├── D2_KNOWN_STRUCTURES.md
│   │       └── D2_STRUCTURES_REFERENCE.md
│   │
│   ├── conventions/              # Calling conventions (5 files)
│   │   ├── CONVENTIONS_INDEX.md
│   │   ├── QUICK_REFERENCE_CARD.md
│   │   ├── D2CALL_CONVENTION_REFERENCE.md
│   │   ├── D2REGCALL_CONVENTION_REFERENCE.md
│   │   └── D2MIXCALL_CONVENTION_REFERENCE.md
│   │
│   ├── releases/                 # Version documentation
│   │   ├── v1.7.3/               # Latest
│   │   ├── v1.7.2/
│   │   ├── v1.7.0/
│   │   ├── v1.6.0/
│   │   ├── v1.5.1/
│   │   ├── v1.5.0/
│   │   └── v1.4.0/
│   │
│   ├── troubleshooting/          # Problem resolution
│   │   └── TROUBLESHOOTING_PLUGIN_LOAD.md
│   │
│   ├── code-reviews/             # Code quality reviews
│   ├── reports/                  # Analysis reports
│   └── archive/                  # Historical documentation
```

## 🗂️ Documentation by Purpose

### For New Users

**Start Here:**
1. [START_HERE.md](../START_HERE.md) - Choose your path, get oriented
2. [README.md](../README.md) - Installation and setup
3. [Quick Start Prompt](prompts/QUICK_START_PROMPT.md) - Simple function analysis

**Next Steps:**
4. [OPTIMIZED_FUNCTION_DOCUMENTATION.md](prompts/OPTIMIZED_FUNCTION_DOCUMENTATION.md) - Main workflow
5. [API_REFERENCE.md](API_REFERENCE.md) - Browse available tools
6. [Troubleshooting](troubleshooting/TROUBLESHOOTING_PLUGIN_LOAD.md) - Common issues

### For Function Documentation

**Workflows (Choose One):**
- [OPTIMIZED_FUNCTION_DOCUMENTATION.md](prompts/OPTIMIZED_FUNCTION_DOCUMENTATION.md) - ⭐ Recommended
- [UNIFIED_ANALYSIS_PROMPT.md](prompts/UNIFIED_ANALYSIS_PROMPT.md) - Comprehensive
- [QUICK_START_PROMPT.md](prompts/QUICK_START_PROMPT.md) - Simple/beginner

**Formatting:**
- [PLATE_COMMENT_FORMAT_GUIDE.md](prompts/PLATE_COMMENT_FORMAT_GUIDE.md) - Format rules
- [PLATE_COMMENT_EXAMPLES.md](prompts/PLATE_COMMENT_EXAMPLES.md) - Real examples

### For Structure Discovery

**Complete Workflow:**
1. [README_STRUCTURE_DISCOVERY.md](guides/README_STRUCTURE_DISCOVERY.md) - Overview
2. [STRUCTURE_DISCOVERY_MASTER_GUIDE.md](guides/STRUCTURE_DISCOVERY_MASTER_GUIDE.md) - Methodology
3. [STRUCTURE_DISCOVERY_PROMPT.md](guides/STRUCTURE_DISCOVERY_PROMPT.md) - AI workflow
4. [STRUCTURE_APPLICATION_WORKFLOW.md](guides/STRUCTURE_APPLICATION_WORKFLOW.md) - Apply

**Real Examples:**
- [pUnit/UnitAny Example](examples/punit/) - Complete case study (8 files)
- [Diablo II Structures](examples/diablo2/) - Known structures reference

### For Developers

**Development Setup:**
1. [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md) - Complete dev setup and standards
2. [CLAUDE.md](../CLAUDE.md) - AI assistant configuration
3. [API_REFERENCE.md](API_REFERENCE.md) - All 109 MCP tools

**Build & Deploy:**
- `copy-ghidra-libs.bat` / `.sh` - Copy Ghidra dependencies
- `deploy-to-ghidra.ps1` - Automated deployment
- [CHANGELOG.md](../CHANGELOG.md) - Version history

### For Advanced Users

**Data Structure Analysis:**
- [DATA_TYPE_TOOLS.md](DATA_TYPE_TOOLS.md) - Structure/enum/union tools
- [ENHANCED_ANALYSIS_PROMPT.md](prompts/ENHANCED_ANALYSIS_PROMPT.md) - Advanced workflow
- [DATA_DOCUMENTATION_TEMPLATE.md](prompts/DATA_DOCUMENTATION_TEMPLATE.md) - Data docs

**Troubleshooting:**
- [STRING_DETECTION_GUIDE.md](guides/STRING_DETECTION_GUIDE.md) - String analysis
- [REGISTER_REUSE_FIX_GUIDE.md](guides/REGISTER_REUSE_FIX_GUIDE.md) - Fix decompilation
- [NORETURN_FIX_GUIDE.md](guides/NORETURN_FIX_GUIDE.md) - Handle no-return
- **Archive Management**: Historical docs properly organized
- **Latest Update**: 2025-10-10 (v1.6.0 release)

## 🔄 Recent Changes (v1.6.0)

### Documentation Improvements
- ✅ Reorganized structure with clear subdirectories
- ✅ Created `docs/guides/` for specialized topics
- ✅ Moved utility scripts to `tools/` directory
- ✅ Consolidated implementation reports into release folders
- ✅ Renamed `RELEASE_NOTES.md` to `CHANGELOG.md`
- ✅ Removed redundant `docs/README.md` (merged into this index)
- ✅ Archived outdated configuration docs
- ✅ Updated version references throughout

### New Documentation
- [v1.6.0 Implementation Summary](releases/v1.6.0/IMPLEMENTATION_SUMMARY.md) - New tool implementations
- [v1.6.0 Verification Report](releases/v1.6.0/VERIFICATION_REPORT.md) - Python/Java sync analysis
- [v1.6.0 Feature Status](releases/v1.6.0/FEATURE_STATUS.md) - Recommendations implementation status
- [Quick Start Prompt](prompts/QUICK_START_PROMPT.md) - Simplified beginner workflow

## 🏆 Quality Standards

All documentation follows these standards:

### Structure
- **Clear Headers** - Descriptive section titles
- **Table of Contents** - For documents over 100 lines
- **Status Indicators** - Version numbers and dates
- **Navigation** - Internal links and cross-references

### Content
- **Accuracy** - Verified against current implementation
- **Completeness** - All features documented
- **Examples** - Practical use cases included
- **Troubleshooting** - Common issues addressed

### Maintenance
- **Version Sync** - Updated with each release
- **Link Validation** - All references verified
- **Archive Policy** - Outdated docs moved to archive/
- **Review Cycle** - Quarterly documentation audits

## 📖 Documentation Standards

### File Naming Conventions
- **Release-specific**: Use directory structure, not version in filename
  - ✅ `releases/v1.6.0/IMPLEMENTATION_SUMMARY.md`
  - ❌ `IMPLEMENTATION_SUMMARY_v1.6.0.md`

- **Descriptive names**: Clear purpose
  - ✅ `QUICK_START_PROMPT.md`
  - ❌ `SIMPLE_ANALYSIS_PROMPT.md`

- **Consistent format**: UPPERCASE for major docs, lowercase for code
  - ✅ `README.md`, `API_REFERENCE.md`
  - ✅ `copy-ghidra-libs.bat`, `deploy-to-ghidra.ps1`

### Header Format
All documentation should start with:
```markdown
# Document Title

**Date**: YYYY-MM-DD
**Version**: x.y.z (if version-specific)
**Status**: Current | Historical | Archived

Brief description of document purpose.
```

### Link Format
- Relative links for internal docs: `[Text](../path/to/doc.md)`
- Absolute links for external resources: `[Text](https://example.com)`
- Section anchors: `[Text](#section-name)`

## 🔍 Finding Documentation

### By Task
- **Installing**: [README.md](../README.md#installation)
- **Building**: [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md)
- **Analyzing Functions**: [Unified Analysis Prompt](prompts/UNIFIED_ANALYSIS_PROMPT.md)
- **Analyzing Data**: [Enhanced Analysis Prompt](prompts/ENHANCED_ANALYSIS_PROMPT.md)
- **Creating Structures**: [DATA_TYPE_TOOLS.md](DATA_TYPE_TOOLS.md)
- **Troubleshooting**: [troubleshooting/](troubleshooting/)

### By Audience
- **New Users**: README → Quick Start Prompt → Troubleshooting
- **Developers**: DEVELOPMENT_GUIDE → CLAUDE.md → API_REFERENCE
- **Advanced Users**: Unified Prompt → Enhanced Prompt → Data Type Tools
- **Contributors**: DEVELOPMENT_GUIDE → Code Review Report → CHANGELOG

### By Type
- **Guides**: [guides/](guides/) - In-depth topic coverage
- **Prompts**: [prompts/](prompts/) - Workflow templates
- **Releases**: [releases/](releases/) - Version-specific docs
- **Reports**: [reports/](reports/) - Development analysis
- **Troubleshooting**: [troubleshooting/](troubleshooting/) - Problem resolution

## 📞 Support & Feedback

- **Issues**: Report via GitHub Issues
- **Documentation Requests**: Tag issue with `documentation` label
- **Contribution Guide**: See [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md)

---

**Documentation Status**: ✅ Complete and Current
**Version**: 1.6.0
**Last Updated**: October 10, 2025
**Next Review**: January 10, 2026
