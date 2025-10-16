# Ghidra MCP Documentation Prompts

This directory contains optimized prompts for documenting binary code in Ghidra using the MCP tools. These prompts are designed to be used with Claude Code or other AI assistants to systematically reverse engineer and document functions.

## Available Prompts

### Core Documentation Workflows

1. **OPTIMIZED_FUNCTION_DOCUMENTATION.md** ⭐ **RECOMMENDED**
   - Most comprehensive and detailed workflow
   - Complete step-by-step instructions for thorough function documentation
   - Includes verification steps and error handling
   - Best for: Detailed analysis requiring full documentation
   - Use when: Working on critical functions or complex algorithms

2. **SINGLE_FUNCTION_COMPLETE_DOCUMENTATION.md**
   - Concise workflow for single function analysis
   - Structured steps with clear sections
   - Best for: Quick reference during documentation
   - Use when: You need a quick reminder of the workflow

3. **FUNCTION_DOCUMENTATION_WORKFLOW.md**
   - Original workflow in prose format
   - Less structured than the above prompts
   - Best for: Understanding the general approach
   - Use when: Learning the documentation methodology

### Formatting Guides

4. **PLATE_COMMENT_FORMAT_GUIDE.md** ⭐ **ESSENTIAL**
   - Exact template for creating structured function header comments
   - Box-drawing format with precise character counts
   - Detailed formatting rules for sections
   - Best for: Creating consistent, professional plate comments
   - Use when: You need to format function headers correctly

5. **PLATE_COMMENT_EXAMPLES.md** ⭐ **PRACTICAL**
   - Real-world examples of properly formatted plate comments
   - Multiple function types (validation, processing, initialization, etc.)
   - Quick reference templates
   - Best for: Seeing complete examples before creating your own
   - Use when: You need inspiration or want to copy a template

### Specialized Prompts

6. **ENHANCED_ANALYSIS_PROMPT.md**
   - Advanced analysis techniques
   - Best for: Complex reverse engineering scenarios
   - Use when: Standard workflow isn't sufficient

7. **UNIFIED_ANALYSIS_PROMPT.md**
   - Combines multiple analysis approaches
   - Best for: Flexible analysis methodology
   - Use when: You need adaptability in approach

8. **QUICK_START_PROMPT.md**
   - Minimal instructions for rapid documentation
   - Best for: Experienced users who know the tools
   - Use when: You want minimal guidance

## Recommended Usage Workflow

### For Beginners

1. Start with **OPTIMIZED_FUNCTION_DOCUMENTATION.md** to understand the complete process
2. Reference **PLATE_COMMENT_FORMAT_GUIDE.md** when creating function headers
3. Use **PLATE_COMMENT_EXAMPLES.md** to see what good documentation looks like
4. Practice on simple functions before moving to complex ones

### For Experienced Users

1. Use **SINGLE_FUNCTION_COMPLETE_DOCUMENTATION.md** as your primary reference
2. Keep **PLATE_COMMENT_FORMAT_GUIDE.md** open for header formatting
3. Refer to **PLATE_COMMENT_EXAMPLES.md** when documenting different function types
4. Customize based on project-specific conventions

### For High-Volume Documentation

1. Use **document_function_complete** MCP tool for batch operations
2. Follow **OPTIMIZED_FUNCTION_DOCUMENTATION.md** workflow
3. Use **PLATE_COMMENT_EXAMPLES.md** templates for consistency
4. Automate using batch tools (batch_rename_variables, batch_create_labels, etc.)

## Plate Comment Format

The plate comment format is a critical component of documentation. Here's the basic structure:

```c
/**********************************************************************************************
 * [Function summary - one clear sentence]                                                   *
 *                                                                                            *
 * Algorithm:                                                                                 *
 * 1. [First step]                                                                            *
 * 2. [Second step]                                                                           *
 * ...                                                                                        *
 *                                                                                            *
 * Parameters:                                                                                *
 *   paramName: [Description]                                                                 *
 *                                                                                            *
 * Returns:                                                                                   *
 *   [Type]: [What it means]                                                                  *
 *                                                                                            *
 * Special Cases:                                                                             *
 *   - [Edge cases and special handling]                                                      *
 *********************************************************************************************/
```

**Critical formatting rules:**
- Each line must be exactly **96 characters** including newline
- Content lines: ` * ` + content + ` *`
- Top border: `/*` + 93 asterisks
- Bottom border: 1 space + 94 asterisks + `*/`

See **PLATE_COMMENT_FORMAT_GUIDE.md** for complete details and **PLATE_COMMENT_EXAMPLES.md** for working examples.

## Diablo II Specific Conventions

When working with Diablo II binaries, these prompts include specific guidance for:

### Common Structures
- **UnitAny**: dwType, dwUnitId, dwMode, pInventory, pStats, wX, wY
- **Room1/Room2**: pRoom2, dwPosX, dwPosY, dwSizeX, dwSizeY, pLevel
- **PlayerData**: szName, pNormalQuest, pNightmareQuest, pHellQuest
- **ItemData**: dwQuality, dwItemFlags, wPrefix, wSuffix, BodyLocation
- **MonsterData**: anEnchants, wUniqueNo, wName
- **Inventory**: pOwner, pFirstItem, pCursorItem, dwItemCount

### Naming Conventions (Hungarian Notation)
- `dw`: DWORD (dwFlags, dwUnitId)
- `p`/`lp`: Pointers (pNext, lpPlayerUnit)
- `w`: WORD (wLevel, wStatIndex)
- `n`: Counts (nCount, nMaxXCells)
- `sz`: Strings (szName, szGameName)
- `f`/`b`: Boolean (fSaved, bActive)

## Integration with MCP Tools

These prompts are designed to work with the following Ghidra MCP tools:

### Analysis Tools
- `analyze_function_complete`: Get all function info in one call
- `analyze_data_region`: Analyze data structures
- `detect_array_bounds`: Identify array sizes
- `search_functions_enhanced`: Find functions to document

### Documentation Tools
- `document_function_complete`: Apply all changes atomically
- `set_plate_comment`: Add function header
- `batch_set_comments`: Add multiple comments
- `batch_create_labels`: Create jump target labels
- `batch_rename_variables`: Rename multiple variables
- `set_function_prototype`: Define function signature

### Verification Tools
- `analyze_function_completeness`: Check documentation status
- `validate_function_prototype`: Verify prototype syntax
- `can_rename_at_address`: Check if rename will work

## Tips for Effective Documentation

1. **Always verify function boundaries first** - Incorrect boundaries lead to wrong analysis
2. **Use batch operations** - Minimize API calls with batch_* tools
3. **Cross-reference assembly** - Verify offsets match disassembly, not decompiler
4. **Document structures inline** - Include structure layouts in plate comments
5. **Name meaningfully** - Use descriptive names that explain purpose, not just type
6. **Reference magic numbers** - Always explain hex values and sentinel values
7. **Format consistently** - Use the plate comment template for every function

## Common Issues and Solutions

### Plate Comment Formatting
- **Problem**: Lines don't align or exceed 96 characters
- **Solution**: Use PLATE_COMMENT_FORMAT_GUIDE.md template exactly

### Variable Rename Failures
- **Problem**: "Variable not found" errors
- **Solution**: Use analyze_function_complete to get exact variable names first

### Offset Mismatches
- **Problem**: Comments reference wrong offsets
- **Solution**: Always verify against disassembly, not decompiler output

### Connection Timeouts
- **Problem**: batch_* operations timeout
- **Solution**: Split into smaller batches or use individual operations

## Contributing

When creating new prompts or improving existing ones:

1. Test the prompt on multiple function types
2. Verify it produces consistent, accurate documentation
3. Include examples and formatting guidelines
4. Update this README to reference the new prompt
5. Follow the existing structure and style

## Version History

- **v1.6.5**: Added PLATE_COMMENT_FORMAT_GUIDE.md and PLATE_COMMENT_EXAMPLES.md
- **v1.6.0**: Added validation tools and enhanced search
- **v1.5.1**: Added batch operation support
- **v1.5.0**: Initial prompt collection
