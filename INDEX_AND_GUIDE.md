# Index: Hash-Based Function Renaming Solution

## Quick Navigation

### **I need a quick answer** (5 minutes)
→ Read: `SOLUTION_SUMMARY.md`

### **I need visual understanding** (10 minutes)
→ Read: `VISUAL_COMPARISON_SMemAlloc_Ordinal401.md`

### **I need complete technical details** (1 hour)
→ Read: `HYPOTHESIS_CONFIRMATION_SMemAlloc_Ordinal401.md`

### **I need strategic framework** (45 minutes)
→ Read: `Hash_Based_Function_Renaming_Strategy.md`

### **I need to implement now** (30 minutes)
→ Read: `IMPLEMENTATION_GUIDE_SMemAllocEx_Rename.md`

### **I want everything** (2 hours)
→ Read: `COMPLETE_SOLUTION_PACKAGE.md` (overview), then each section

---

## Document Index

| Document | Length | Audience | Key Info |
|----------|--------|----------|----------|
| `SOLUTION_SUMMARY.md` | 2 pages | Everyone | Quick summary, key findings, next steps |
| `HYPOTHESIS_CONFIRMATION_SMemAlloc_Ordinal401.md` | 15 pages | Technical | Full decompiled code analysis, evidence |
| `Hash_Based_Function_Renaming_Strategy.md` | 12 pages | Tech Lead | Strategic approach, broader implications |
| `IMPLEMENTATION_GUIDE_SMemAllocEx_Rename.md` | 10 pages | Engineer | Step-by-step execution guide |
| `VISUAL_COMPARISON_SMemAlloc_Ordinal401.md` | 8 pages | Visual Learner | Diagrams, side-by-side comparisons |
| `COMPLETE_SOLUTION_PACKAGE.md` | 6 pages | Project Manager | Overview of all materials, roadmap |

---

## Core Finding

**SMemAlloc (Storm.dll 1.07) = Ordinal_401 (Storm.dll 1.08+)**

Same algorithm, same purpose, different compilation → different hashes

**Solution**: Rename Ordinal_401 → SMemAllocEx for consistency

---

## Implementation Path

### Prerequisites
- [ ] Read SOLUTION_SUMMARY.md (agree with approach)
- [ ] Review IMPLEMENTATION_GUIDE_SMemAllocEx_Rename.md (understand process)

### Execution (4 Phases)
1. [ ] Phase 1: Pre-rename verification (check functions exist)
2. [ ] Phase 2: Hash verification (confirm hash matches)
3. [ ] Phase 3: Apply renames (execute rename commands)
4. [ ] Phase 4: Post-rename verification (confirm success)

### Follow-up
- [ ] Document the renames (for audit trail)
- [ ] Analyze other high-priority Ordinals
- [ ] Build hash registry file
- [ ] Plan automated propagation

---

## Key Deliverables

### Documentation (5 files)
✓ SOLUTION_SUMMARY.md  
✓ HYPOTHESIS_CONFIRMATION_SMemAlloc_Ordinal401.md  
✓ Hash_Based_Function_Renaming_Strategy.md  
✓ IMPLEMENTATION_GUIDE_SMemAllocEx_Rename.md  
✓ VISUAL_COMPARISON_SMemAlloc_Ordinal401.md  
✓ COMPLETE_SOLUTION_PACKAGE.md  
✓ This index file

### Code Tools (2 files)
✓ ghidra_scripts/IdentifyAndRenameHashMatches.java  
✓ hash_based_function_renaming.py

---

## Recommended Reading Order

### For Executives/Project Managers
1. SOLUTION_SUMMARY.md (5 min)
2. VISUAL_COMPARISON_SMemAlloc_Ordinal401.md (10 min)
3. COMPLETE_SOLUTION_PACKAGE.md (10 min)
**Total: 25 minutes**

### For Technical Leads
1. SOLUTION_SUMMARY.md (5 min)
2. HYPOTHESIS_CONFIRMATION_SMemAlloc_Ordinal401.md (45 min)
3. Hash_Based_Function_Renaming_Strategy.md (30 min)
**Total: 80 minutes**

### For Implementation Engineers
1. SOLUTION_SUMMARY.md (5 min)
2. IMPLEMENTATION_GUIDE_SMemAllocEx_Rename.md (20 min)
3. Execute Phases 1-4 (30 min)
**Total: 55 minutes execution time**

### For Code Maintainers
1. Hash_Based_Function_Renaming_Strategy.md (30 min)
2. Review hash_based_function_renaming.py (15 min)
3. Review IdentifyAndRenameHashMatches.java (15 min)
**Total: 60 minutes**

---

## Key Questions Answered

### Q: Is SMemAlloc the same as Ordinal_401?
**A:** Yes! ✓ CONFIRMED
- Same algorithm (256-pool heap allocation)
- Same purpose (thread-safe memory allocation)
- Different hashes (recompiled in 1.08)
- See: HYPOTHESIS_CONFIRMATION_...md

### Q: Why different hashes if they're the same?
**A:** Recompilation with different compiler settings
- 1.07: 137 bytes, 45 instructions
- 1.08: 336 bytes, 106 instructions (2.45× larger)
- Different register allocation and optimization strategy
- See: HYPOTHESIS_CONFIRMATION_...md (Why Different Hashes section)

### Q: What's the solution?
**A:** Three-tier approach:
1. Tier 1: Hash-based identification (auto)
2. Tier 2: Functional analysis (semi-auto)
3. Tier 3: Manual registry (user-maintained)
- See: Hash_Based_Function_Renaming_Strategy.md

### Q: How do I implement this?
**A:** 4-phase workflow:
1. Verify functions exist
2. Verify hashes match expected value
3. Apply renames (SMemAlloc ← Ordinal_401)
4. Verify renames worked
- See: IMPLEMENTATION_GUIDE_SMemAllocEx_Rename.md

### Q: What functions need renaming?
**A:** Immediate:
- Ordinal_401 (1.08+) → SMemAllocEx

High Priority:
- Ordinal_502 (hash computation function)
- Other frequently-called Ordinals

- See: Hash_Based_Function_Renaming_Strategy.md

### Q: Can this be automated?
**A:** Yes!
- Ghidra script: IdentifyAndRenameHashMatches.java
- Python utility: hash_based_function_renaming.py
- MCP tools: rename_function_by_address()

- See: Hash_Based_Function_Renaming_Strategy.md (Tools and Scripts)

### Q: What's the impact?
**A:** 
- ✓ Consistent naming across versions
- ✓ Better documentation tracking
- ✓ Easier cross-version analysis
- ✓ Foundation for automated propagation

- See: COMPLETE_SOLUTION_PACKAGE.md (Expected Outcomes)

---

## Files by Purpose

### Understanding the Problem
- SOLUTION_SUMMARY.md
- VISUAL_COMPARISON_SMemAlloc_Ordinal401.md

### Technical Analysis
- HYPOTHESIS_CONFIRMATION_SMemAlloc_Ordinal401.md

### Strategic Planning
- Hash_Based_Function_Renaming_Strategy.md
- COMPLETE_SOLUTION_PACKAGE.md

### Implementation
- IMPLEMENTATION_GUIDE_SMemAllocEx_Rename.md
- ghidra_scripts/IdentifyAndRenameHashMatches.java
- hash_based_function_renaming.py

### Reference
- This file (INDEX_AND_GUIDE.md)

---

## Quick Commands Reference

### Verify Functions Exist
```python
switch_program("1.08")
search_functions_by_name("Ordinal_401")  # Should find @ 0x6ffcbd60
```

### Get Function Hash
```python
switch_program("1.08")
get_function_hash("0x6ffcbd60")  # Should be 6a811228...
```

### Apply Rename
```python
switch_program("1.08")
rename_function_by_address("0x6ffcbd60", "SMemAllocEx")
```

### Verify Rename
```python
switch_program("1.08")
search_functions_by_name("SMemAllocEx")  # Should find @ 0x6ffcbd60
```

---

## Status Summary

### Completed ✓
- Hypothesis confirmation (SMemAlloc = Ordinal_401)
- Root cause analysis (why different hashes)
- Strategic framework development
- Implementation guide creation
- Code tools provided
- Comprehensive documentation

### Ready to Execute
- Rename Ordinal_401 → SMemAllocEx (1.08+)
- Apply to other versions
- Build hash registry

### Next Steps
- Analyze other Ordinal functions (502, 400-410, etc.)
- Build complete hash registry
- Automate cross-version matching
- Propagate documentation

---

## Contact/Support

### For Questions About
| Topic | Document |
|-------|----------|
| **What is SMemAllocEx?** | HYPOTHESIS_CONFIRMATION_... |
| **How does hash matching work?** | Hash_Based_Function_Renaming_Strategy.md |
| **How do I rename functions?** | IMPLEMENTATION_GUIDE_... |
| **What's the big picture?** | COMPLETE_SOLUTION_PACKAGE.md |
| **I prefer visuals** | VISUAL_COMPARISON_... |

---

## Version Information

- **Created**: 2025-12-08
- **Scope**: Storm.dll 1.07, 1.08, 1.09 (extensible to 11+ versions)
- **MCP Tools Used**: get_function_hash, rename_function_by_address, search_functions_by_name, decompile_function, etc.
- **Tested**: Against actual binaries with hash verification

---

## Next Action Items

| Priority | Item | Effort | Document |
|----------|------|--------|----------|
| **HIGH** | Rename Ordinal_401 → SMemAllocEx (1.08+) | 30 min | IMPLEMENTATION_GUIDE_... |
| **HIGH** | Verify renames successful | 10 min | IMPLEMENTATION_GUIDE_... Phase 4 |
| **MEDIUM** | Analyze other high-priority Ordinals | 2-3 hours | Hash_Based_Function_Renaming_Strategy.md |
| **MEDIUM** | Build hash registry file | 1-2 hours | COMPLETE_SOLUTION_PACKAGE.md |
| **LOW** | Automate propagation system | 1-2 days | Future planning |

---

## Document Statistics

```
Total Documents: 8
├── Analysis Documents: 5
│   ├── SOLUTION_SUMMARY.md (2 pages)
│   ├── HYPOTHESIS_CONFIRMATION_... (15 pages)
│   ├── Hash_Based_Function_Renaming_Strategy.md (12 pages)
│   ├── VISUAL_COMPARISON_... (8 pages)
│   └── COMPLETE_SOLUTION_PACKAGE.md (6 pages)
│
├── Code Tools: 2
│   ├── IdentifyAndRenameHashMatches.java (85 lines)
│   └── hash_based_function_renaming.py (280 lines)
│
└── Meta-documents: 1
    └── INDEX_AND_GUIDE.md (this file)

Total Pages: ~45
Total Code Lines: ~365
Estimated Reading Time: 90-120 minutes
Estimated Implementation Time: 45 minutes
```

---

## Success Criteria

After implementation, confirm:

- [ ] Ordinal_401 renamed to SMemAllocEx in 1.08+
- [ ] Hash verification confirms same function (6a811228...)
- [ ] Search for SMemAllocEx returns correct addresses
- [ ] Cross-references updated correctly
- [ ] Documentation can be applied across versions
- [ ] Process documented for future functions

---

**Ready to start?** Open `SOLUTION_SUMMARY.md` first.
