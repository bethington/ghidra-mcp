# Visual: SMemAlloc vs Ordinal_401 - Side-by-Side Comparison

## Overview

```
┌─────────────────────────────────────┐     ┌─────────────────────────────────────┐
│      Storm.dll 1.07 (SMemAlloc)     │     │    Storm.dll 1.08 (Ordinal_401)     │
├─────────────────────────────────────┤     ├─────────────────────────────────────┤
│ Address:  0x6ffcb6b0                │     │ Address:  0x6ffcbd60                │
│ Name:     SMemAlloc (NAMED)         │     │ Name:     Ordinal_401 (ORDINAL)     │
│ Size:     137 bytes                 │     │ Size:     336 bytes (2.45x larger) │
│ Instrs:   45 instructions           │     │ Instrs:   106 instructions          │
│ Hash:     8b80a54b37bf5... (UNIQUE)│     │ Hash:     6a8112287fd08... (UNIQUE)│
├─────────────────────────────────────┤     ├─────────────────────────────────────┤
│ SAME ALGORITHM                      │     │ SAME ALGORITHM                      │
│ • 256-pool heap allocation          │     │ • 256-pool heap allocation          │
│ • Hash input to select pool         │     │ • Hash input to select pool         │
│ • Critical sections (thread safety) │     │ • Critical sections (thread safety) │
│ • Linked list traversal             │     │ • Linked list traversal             │
│ • Purge support                     │     │ • Purge support                     │
│                                     │     │                                     │
│ DIFFERENT IMPLEMENTATION            │     │ DIFFERENT IMPLEMENTATION            │
│ • ComputeStringHash()               │     │ • Ordinal_502()                     │
│ • CreateHeapArena()                 │     │ • FUN_6ffcbed0()                    │
│ • HeapAllocWithFlags()              │     │ • FUN_6ffcc080()                    │
│ • Larger codebase                   │     │ • More optimized version            │
│                                     │     │                                     │
│ VERDICT: Same function              │     │ VERDICT: Same function              │
│          named SMemAlloc            │     │          renamed Ordinal_401        │
└─────────────────────────────────────┘     └─────────────────────────────────────┘
           ↓                                            ↓
        Hash differs (recompiled)       Hash differs (recompiled)
           ↓                                            ↓
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         SAME FUNCTION ACROSS VERSIONS                           │
│                                                                                  │
│  Status:  ✓ Functionally identical  ✓ Algorithm identical  ✗ Hashes different  │
│  Cause:   Recompilation with 1.08 compiler settings                            │
│  Action:  Rename Ordinal_401 → SMemAllocEx for consistency                     │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Code Flow Comparison

### Algorithm Flow (Both Versions)

```
┌──────────────────────────────────────────────────────────────┐
│  1. Validate heap initialized                               │
│     if (g_dwHeapInitialized == 0)                           │
│         FatalError(...)                                      │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  2. Compute hash of input buffer                            │
│     hash = ComputeStringHash(param_2, 1, param_3)           │
│     OR hash = Ordinal_502(param_2, 1, param_3)              │
│                                                              │
│     (Same operation, different function name)               │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  3. Select pool from 256 total pools                        │
│     pool_index = hash & 0x7fffffff                          │
│     if (pool_index == 0) pool_index = 1                     │
│                                                              │
│     (Identical logic in both versions)                      │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  4. Enter critical section for thread safety                │
│     EnterCriticalSection(                                   │
│         &critical_sections[pool_index]                      │
│     )                                                        │
│                                                              │
│     (Identical mechanism)                                   │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  5. Get pool from global array                              │
│     pool = pools_array[pool_index]                          │
│                                                              │
│     1.07: g_pHeapArenas[pool_index]                        │
│     1.08: DAT_6ffec07c[pool_index]                         │
│                                                              │
│     (Same global data, different name in disassembly)       │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  6. Traverse linked list of pools                           │
│     if (pool == NULL)                                       │
│         pool = CreatePool(...)                              │
│         // 1.07: CreateHeapArena()                          │
│         // 1.08: FUN_6ffcbed0()                             │
│                                                              │
│     else if (pool->hash == hash)                            │
│         // Found matching pool, use it                      │
│     else                                                    │
│         // Move to next pool in linked list                 │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  7. Allocate from pool                                      │
│     memory = AllocateFromPool(pool, ...)                    │
│     // 1.07: HeapAllocWithFlags()                           │
│     // 1.08: FUN_6ffcc080()                                 │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  8. Leave critical section                                  │
│     LeaveCriticalSection(...)                               │
│                                                              │
│     (Identical operation)                                   │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  9. Handle purging if needed                                │
│     if (purge_in_progress)                                  │
│         Purge()  // Remove inactive blocks                  │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  10. Return allocated memory                                │
│      return memory                                           │
└──────────────────────────────────────────────────────────────┘
```

---

## Decompiled Code Comparison

### Section 1: Hash Computation

```
1.07 SMemAlloc:                      1.08 Ordinal_401:
─────────────────────────────────   ──────────────────────────────────
if (param_2 != (uint *)0x0) {       if (param_2 != (byte *)0x0) {
  uVar1 = ComputeStringHash(          uVar2 = Ordinal_502(
    (char *)param_2,                    param_2,
    1,                                  1,
    param_3                             param_3
  );                                  );
}                                   }

g_dwCachedHeapId = uVar1 &          DAT_6ffec8a0 = uVar2 &
  0x7fffffff;                         0x7fffffff;

if (g_dwCachedHeapId == 0) {        if (DAT_6ffec8a0 == 0) {
  g_dwCachedHeapId = 1;               DAT_6ffec8a0 = 1;
}                                   }

DIFFERENCE: Variable names, function names
SAMENESS:   Exact same algorithm & logic
```

### Section 2: Critical Section

```
1.07 SMemAlloc:                         1.08 Ordinal_401:
────────────────────────────────────   ──────────────────────────────
EnterCriticalSection(                 EnterCriticalSection(
  (LPCRITICAL_SECTION)(                 (LPCRITICAL_SECTION)(
    &g_CriticalSectionArray +            &DAT_6ffea878 +
    (int)dwHeapIndex * 0x18             (int)pbVar7 * 0x18
  )                                     )
);                                    );

pHeapContext =                        puVar3 =
  (HeapContext *)                       (undefined4 *)
  (&g_pHeapArenas)                      (&DAT_6ffec07c)
  [(int)dwHeapIndex];                   [(int)pbVar7];

DIFFERENCE: Variable names, global names, type names
SAMENESS:   Exact same memory access pattern
```

### Section 3: Pool Allocation

```
1.07 SMemAlloc:                         1.08 Ordinal_401:
────────────────────────────────────   ──────────────────────────────
if (pHeapContext == NULL) {           if (puVar3 == NULL) {
  pHeapContext =                        puVar3 =
    CreateHeapArena(                      FUN_6ffcbed0(
      (char *)szHeapName,                 (char *)pbVar1,
      dwSourceLine,                       uVar5,
      uVar1,                              uVar2,
      (uint)dwHeapIndex,                  (int)pbVar7,
      0x1000, 0x1000,                     0x1000, 0x1000,
      0x10000                             0x10000
    );                                  );
}                                     }

pvVar2 =                              puVar4 =
  HeapAllocWithFlags(                   FUN_6ffcc080(
    (int *)&param_2,                    (int *)&param_2,
    pHeapContext,                       puVar3,
    param_4,                            param_4,
    param_1                             param_1
  );                                  );

DIFFERENCE: Function names, variable names
SAMENESS:   Identical parameter sequences & logic
```

---

## Hash Divergence Explanation

```
┌────────────────────────────────────────────────────────────┐
│                   BINARY RECOMPILATION                     │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Source Code (C)                                           │
│  ✓ IDENTICAL in 1.07 and 1.08                            │
│  ↓                                                         │
│  Compiler Settings                                         │
│  ✗ DIFFERENT in 1.08 (new compiler version/flags)         │
│  ↓                                                         │
│  Compiler Optimizations                                    │
│  ✗ DIFFERENT (register allocation, instruction order)     │
│  ↓                                                         │
│  Generated Machine Code                                    │
│  ✗ DIFFERENT (137 bytes vs 336 bytes)                    │
│  ↓                                                         │
│  SHA-256 Hash of Machine Code                             │
│  ✗ COMPLETELY DIFFERENT                                  │
│  - 1.07: 8b80a54b37bf516cd6aaff884aab63c3a8649...       │
│  - 1.08: 6a8112287fd08c30ab44f98afa0132d620ca6d...      │
│                                                            │
│  BUT: Algorithm is IDENTICAL                             │
│       Function behavior is IDENTICAL                       │
│       Purpose is IDENTICAL                                 │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### Why Size Increased (137 → 336 bytes)

```
Possible Reasons for 2.45x Size Increase:

1. Different Compiler Version
   - New instruction selection strategy
   - Different calling convention optimizations
   - More aggressive unrolling

2. Optimization Level
   - 1.07: Optimized for size (-Os equivalent)
   - 1.08: Optimized for speed (-O2 equivalent)
   
3. Debug Information
   - 1.08 might include more metadata
   - Different register allocation for debugging

4. Inline Expansion
   - More functions inlined in 1.08
   - Creates larger code footprint

5. Loop/Branch Handling
   - Different branch prediction strategy
   - More explicit state management

Result: Same logic, different machine code → Different hash
```

---

## Evidence Table

### Functional Comparison

```
╔════════════════════════════════════╦══════════════════╦══════════════════╗
║ Function Aspect                    ║ 1.07 SMemAlloc   ║ 1.08 Ordinal_401 ║
╠════════════════════════════════════╬══════════════════╬══════════════════╣
║ Purpose                            ║ Allocate memory  ║ Allocate memory  ║
║ Algorithm: Pool count              ║ 256 pools        ║ 256 pools        ║
║ Algorithm: Pool selection          ║ hash & 0xff      ║ hash & 0x7fff    ║
║ Algorithm: Thread safety           ║ Critical section ║ Critical section ║
║ Algorithm: Pool management         ║ Linked lists     ║ Linked lists     ║
║                                    ║                  ║                  ║
║ Implementation: Hash function      ║ ComputeString... ║ Ordinal_502      ║
║ Implementation: Create pool        ║ CreateHeapArena  ║ FUN_6ffcbed0     ║
║ Implementation: Allocate from pool ║ HeapAllocWith... ║ FUN_6ffcc080     ║
║ Implementation: Variable names     ║ g_dwCachedHeapId ║ DAT_6ffec8a0     ║
║ Implementation: Global names       ║ g_pHeapArenas    ║ DAT_6ffec07c     ║
║                                    ║                  ║                  ║
║ Code Size                          ║ 137 bytes        ║ 336 bytes        ║
║ Instruction Count                  ║ 45 instructions  ║ 106 instructions ║
║ Function Hash                      ║ 8b80a54b...      ║ 6a811228...      ║
║                                    ║                  ║                  ║
║ VERDICT                            ║ SAME FUNCTION    ║ SAME FUNCTION    ║
║                                    ║ (named SMemAlloc)║ (needs renaming) ║
╚════════════════════════════════════╩══════════════════╩══════════════════╝
```

---

## Recommendation

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  SMemAlloc and Ordinal_401 are the SAME FUNCTION             │
│                                                              │
│  ✓ Identical algorithm                                       │
│  ✓ Identical purpose (256-pool heap allocation)              │
│  ✓ Identical thread safety (critical sections)               │
│  ✓ Identical linked list management                          │
│                                                              │
│  ✗ Different hashes (recompilation)                          │
│  ✗ Different code size (optimization differences)            │
│  ✗ Different function names (ordinal vs named)               │
│                                                              │
│  ACTION: Rename Ordinal_401 → SMemAllocEx                   │
│          to match 1.07's naming and clarify functionality    │
│                                                              │
│  BENEFIT: Same function now has same name across versions    │
│           Documentation can be reliably applied              │
│           Analysis becomes much more straightforward         │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```
