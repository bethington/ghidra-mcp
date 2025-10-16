param(
    [switch]$Reverse,
    [switch]$Help
)

# Simple script to process functions one by one using Claude CLI
$todoFile = "C:\Users\benam\source\cpp\Fortification\D2CommonPtrsTodo.txt"

function Show-Help {
    Write-Host @"
Simple-Process.ps1 - Function Processing Script

USAGE:
    .\simple-process.ps1 [OPTIONS]

OPTIONS:
    -Reverse    Process functions from bottom of list in reverse order
    -Help       Show this help message

EXAMPLES:
    .\simple-process.ps1          # Process from top to bottom (default)
    .\simple-process.ps1 -Reverse # Process from bottom to top
    .\simple-process.ps1 -Help    # Show this help

DESCRIPTION:
    Processes FUN_ functions from D2GamePtrsTodo.txt one by one using Claude CLI.
    Default behavior processes from first [ ] function to last.
    With -Reverse flag, processes from last [ ] function to first.
"@
    exit 0
}

if ($Help) {
    Show-Help
}

while ($true) {
    # Get next pending function
    $content = Get-Content $todoFile
    $pendingFunctions = $content | Where-Object { $_ -match '^\[ \] (FUN_[0-9a-fA-F]+)' }
    
    if ($pendingFunctions.Count -eq 0) {
        Write-Host "All functions completed!"
        break
    }
    
    # Select function based on direction
    if ($Reverse) {
        $pendingLine = $pendingFunctions | Select-Object -Last 1
        Write-Host "Processing from bottom (reverse order): $($pendingFunctions.Count) remaining"
    } else {
        $pendingLine = $pendingFunctions | Select-Object -First 1
        Write-Host "Processing from top (normal order): $($pendingFunctions.Count) remaining"
    }
    
    # Extract function name
    $matches = [regex]::Match($pendingLine, '^\[ \] (FUN_[0-9a-fA-F]+)')
    $funcName = $matches.Groups[1].Value
    
    Write-Host "Processing: $funcName"
    
    # Build prompt with proper escaping
    $prompt = @"
You are assisting with reverse engineering binary code in Ghidra. Your task is to systematically document function $funcName by analyzing its behavior, renaming symbols to be descriptive, adding comprehensive comments, and applying proper data types. Follow this workflow carefully to ensure complete and accurate documentation.

Start by locating function $funcName in the Ghidra project. Before beginning any analysis, verify that function boundaries are correct by examining the disassembly. Check that the function starts at the expected address, confirm all code blocks belong to this function, and ensure return instructions are properly included at function exits. If you discover the boundaries are incorrect, you will need to delete the function and recreate it with the correct address range.

Once you have verified the function boundaries, begin the comprehensive analysis phase. Use analyze_function_complete to gather all necessary information about function $funcName in a single efficient call. This tool retrieves the decompiled code, cross-references, callees, callers, disassembly, and variable information simultaneously. Carefully study the decompiled code to understand what the function does, examine how it is called by other functions to understand its context and purpose, review the functions it calls to understand its dependencies, and analyze the disassembly to see actual memory access patterns and offsets.

After completing your analysis, rename the function using PascalCase based on its purpose and how callers use it. Choose descriptive names that reflect the function's action and target, such as ProcessPlayerSlots for a function that iterates over player data, ValidateEntityState for a function checking entity validity, or InitializeGameResources for a function setting up game structures. Next, set an accurate return data type by examining what value the function returns in EAX or RAX. Use void if there is no return value, int or DWORD for status codes or count values, BOOL for true/false return values, or pointer types for functions returning object references.

Define the complete function prototype with all parameters properly typed and named. Examine how parameters are used in the decompiled code and give them descriptive camelCase names like playerNode, itemPointer, or resourceCount. Specify the correct calling convention based on the architecture and observed behavior: use __cdecl for standard C functions where caller cleans stack, __stdcall for Windows API functions where callee cleans stack, __fastcall for functions passing first arguments in registers, or __thiscall for C++ member functions with implicit this pointer.

Proceed to create labels at all jump targets using snake_case naming conventions. For control flow structures, use descriptive labels like loop_start for the beginning of a loop, loop_continue for continue targets, loop_end for loop exits, or loop_check for condition checks. For validation logic, use labels like validation_failed, check_bounds, or bounds_ok. For error handling, use error_handler, cleanup_and_exit, or handle_failure. For state machines, use sequential labels like state_0_init, state_1_processing, or state_2_complete. Always use batch_create_labels to create multiple labels in a single atomic operation.

Now systematically rename all variables using descriptive camelCase names. Replace generic names like local_8, param_1, or iVar1 with meaningful names that describe what the variable represents. Use names like playerIndex for array indices, bufferSize for size values, entityPointer for object pointers, or isValid for boolean flags. When meaningful, include register artifacts in your naming such as eax_returnValue or ecx_objectPointer to show data flow. Use batch_rename_variables to rename multiple variables atomically. Pay special attention to common patterns: iVar1, iVar2, etc. should become descriptive names based on their purpose, extraout_EDX or similar should become register artifacts, and uVar1, lVar1, etc. should be renamed based on their semantic meaning.

When working with Diablo II game structures, apply the appropriate data types. For UnitAny structures, use fields like dwType for unit type, dwUnitId for unique identifier, dwMode for current mode, pInventory for inventory pointer, pStats for stats pointer, and wX/wY for coordinates. For Room1 and Room2 structures, use pRoom2 for Room2 pointer, dwPosX/dwPosY for position, dwSizeX/dwSizeY for dimensions, and pLevel for level pointer. For PlayerData, use szName for player name, pNormalQuest/pNightmareQuest/pHellQuest for quest pointers. For ItemData, use dwQuality, dwItemFlags, wPrefix, wSuffix, and BodyLocation. For MonsterData, use anEnchants, wUniqueNo, and wName. For Inventory, use pOwner, pFirstItem, pCursorItem, and dwItemCount. Use proper pointer types like LPUNITANY, LPROOM1, LPROOM2, and LPLEVEL. Follow Hungarian notation consistently: use dw prefix for DWORD fields like dwFlags or dwUnitId, p or lp prefix for pointers like pNext or lpPlayerUnit, w prefix for WORD fields like wLevel or wStatIndex, n prefix for counts like nCount or nMaxXCells, sz prefix for strings like szName or szGameName, and f or b prefix for booleans like fSaved or bActive.

Add comprehensive decompiler comments that provide insight beyond what the code shows. Explain the algorithm's context and purpose, describe how structures are accessed and what fields mean, document magic numbers and sentinel values, explain validation logic and boundary checks, and note edge cases and error handling. Critically, you must verify offset values against the actual assembly before adding comments. The assembly shows true memory offsets where an instruction like [EBX + 0x4] means offset +4 from the base, not offset +2. Always match your comment offsets to what appears in the disassembly rather than relying on the decompiler's line order, and document memory access patterns rather than just stating what variable is being loaded. Use concise disassembly comments with a maximum of 32 characters that describe the instruction's purpose, such as "Load player slot index", "Check if slot active", or "Jump to error handler".

Create a comprehensive function header comment using set_plate_comment following the exact format template from PLATE_COMMENT_FORMAT_GUIDE.md. The plate comment must use plain text format WITHOUT any decorative borders - Ghidra adds all formatting automatically. The format includes: a one-line function summary, an Algorithm section with numbered steps describing each major operation in the function, a Parameters section listing each parameter with its type and purpose, a Returns section documenting return values and conditions, a Special Cases section for edge cases and magic numbers, and optionally a Structure Layout section with an ASCII table showing field offsets sizes and descriptions when the function accesses structured data. Number algorithm steps starting from 1 and include all validation checks, function calls, and error handling. Reference specific ordinals, addresses, and magic numbers by their values. For structure layouts, use the table format with columns for Offset, Size, Field Name, Type, and Description, and calculate the total structure size from stride patterns or highest offset. Create struct definitions for repeated access patterns using create_struct, and use analyze_data_region to analyze pointer targets and understand data layouts. Replace all undefined types with proper types: undefined1 becomes BYTE, undefined2 becomes WORD, undefined4 becomes DWORD or pointer, and undefined8 becomes QWORD.

After completing major operations like function renaming, prototype setting, or adding comments, always verify that changes applied correctly. Decompile the function again and check that the plate comment appears correctly, confirm that all variable renames succeeded and no default names remain, and validate that comment placement matches the intended addresses.

For batch operations, prefer document_function_complete whenever possible as this performs all documentation updates in a single atomic transaction. However, if document_function_complete fails due to connection errors or timeouts, fall back to individual operations in this specific order: first use rename_function_by_address to rename the function, then set_function_prototype to set the return type and parameters, next use batch_create_labels to create all labels at once, then use batch_rename_variables to rename variables in batches iterating as needed, then set_plate_comment to add the function header, and finally use batch_set_comments to add all decompiler and disassembly comments. Verify after each major step that changes were applied successfully.

Handle errors appropriately based on their type. For connection timeouts, retry the operation once and then switch to smaller batches if it fails again. For "Variable not found" errors, verify that the variable name is correct and exists in the function. For offset mismatches between your comments and the actual code, cross-reference the disassembly before adding comments to ensure accuracy. During execution, work efficiently and silently without generating excessive status output or progress updates. Do not create or edit any files on the filesystem. Apply all changes directly in Ghidra using the available MCP tools. Use batch operations whenever possible to minimize network round-trips. If batch operations fail with connection errors, retry with individual operations. Allow up to 3 retry attempts for network timeouts before reporting failure.

A function is considered fully documented when all of the following criteria are met: it has a descriptive PascalCase name that clearly indicates its purpose, the function prototype includes an accurate return type, all parameters are properly typed and named, all variables use descriptive camelCase names with no remaining undefined2, undefined4, iVar, param_, or local_ default names, the plate comment appears in the decompiler showing the function's purpose and structure documentation with algorithm overview, all jump targets have descriptive snake_case labels, the decompiler shows inline comments at key operations explaining what is happening, the disassembly has concise comments with a maximum of 32 characters at important instructions, and verification shows that all changes were applied successfully with no errors. Only after verifying all these criteria are met for function $funcName should you consider the function documentation complete.
"@

    try {
        # Set NODE_OPTIONS to increase heap size to 8GB
        $env:NODE_OPTIONS = "--max-old-space-size=8192"
        
        # Execute Claude with error handling
        Write-Host "Calling Claude CLI..." -ForegroundColor Cyan
        $output = claude -c --dangerously-skip-permissions $prompt 2>&1
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -ne 0) {
            Write-Host "ERROR: Claude CLI failed with exit code $exitCode" -ForegroundColor Red
            Write-Host "Output: $output" -ForegroundColor Yellow
            
            $response = Read-Host "Continue to next function? (Y/N)"
            if ($response -notmatch '^[Yy]') {
                Write-Host "Aborted by user" -ForegroundColor Red
                exit 1
            }
        }
        else {
            Write-Host "Successfully processed $funcName" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
        $response = Read-Host "Continue to next function? (Y/N)"
        if ($response -notmatch '^[Yy]') {
            Write-Host "Aborted by user" -ForegroundColor Red
            exit 1
        }
    }
    finally {
        # Always clear environment variable
        $env:NODE_OPTIONS = $null
    }
    
    # Mark as done
    $content = Get-Content $todoFile -Raw
    $updated = $content -replace "\[ \] ($([regex]::Escape($funcName))[^\r\n]*)", "[X] `$1"
    Set-Content $todoFile $updated -NoNewline
    
    Write-Host "Completed: $funcName" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor DarkGray
    Start-Sleep -Seconds 2
}

Write-Host "`n*** All functions processed! ***" -ForegroundColor Green