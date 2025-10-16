param(
    [switch]$Reverse,
    [switch]$OnlyDAT,
    [switch]$Help
)

# Simple script to process data items one by one using Claude CLI
$todoFile = "C:\Users\benam\source\mcp\ghidra-mcp\D2CommonDataTodo.txt"
$ghidraUrl = "http://127.0.0.1:8089"

function Show-Help {
    Write-Host @"
Simple-Data-Process.ps1 - Data Item Processing Script

USAGE:
    .\simple-data-process.ps1 [OPTIONS]

OPTIONS:
    -Reverse    Process data items from bottom of list in reverse order
    -OnlyDAT    Fetch and process only undefined DAT_ items from Ghidra
    -Help       Show this help message

EXAMPLES:
    .\simple-data-process.ps1          # Process from top to bottom (default)
    .\simple-data-process.ps1 -Reverse # Process from bottom to top
    .\simple-data-process.ps1 -OnlyDAT # Fetch and process only DAT_ items
    .\simple-data-process.ps1 -Help    # Show this help

DESCRIPTION:
    Processes data items one by one using Claude CLI.
    Can read from D2CommonDataTodo.txt or fetch directly from Ghidra using list_data_items endpoint.
    Default behavior processes from first [ ] data item to last.
    With -Reverse flag, processes from last [ ] data item to first.
    With -OnlyDAT flag, fetches only undefined DAT_ items from Ghidra (ignores todo file).
"@
    exit 0
}

if ($Help) {
    Show-Help
}

# Function to fetch data items from Ghidra
function Get-DataItemsFromGhidra {
    param([switch]$OnlyDAT)

    Write-Host "Fetching data items from Ghidra..." -ForegroundColor Cyan

    try {
        $url = "$ghidraUrl/list_data_items?offset=0&limit=20000"
        $response = curl.exe -s $url

        if (-not $response) {
            Write-Host "ERROR: Failed to fetch data items from Ghidra" -ForegroundColor Red
            return @()
        }

        # Parse response - each line is a data item
        $items = $response -split "`n" | Where-Object { $_ -match '\S' }

        $dataItems = @()
        foreach ($item in $items) {
            # Parse format: "NAME @ ADDRESS [TYPE] (SIZE)"
            if ($item -match '^(.+?) @ ([0-9a-fA-F]+)') {
                $name = $matches[1]
                $addr = $matches[2]

                # Filter for DAT_ items if requested
                if ($OnlyDAT -and $name -notmatch '^DAT_') {
                    continue
                }

                $dataItems += @{
                    Name = $name
                    Address = $addr
                    Original = $item
                }
            }
        }

        Write-Host "Found $($dataItems.Count) data items" -ForegroundColor Green
        return $dataItems
    }
    catch {
        Write-Host "ERROR: Failed to fetch from Ghidra: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# Get data items (either from Ghidra or todo file)
$dataItems = @()
if ($OnlyDAT) {
    $dataItems = Get-DataItemsFromGhidra -OnlyDAT
    if ($dataItems.Count -eq 0) {
        Write-Host "No data items found!" -ForegroundColor Red
        exit 1
    }
} else {
    # Get from todo file
    if (-not (Test-Path $todoFile)) {
        Write-Host "ERROR: Todo file not found: $todoFile" -ForegroundColor Red
        Write-Host "Use -OnlyDAT flag to fetch directly from Ghidra" -ForegroundColor Yellow
        exit 1
    }

    $content = Get-Content $todoFile
    $pendingLines = $content | Where-Object { $_ -match '^\[ \] (.+?) @ ([0-9a-fA-F]+)' }

    foreach ($line in $pendingLines) {
        if ($line -match '^\[ \] (.+?) @ ([0-9a-fA-F]+)') {
            $dataItems += @{
                Name = $matches[1]
                Address = $matches[2]
                Original = $line
            }
        }
    }
}

if ($dataItems.Count -eq 0) {
    Write-Host "All data items completed!" -ForegroundColor Green
    exit 0
}

# Process data items (reverse order if requested)
if ($Reverse) {
    [array]::Reverse($dataItems)
    Write-Host "Processing in reverse order (bottom to top)" -ForegroundColor Yellow
}

$totalItems = $dataItems.Count
$currentIndex = 0

foreach ($dataItem in $dataItems) {
    $currentIndex++

    $dataName = $dataItem.Name
    $dataAddr = $dataItem.Address

    Write-Host "[$currentIndex/$totalItems] Processing: $dataName @ 0x$dataAddr" -ForegroundColor Cyan

    # Build prompt with proper escaping
    $prompt = @"
You are assisting with reverse engineering binary data in Ghidra. Your task is to analyze and properly classify the data item at address 0x$dataAddr (currently named "$dataName") by determining its true data type, applying appropriate structure definitions, and adding descriptive comments.

Start by analyzing the data region at address 0x$dataAddr using analyze_data_region to understand:
- The boundaries of this data region
- Cross-references (xrefs) showing how this data is accessed
- Assembly patterns indicating the data type (pointer dereference, array indexing, structure field access)
- Stride patterns suggesting array elements or structure size

Use inspect_memory_content to examine the raw bytes at 0x$dataAddr and detect:
- Whether this is likely a string (printable ASCII characters with null terminator)
- Numeric data patterns (DWORDs, WORDs, etc.)
- Pointer values (addresses in valid memory ranges)

Use get_xrefs_to to find all references to this address and understand:
- How many functions reference this data
- Whether it's accessed as a single value, array element, or structure field
- The assembly instructions used to access it (MOV, LEA, CMP, etc.)

Use batch_decompile_xref_sources to see how this data is used in decompiled code:
- Variable names and types assigned by callers
- How the data is indexed or offset
- What operations are performed on it

Based on your analysis, classify the data as one of:
1. **PRIMITIVE** - Single scalar value (DWORD, WORD, BYTE, pointer, etc.)
2. **ARRAY** - Multiple elements of the same type accessed with stride pattern
3. **STRUCTURE** - Complex data with different field types at fixed offsets
4. **STRING** - Null-terminated character data

For PRIMITIVE data:
- Use create_and_apply_data_type with classification="PRIMITIVE" and appropriate type (DWORD, LPVOID, etc.)
- Rename using descriptive name based on usage (e.g., g_MaxPlayerCount, g_GameStateFlags)

For ARRAY data:
- Use detect_array_bounds to determine element count and stride
- Create array type with create_and_apply_data_type using classification="ARRAY"
- Provide element_type and count in type_definition (must be JSON string)
- Rename with descriptive array name (e.g., g_SkillLevelTable, g_ItemQualityColors)

For STRUCTURE data:
- Analyze field access patterns to determine structure layout
- Use create_and_apply_data_type with classification="STRUCTURE"
- Define fields with proper names, types, and offsets based on xref analysis
- Rename structure instance descriptively (e.g., g_GameConfig, g_PlayerManager)

For STRING data:
- Apply char[] or char* type as appropriate
- Rename with descriptive string name (e.g., g_VersionString, g_DefaultPlayerName)

When working with Diablo II data structures, use proper types:
- LPUNITANY, LPROOM1, LPROOM2, LPLEVEL for game object pointers
- DWORD (dw prefix) for flags, IDs, counts
- WORD (w prefix) for smaller integers
- BYTE (b prefix) for single bytes
- Use existing structure definitions when applicable

Add comprehensive comments explaining:
- The purpose and meaning of this data
- How it's used by referencing functions
- Valid value ranges or special sentinel values
- Relationship to other game systems or structures

After applying the data type and renaming, verify the changes by:
- Checking that the data type appears correctly in Ghidra's listing
- Confirming xrefs still resolve to the renamed symbol
- Validating that decompiled code shows improved type information

Work efficiently and silently. Do not create or edit any files. Apply all changes directly in Ghidra using MCP tools. Use batch operations when possible. If operations fail, retry once before reporting failure.

The data item is considered fully documented when:
- It has an accurate data type (not undefined or generic DAT_)
- It has a descriptive name reflecting its purpose
- Cross-references show improved type information
- Comments explain its meaning and usage
- Verification confirms all changes applied successfully

Now analyze and document the data item at address 0x$dataAddr.
"@

    try {
        # Set NODE_OPTIONS to increase heap size to 8GB
        $env:NODE_OPTIONS = "--max-old-space-size=8192"

        # Execute Claude with error handling
        Write-Host "Calling Claude CLI..." -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor DarkGray

        # Call Claude without capturing output so we see real-time progress
        claude -c -p --dangerously-skip-permissions $prompt
        $exitCode = $LASTEXITCODE

        Write-Host "========================================" -ForegroundColor DarkGray
        if ($exitCode -ne 0) {
            Write-Host "ERROR: Claude CLI failed with exit code $exitCode" -ForegroundColor Red

            $response = Read-Host "Continue to next data item? (Y/N)"
            if ($response -notmatch '^[Yy]') {
                Write-Host "Aborted by user" -ForegroundColor Red
                exit 1
            }
        }
        else {
            Write-Host "Successfully processed $dataName @ 0x$dataAddr" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
        $response = Read-Host "Continue to next data item? (Y/N)"
        if ($response -notmatch '^[Yy]') {
            Write-Host "Aborted by user" -ForegroundColor Red
            exit 1
        }
    }
    finally {
        # Always clear environment variable
        $env:NODE_OPTIONS = $null
    }

    # Mark as done (only if using todo file)
    if (-not $OnlyDAT -and (Test-Path $todoFile)) {
        $content = Get-Content $todoFile -Raw
        # Escape the data name and address for regex matching
        $escapedName = [regex]::Escape($dataName)
        $escapedAddr = [regex]::Escape($dataAddr)
        # Use multiline mode (?m) to match line starts with ^
        $updated = $content -replace "(?m)^\[ \] ($escapedName @ $escapedAddr)", "[X] `$1"
        Set-Content $todoFile $updated -NoNewline
    }

    Write-Host "Completed: $dataName @ 0x$dataAddr" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor DarkGray
    Start-Sleep -Seconds 2
}

Write-Host "`n*** All data items processed! ***" -ForegroundColor Green