<#
.SYNOPSIS
    Validates function names against naming standards and identifies violations.
    
.DESCRIPTION
    This script retrieves all functions from Ghidra via the MCP server and filters
    out valid patterns, leaving only functions that may need review or renaming.
    
    Valid patterns (auto-filtered):
    - FUN_* (unprocessed Ghidra default names)
    - Ordinal_* (DLL ordinal exports)
    - thunk_* (thunk/trampoline functions)
    - switch_* (switch table handlers)
    - entry (program entry point)
    - _* __* ___* (library/CRT functions)
    - PascalCase with valid verb prefixes
    
.PARAMETER GhidraServer
    URL of the Ghidra MCP server (default: http://127.0.0.1:8089)
    
.PARAMETER OutputFile
    Optional file to write results to
    
.PARAMETER ShowValid
    Also show valid functions (for debugging)
    
.PARAMETER FixAutomatically
    Attempt to rename obvious violations automatically

.EXAMPLE
    .\validate-function-names.ps1
    .\validate-function-names.ps1 -OutputFile "naming-violations.txt"
    .\validate-function-names.ps1 -ShowValid
#>

param(
    [string]$GhidraServer = "http://127.0.0.1:8089",
    [string]$OutputFile = "",
    [switch]$ShowValid,
    [switch]$FixAutomatically
)

# Valid patterns that should be skipped (regex patterns)
$ValidPatterns = @(
    # Unprocessed/default names - skip entirely
    '^FUN_[0-9a-fA-F]+$',           # Ghidra default: FUN_6fc80a40
    '^Ordinal_\d+$',                 # DLL ordinals: Ordinal_10025
    '^thunk_',                       # Thunk functions
    '^switch_',                      # Switch handlers
    '^entry$',                       # Entry point
    '^_entry$',                      # Alt entry point
    
    # Library/runtime functions - valid as-is
    '^_{1,3}[a-z]',                  # _malloc, __aullrem, ___add_12
    '^_[A-Z][a-z]',                  # _CxxThrowException, _Alloca
    
    # Compiler-generated
    '^\?\?',                         # C++ mangled names ??0ClassName@@
    '^@',                            # Fastcall decorated @funcname@8
    
    # Valid PascalCase with action verbs
    '^(Get|Set|Init|Initialize|Process|Update|Validate|Create|Alloc|Free|Destroy|Handle|Is|Has|Can|Find|Search|Load|Save|Draw|Render|Parse|Build|Calculate|Compute|Check|Execute|Run|Start|Stop|Enable|Disable|Add|Remove|Insert|Delete|Clear|Reset|Open|Close|Read|Write|Send|Receive|Connect|Disconnect|Register|Unregister|Lock|Unlock|Acquire|Release|Push|Pop|Enqueue|Dequeue|Allocate|Deallocate|Attach|Detach|Bind|Unbind|Show|Hide|Activate|Deactivate|Begin|End|Enter|Exit|Format|Convert|Transform|Apply|Revoke|Grant|Deny|Accept|Reject|Dispatch|Notify|Signal|Wait|Sleep|Wake|Resume|Suspend|Cancel|Abort|Retry|Skip|Ignore|Verify|Confirm|Authenticate|Authorize|Encrypt|Decrypt|Compress|Decompress|Encode|Decode|Serialize|Deserialize|Marshal|Unmarshal|Pack|Unpack|Wrap|Unwrap|Map|Unmap|Mount|Unmount|Install|Uninstall|Configure|Reconfigure|Prepare|Cleanup|Finalize|Terminate|Kill|Spawn|Fork|Join|Merge|Split|Copy|Move|Swap|Sort|Filter|Reduce|Aggregate|Collect|Gather|Scatter|Broadcast|Multicast|Publish|Subscribe|Emit|Consume|Produce|Generate|Fabricate|Synthesize|Analyze|Evaluate|Measure|Sample|Poll|Query|Fetch|Retrieve|Lookup|Resolve|Translate|Interpolate|Extrapolate|Approximate|Estimate|Predict|Infer|Deduce|Derive|Extract|Inject|Embed|Embed)[A-Z][a-zA-Z0-9]*$'
)

# Known invalid patterns that definitely need fixing
$InvalidPatterns = @(
    @{ Pattern = '^[A-Z]+_[A-Z]'; Issue = 'Snake_case prefix (MODULE_Function)' },
    @{ Pattern = '^[a-z][a-zA-Z]+$'; Issue = 'camelCase (should be PascalCase)' },
    @{ Pattern = '^[A-Z]+$'; Issue = 'ALL_CAPS (should be PascalCase)' },
    @{ Pattern = '^[A-Z][a-z]+\d+$'; Issue = 'Generic numbered name (Handler1, Process2)' },
    @{ Pattern = '^(Handler|Process|Function|Method|Routine|Procedure|Sub|Func)$'; Issue = 'Generic single-word name' }
)

function Test-ValidFunctionName {
    param([string]$Name)
    
    foreach ($pattern in $ValidPatterns) {
        if ($Name -match $pattern) {
            return $true
        }
    }
    return $false
}

function Get-InvalidReason {
    param([string]$Name)
    
    foreach ($invalid in $InvalidPatterns) {
        if ($Name -match $invalid.Pattern) {
            return $invalid.Issue
        }
    }
    
    # Additional checks
    if ($Name -match '^[a-z]') {
        return 'Starts with lowercase'
    }
    if ($Name -match '_' -and $Name -notmatch '^_') {
        return 'Contains underscore (not library function)'
    }
    if ($Name.Length -lt 4) {
        return 'Name too short'
    }
    
    return 'Does not match PascalCase verb-first pattern'
}

# Main execution
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Function Name Validation Tool" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get all functions from Ghidra
Write-Host "Fetching functions from $GhidraServer..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$GhidraServer/list_functions?offset=0&limit=10000" -Method GET -TimeoutSec 30
    $functions = $response.functions
    Write-Host "Retrieved $($functions.Count) functions" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Could not connect to Ghidra server at $GhidraServer" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Categorize functions
$valid = @()
$invalid = @()
$unprocessed = @()

foreach ($func in $functions) {
    $name = $func.name
    $address = $func.address
    
    # Check if it's an unprocessed name (FUN_, Ordinal_)
    if ($name -match '^FUN_[0-9a-fA-F]+$' -or $name -match '^Ordinal_\d+$') {
        $unprocessed += @{ Name = $name; Address = $address }
        continue
    }
    
    # Check if it's a valid name pattern
    if (Test-ValidFunctionName $name) {
        $valid += @{ Name = $name; Address = $address }
    } else {
        $reason = Get-InvalidReason $name
        $invalid += @{ Name = $name; Address = $address; Reason = $reason }
    }
}

# Output results
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total functions:     $($functions.Count)" -ForegroundColor White
Write-Host "Unprocessed (FUN_):  $($unprocessed.Count)" -ForegroundColor Gray
Write-Host "Valid names:         $($valid.Count)" -ForegroundColor Green
Write-Host "Need review:         $($invalid.Count)" -ForegroundColor $(if ($invalid.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host ""

if ($ShowValid -and $valid.Count -gt 0) {
    Write-Host "VALID FUNCTIONS:" -ForegroundColor Green
    Write-Host "----------------" -ForegroundColor Green
    foreach ($v in $valid | Sort-Object { $_.Name }) {
        Write-Host "  $($v.Name)" -ForegroundColor Gray
    }
    Write-Host ""
}

if ($invalid.Count -gt 0) {
    Write-Host "FUNCTIONS NEEDING REVIEW:" -ForegroundColor Yellow
    Write-Host "-------------------------" -ForegroundColor Yellow
    
    # Group by reason
    $grouped = $invalid | Group-Object { $_.Reason }
    
    foreach ($group in $grouped | Sort-Object Count -Descending) {
        Write-Host ""
        Write-Host "[$($group.Count)] $($group.Name):" -ForegroundColor Yellow
        foreach ($item in $group.Group | Sort-Object { $_.Name }) {
            Write-Host "  0x$($item.Address): $($item.Name)" -ForegroundColor White
        }
    }
}

# Write to file if requested
if ($OutputFile) {
    $output = @()
    $output += "Function Name Validation Report"
    $output += "Generated: $(Get-Date)"
    $output += "Server: $GhidraServer"
    $output += ""
    $output += "Summary:"
    $output += "  Total: $($functions.Count)"
    $output += "  Unprocessed: $($unprocessed.Count)"
    $output += "  Valid: $($valid.Count)"
    $output += "  Need Review: $($invalid.Count)"
    $output += ""
    
    if ($invalid.Count -gt 0) {
        $output += "Functions Needing Review:"
        $output += "-------------------------"
        foreach ($item in $invalid | Sort-Object { $_.Reason }, { $_.Name }) {
            $output += "0x$($item.Address)`t$($item.Name)`t$($item.Reason)"
        }
    }
    
    $output | Out-File $OutputFile -Encoding UTF8
    Write-Host ""
    Write-Host "Results written to: $OutputFile" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan

# Return count of invalid for scripting
exit $invalid.Count
