# PowerShell script to extract Ghidra functions via REST API and format for todo list
param(
    [string]$DllName = "D2Common.dll",
    [string]$OutputFile = "",
    [string]$GhidraUrl = "http://127.0.0.1:8089/list_functions",
    [int]$BatchSize = 10000,
    [switch]$FunOnly,
    [switch]$OrdinalsOnly,
    [switch]$All,
    [switch]$UndocumentedOnly,
    [int]$MinCompletenessScore = 50,
    [switch]$ExcludeLibraryFunctions,
    [switch]$Preview,
    [switch]$Help
)

# Auto-generate output file name if not provided
if ([string]::IsNullOrEmpty($OutputFile)) {
    $OutputFile = "FunctionsTodo.txt"
}

function Show-Help {
    Write-Host @"
GHIDRA FUNCTION EXTRACTOR - REST API VERSION
============================================

USAGE:
    .\extract_ghidra_functions_REST.ps1 [OPTIONS]

OPTIONS:
    -DllName <name>       DLL name to extract from (default: D2Common.dll)
    -OutputFile <file>    Output file path (default: auto-generated from DLL name)
    -GhidraUrl <url>      Ghidra REST API URL (default: http://127.0.0.1:8089/list_functions)
    -BatchSize <number>   Functions per batch request (default: 10000)
    -FunOnly              Extract only FUN_ functions (excludes Ordinal_ functions)
    -OrdinalsOnly         Extract only Ordinal_ functions (excludes FUN_ functions)
    -All                  Include all functions (ignores completeness filtering)
    -UndocumentedOnly     Filter to only include functions needing documentation
    -MinCompletenessScore Minimum completeness score to exclude (default: 50, range: 0-100)
    -ExcludeLibraryFunctions  Exclude library functions (starting with ___, __, or _)
    -Preview              Show preview without writing file
    -Help                 Show this help message

EXAMPLES:
    .\extract_ghidra_functions_REST.ps1
    .\extract_ghidra_functions_REST.ps1 -DllName "D2Client.dll"
    .\extract_ghidra_functions_REST.ps1 -DllName "D2Game.dll" -Preview
    .\extract_ghidra_functions_REST.ps1 -DllName "Packets.dll" -OutputFile "PacketsTodo.txt"
    .\extract_ghidra_functions_REST.ps1 -GhidraUrl "http://localhost:8089/list_functions"
    .\extract_ghidra_functions_REST.ps1 -FunOnly
    .\extract_ghidra_functions_REST.ps1 -OrdinalsOnly
    .\extract_ghidra_functions_REST.ps1 -All
    .\extract_ghidra_functions_REST.ps1 -All -ExcludeLibraryFunctions
    .\extract_ghidra_functions_REST.ps1 -UndocumentedOnly
    .\extract_ghidra_functions_REST.ps1 -UndocumentedOnly -MinCompletenessScore 60
    .\extract_ghidra_functions_REST.ps1 -ExcludeLibraryFunctions

DESCRIPTION:
    Extracts both FUN_ and Ordinal_ functions from Ghidra using REST API calls for the specified DLL.
    By default, both FUN_ and Ordinal_ functions are included. Use -FunOnly or -OrdinalsOnly to filter to specific types.
    Use -All to get all functions regardless of documentation completeness.
    Use -UndocumentedOnly to filter for functions that need documentation (completeness score < threshold).
    Use -ExcludeLibraryFunctions to filter out library functions (starting with _, __, or ___).
    Functions are formatted as "[ ] FUN_035b14f0 @ 035b14f0" or "[ ] Ordinal_123 @ 035b14f0" for todo tracking.
    
    Supports any DLL including:
    - D2Common.dll (default)
    - D2Client.dll
    - D2Game.dll
    - Packets.dll
    - Any other DLL loaded in Ghidra
"@
    exit 0
}

if ($Help) {
    Show-Help
}

# Validate conflicting parameters
if ($FunOnly -and $OrdinalsOnly) {
    Write-Host "ERROR: Cannot specify both -FunOnly and -OrdinalsOnly" -ForegroundColor Red
    Write-Host "Use -FunOnly for FUN_ functions only, -OrdinalsOnly for Ordinal_ functions only, or neither for both types." -ForegroundColor Yellow
    exit 1
}

if ($All -and $UndocumentedOnly) {
    Write-Host "ERROR: Cannot specify both -All and -UndocumentedOnly" -ForegroundColor Red
    Write-Host "Use -All to get all functions, or -UndocumentedOnly to filter by completeness score." -ForegroundColor Yellow
    exit 1
}

Write-Host "GHIDRA FUNCTION EXTRACTOR - REST API VERSION" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "Output file: $OutputFile"
Write-Host "Ghidra URL: $GhidraUrl"
Write-Host "Batch size: $BatchSize"
if ($FunOnly) {
    Write-Host "Function filter: FUN_ only" -ForegroundColor Yellow
} elseif ($OrdinalsOnly) {
    Write-Host "Function filter: Ordinals only" -ForegroundColor Yellow
} else {
    Write-Host "Function filter: Both FUN_ and Ordinals (default)" -ForegroundColor Cyan
}
if ($ExcludeLibraryFunctions) {
    Write-Host "Library functions: EXCLUDED (_, __, ___)" -ForegroundColor Yellow
}
if ($All) {
    Write-Host "Documentation filter: ALL FUNCTIONS (no completeness filtering)" -ForegroundColor Cyan
} elseif ($UndocumentedOnly) {
    Write-Host "Documentation filter: Undocumented only" -ForegroundColor Yellow
    Write-Host "Min completeness score: $MinCompletenessScore" -ForegroundColor Yellow
} else {
    Write-Host "Documentation filter: All functions (default)" -ForegroundColor Cyan
}
Write-Host ""

$allFunctions = @()
$offset = 0
$totalFetched = 0
$filteredCount = 0
$libraryFunctionsFiltered = 0
$completenessApiUrl = $GhidraUrl -replace '/list_functions.*$', '/analyze_function_completeness'

try {
    do {
        Write-Host "Fetching batch: offset $offset, limit $BatchSize..." -ForegroundColor Blue
        
        # Construct URL with pagination parameters
        $requestUrl = "$GhidraUrl"
        if ($GhidraUrl -notlike "*offset=*") {
            $separator = if ($GhidraUrl -like "*?*") { "&" } else { "?" }
            $requestUrl = "$GhidraUrl${separator}offset=$offset&limit=$BatchSize"
        }
        
        # Make REST API call
        $response = Invoke-WebRequest -Uri $requestUrl -Method GET -TimeoutSec 30
        
        if ($response.StatusCode -eq 200) {
            $content = $response.Content
            Write-Host "Response length: $($content.Length) characters" -ForegroundColor Cyan
            
            # Parse functions from response
            # Expected format from Ghidra: "FUN_address at address" per line
            $lines = $content -split "`n" | Where-Object { $_.Trim() -ne "" }
            $batchFunctions = @()
            
            foreach ($line in $lines) {
                $line = $line.Trim()
                # Match pattern: function_name at hexaddress
                if ($line -match '^(.+?)\s+at\s+([0-9a-fA-F]+)') {
                    $funcName = $matches[1]
                    $address = $matches[2]
                    
                    # Apply function type filtering
                    if ($FunOnly -and $funcName -like "Ordinal_*") {
                        continue  # Skip Ordinal_ functions when FunOnly is specified
                    }
                    if ($OrdinalsOnly -and $funcName -like "FUN_*") {
                        continue  # Skip FUN_ functions when OrdinalsOnly is specified
                    }
                    # Default: include both FUN_ and Ordinal_ functions
                    
                    # Filter out library functions if requested
                    if ($ExcludeLibraryFunctions) {
                        # Check if function name starts with ___, __, or _
                        if ($funcName -match '^___' -or $funcName -match '^__[^_]' -or $funcName -match '^_[^_]') {
                            $libraryFunctionsFiltered++
                            Write-Host "  Filtered library function: $funcName" -ForegroundColor DarkGray
                            continue
                        }
                    }
                    
                    # Check documentation completeness if -UndocumentedOnly is specified
                    # Skip completeness check if -All is specified
                    $includeFunction = $true
                    if ($UndocumentedOnly -and -not $All) {
                        try {
                            $completenessUrl = "$completenessApiUrl`?function_address=0x$address"
                            $completenessResponse = Invoke-RestMethod -Uri $completenessUrl -Method GET -TimeoutSec 10
                            
                            if ($completenessResponse -and $null -ne $completenessResponse.completeness_score) {
                                $score = [int]$completenessResponse.completeness_score
                                
                                # Adjust score: Ordinal_XXX and FUN_XXX are both "default names"
                                # Treat Ordinal_ names as needing documentation like FUN_ names
                                $hasRealName = $completenessResponse.has_custom_name -and 
                                               -not ($funcName -match '^(FUN_|Ordinal_)')
                                
                                # If it's a default name (FUN_ or Ordinal_), subtract 25 points
                                # This makes Ordinal_XXX and FUN_XXX equivalent in scoring
                                if (-not $hasRealName -and $completenessResponse.has_custom_name) {
                                    $score = $score - 25
                                    Write-Host "  Adjusted score for $funcName : $score (default name penalty)" -ForegroundColor DarkYellow
                                }
                                
                                if ($score -ge $MinCompletenessScore) {
                                    $includeFunction = $false
                                    $filteredCount++
                                    Write-Host "  Filtered $funcName (score: $score >= $MinCompletenessScore)" -ForegroundColor DarkGray
                                } else {
                                    Write-Host "  Include $funcName (score: $score < $MinCompletenessScore)" -ForegroundColor Cyan
                                }
                            }
                        } catch {
                            Write-Host "  Warning: Could not check completeness for $funcName : $($_.Exception.Message)" -ForegroundColor Yellow
                            # Include function if completeness check fails
                        }
                    }
                    
                    if ($includeFunction) {
                        $batchFunctions += "[ ] $funcName @ $address"
                    }
                }
            }
            
            if ($batchFunctions.Count -gt 0) {
                $allFunctions += $batchFunctions
                $totalFetched += $batchFunctions.Count
                Write-Host "Found $($batchFunctions.Count) functions in this batch" -ForegroundColor Green
            } else {
                Write-Host "No matching functions found in this batch" -ForegroundColor Yellow
                break
            }
            
            # Check if we got fewer functions than requested (end of data)
            if ($batchFunctions.Count -lt $BatchSize) {
                Write-Host "Received fewer functions than batch size - end of data" -ForegroundColor Yellow
                break
            }
            
            $offset += $BatchSize
        } else {
            Write-Host "ERROR: HTTP $($response.StatusCode) - $($response.StatusDescription)" -ForegroundColor Red
            break
        }
        
    } while ($true)
    
} catch {
    Write-Host "ERROR: Exception occurred: $($_.Exception.Message)" -ForegroundColor Red
    
    if ($_.Exception.InnerException) {
        Write-Host "Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
    
    # Check if it's a connection error
    if ($_.Exception.Message -like "*Unable to connect*" -or $_.Exception.Message -like "*refused*") {
        Write-Host ""
        Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
        Write-Host "1. Make sure Ghidra is running with REST API enabled"
        Write-Host "2. Verify the URL: $GhidraUrl"
        Write-Host "3. Check if port 8089 is accessible"
        Write-Host "4. Try: Test-NetConnection -ComputerName 127.0.0.1 -Port 8089"
    }
}

Write-Host ""
Write-Host "WRITING RESULTS..." -ForegroundColor Green

if ($allFunctions.Count -gt 0) {
    if ($Preview) {
        Write-Host "PREVIEW MODE - First 10 functions:" -ForegroundColor Cyan
        $allFunctions | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" }
        if ($allFunctions.Count -gt 10) {
            Write-Host "  ... and $($allFunctions.Count - 10) more functions"
        }
    } else {
        Write-Host "Writing $($allFunctions.Count) functions to $OutputFile..." -ForegroundColor Green
        
        # Create header for the file
        $functionType = if ($FunOnly) { "FUN_ functions only" } elseif ($OrdinalsOnly) { "Ordinal_ functions only" } else { "FUN_ and Ordinal_ functions" }
        $filterNote = if ($All) { " (all functions)" } elseif ($UndocumentedOnly) { " (completeness < $MinCompletenessScore)" } else { "" }
        $libraryNote = if ($ExcludeLibraryFunctions) { " (excluding library functions)" } else { "" }
        $header = @(
            "# $DllName Function Todo List"
            "# Format: [ ] FUN_address @ address $(if (-not $FunOnly) { 'or [ ] Ordinal_number @ address' })"
            "# Generated by extract_ghidra_functions_REST.ps1 on $(Get-Date)"
            "# Total functions: $($allFunctions.Count) ($functionType$filterNote$libraryNote)"
            $(if ($UndocumentedOnly) { "# Filtered out: $filteredCount functions (completeness >= $MinCompletenessScore)" })
            $(if ($ExcludeLibraryFunctions) { "# Filtered out: $libraryFunctionsFiltered library functions (_, __, ___)" })
            "#"
            ""
        )
        
        # Write to file
        ($header + $allFunctions) | Out-File -FilePath $OutputFile -Encoding UTF8
        
        Write-Host "SUCCESS! $($allFunctions.Count) functions written to $OutputFile" -ForegroundColor Green
    }
} else {
    Write-Host "No functions found to write" -ForegroundColor Yellow
    
    if (-not $Preview) {
        # Create empty file with header
        $functionType = if ($FunOnly) { "FUN_ functions only" } elseif ($OrdinalsOnly) { "Ordinal_ functions only" } else { "FUN_ and Ordinal_ functions" }
        $filterNote = if ($All) { " (all functions)" } elseif ($UndocumentedOnly) { " (completeness < $MinCompletenessScore)" } else { "" }
        $libraryNote = if ($ExcludeLibraryFunctions) { " (excluding library functions)" } else { "" }
        $header = @(
            "# $DllName Function Todo List"
            "# Format: [ ] FUN_address @ address $(if (-not $FunOnly) { 'or [ ] Ordinal_number @ address' })"
            "# Generated by extract_ghidra_functions_REST.ps1 on $(Get-Date)"
            "# No functions found ($functionType filter$filterNote$libraryNote)"
            "#"
            ""
        )
        $header | Out-File -FilePath $OutputFile -Encoding UTF8
    }
}

Write-Host ""
Write-Host "STATISTICS:" -ForegroundColor Green
Write-Host "  Total functions found: $($allFunctions.Count)"
if ($ExcludeLibraryFunctions) {
    Write-Host "  Filtered out (library functions): $libraryFunctionsFiltered" -ForegroundColor Cyan
}
if ($UndocumentedOnly) {
    Write-Host "  Filtered out (well-documented): $filteredCount" -ForegroundColor Cyan
}
Write-Host "  Output file: $OutputFile"
if (Test-Path $OutputFile) {
    $fileSize = (Get-Item $OutputFile).Length
    Write-Host "  File size: $fileSize bytes"
}

Write-Host ""
Write-Host "EXTRACTION COMPLETE!" -ForegroundColor Green