# PowerShell script to extract Ghidra functions via REST API and format for todo list
param(
    [string]$ProgramName = "Game.exe",
    [string]$OutputFile = "",
    [string]$GhidraUrl = "http://127.0.0.1:8089",
    [int]$BatchSize = 1000,
    [switch]$FunOnly,
    [switch]$OrdinalsOnly,
    [switch]$All,
    [switch]$UndocumentedOnly,
    [int]$MinCompletenessScore = 80,
    [switch]$ExcludeLibraryFunctions,
    [switch]$IncludeOnlyLibraryFunctions,
    [switch]$IncludeThunks,
    [switch]$IncludeExternals,
    [switch]$Preview,
    [switch]$RefreshAll,
    [string]$RefreshOutput = "",
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
    .\functions-extract.ps1 [OPTIONS]

OPTIONS:
    -ProgramName <name>   Program name (default: Game.exe)
    -OutputFile <file>    Output file path (default: auto-generated from program name)
    -GhidraUrl <url>      Ghidra REST API URL (default: http://127.0.0.1:8089)
    -BatchSize <number>   Functions per batch request (default: 1000)
    -FunOnly              Extract ONLY functions starting with FUN_ prefix (unnamed/auto-generated)
    -OrdinalsOnly         Extract ONLY functions starting with Ordinal_ prefix
    -All                  Include ALL functions (including named functions, ignores prefix filtering)
    -UndocumentedOnly     Filter to only include functions needing documentation
    -MinCompletenessScore Minimum completeness score to exclude (default: 50, range: 0-100)
    -ExcludeLibraryFunctions  Exclude library functions (starting with ___, __, or _)
    -IncludeOnlyLibraryFunctions  Include ONLY library functions (starting with ___, __, or _)
    -IncludeThunks        Include thunk functions (excluded by default)
    -IncludeExternals     Include external/imported function pointers (excluded by default)
    -Preview              Show preview without writing file
    -RefreshAll           Bypass FunctionsTodo.txt and evaluate completeness for ALL functions directly from Ghidra
    -RefreshOutput <file> Output file for -RefreshAll results (default: console output, supports .json or .csv extension)
    -Help                 Show this help message

EXAMPLES:
    .\functions-extract.ps1
    .\functions-extract.ps1 -ProgramName "Game.exe"
    .\functions-extract.ps1 -ProgramName "Server.exe" -Preview
    .\functions-extract.ps1 -ProgramName "Client.exe" -OutputFile "ClientTodo.txt"
    .\functions-extract.ps1 -GhidraUrl "http://localhost:8089"
    .\functions-extract.ps1 -FunOnly
    .\functions-extract.ps1 -OrdinalsOnly
    .\functions-extract.ps1 -All
    .\functions-extract.ps1 -All -ExcludeLibraryFunctions
    .\functions-extract.ps1 -UndocumentedOnly
    .\functions-extract.ps1 -UndocumentedOnly -MinCompletenessScore 60
    .\functions-extract.ps1 -ExcludeLibraryFunctions
    .\functions-extract.ps1 -IncludeOnlyLibraryFunctions
    .\functions-extract.ps1 -IncludeThunks -IncludeExternals
    .\functions-extract.ps1 -RefreshAll
    .\functions-extract.ps1 -RefreshAll -RefreshOutput completeness-report.json
    .\functions-extract.ps1 -RefreshAll -RefreshOutput completeness-report.csv

DESCRIPTION:
    Extracts functions from Ghidra using REST API calls for the specified program.
    By default, only FUN_ and Ordinal_ prefixed functions are included (undocumented functions).
    Thunk functions and external/imported function pointers are excluded by default.
    Use -FunOnly or -OrdinalsOnly to filter to a specific prefix type.
    Use -All to get all functions including named functions (ignores prefix filtering).
    Use -UndocumentedOnly to filter for functions that need documentation (completeness score < threshold).
    Use -ExcludeLibraryFunctions to filter out library functions (starting with _, __, or ___).
    Use -IncludeOnlyLibraryFunctions to include ONLY library functions (starting with _, __, or ___).
    Use -IncludeThunks to include thunk functions (jump stubs to other functions).
    Use -IncludeExternals to include external/imported function pointers.
    Use -RefreshAll to bypass FunctionsTodo.txt and evaluate completeness for all functions directly from Ghidra.
    Use -RefreshOutput with -RefreshAll to save results to a JSON or CSV file.
    Functions are formatted as "[ ] FUN_035b14f0 @ 035b14f0" or "[ ] Ordinal_123 @ 035b14f0" for todo tracking.
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

if ($ExcludeLibraryFunctions -and $IncludeOnlyLibraryFunctions) {
    Write-Host "ERROR: Cannot specify both -ExcludeLibraryFunctions and -IncludeOnlyLibraryFunctions" -ForegroundColor Red
    Write-Host "Use -ExcludeLibraryFunctions to exclude library functions, or -IncludeOnlyLibraryFunctions to include only library functions." -ForegroundColor Yellow
    exit 1
}

# === REFRESH ALL MODE ===
# Bypass FunctionsTodo.txt and evaluate completeness for all functions directly from Ghidra
if ($RefreshAll) {
    Write-Host "GHIDRA FUNCTION COMPLETENESS SCAN - REFRESH ALL MODE" -ForegroundColor Magenta
    Write-Host "=====================================================" -ForegroundColor Magenta
    Write-Host "Ghidra URL: $GhidraUrl"
    Write-Host "Scanning ALL functions directly from Ghidra (bypassing FunctionsTodo.txt)" -ForegroundColor Cyan
    Write-Host ""
    
    $listApiUrl = "$GhidraUrl/list_functions_enhanced"
    $completenessApiUrl = "$GhidraUrl/analyze_function_completeness"
    
    $allResults = @()
    $offset = 0
    $totalProcessed = 0
    $scoreDistribution = @{
        "100" = 0
        "90-99" = 0
        "80-89" = 0
        "70-79" = 0
        "60-69" = 0
        "50-59" = 0
        "40-49" = 0
        "30-39" = 0
        "20-29" = 0
        "10-19" = 0
        "0-9" = 0
    }
    
    try {
        # First, get all functions
        Write-Host "Fetching all functions from Ghidra..." -ForegroundColor Yellow
        $allFunctions = @()
        
        do {
            $listUrl = "$listApiUrl`?offset=$offset&limit=$BatchSize"
            $response = Invoke-RestMethod -Uri $listUrl -Method GET -TimeoutSec 30
            
            if ($response -and $response.functions) {
                $allFunctions += $response.functions
                $offset += $response.functions.Count
                Write-Host "  Fetched $($allFunctions.Count) functions..." -ForegroundColor DarkGray
            }
        } while ($response -and $response.functions -and $response.functions.Count -eq $BatchSize)
        
        Write-Host "Total functions found: $($allFunctions.Count)" -ForegroundColor Green
        Write-Host ""
        Write-Host "Evaluating completeness for each function..." -ForegroundColor Yellow
        Write-Host ""
        
        $startTime = Get-Date
        
        foreach ($func in $allFunctions) {
            $funcName = $func.name
            $address = $func.address
            
            # Skip thunks and externals by default (like normal mode)
            if (-not $IncludeThunks -and $func.is_thunk) {
                continue
            }
            if (-not $IncludeExternals -and $func.is_external) {
                continue
            }
            
            try {
                $completenessUrl = "$completenessApiUrl`?function_address=0x$address"
                $completenessResponse = Invoke-RestMethod -Uri $completenessUrl -Method GET -TimeoutSec 10
                
                $score = 0
                $hasCustomName = $false
                $hasPrototype = $false
                $hasPlateComment = $false
                $undefinedVars = @()
                $recommendations = @()
                
                if ($completenessResponse) {
                    $score = [int]$completenessResponse.completeness_score
                    $hasCustomName = $completenessResponse.has_custom_name
                    $hasPrototype = $completenessResponse.has_prototype
                    $hasPlateComment = $completenessResponse.has_plate_comment
                    $undefinedVars = $completenessResponse.undefined_variables
                    $recommendations = $completenessResponse.recommendations
                }
                
                # Update score distribution
                if ($score -eq 100) { $scoreDistribution["100"]++ }
                elseif ($score -ge 90) { $scoreDistribution["90-99"]++ }
                elseif ($score -ge 80) { $scoreDistribution["80-89"]++ }
                elseif ($score -ge 70) { $scoreDistribution["70-79"]++ }
                elseif ($score -ge 60) { $scoreDistribution["60-69"]++ }
                elseif ($score -ge 50) { $scoreDistribution["50-59"]++ }
                elseif ($score -ge 40) { $scoreDistribution["40-49"]++ }
                elseif ($score -ge 30) { $scoreDistribution["30-39"]++ }
                elseif ($score -ge 20) { $scoreDistribution["20-29"]++ }
                elseif ($score -ge 10) { $scoreDistribution["10-19"]++ }
                else { $scoreDistribution["0-9"]++ }
                
                $result = [PSCustomObject]@{
                    Name = $funcName
                    Address = "0x$address"
                    Score = $score
                    HasCustomName = $hasCustomName
                    HasPrototype = $hasPrototype
                    HasPlateComment = $hasPlateComment
                    UndefinedVarsCount = $undefinedVars.Count
                    RecommendationsCount = $recommendations.Count
                    UndefinedVars = ($undefinedVars -join "; ")
                    Recommendations = ($recommendations -join "; ")
                }
                
                $allResults += $result
                $totalProcessed++
                
                # Progress indicator
                if ($totalProcessed % 50 -eq 0) {
                    $elapsed = (Get-Date) - $startTime
                    $rate = $totalProcessed / $elapsed.TotalSeconds
                    $remaining = ($allFunctions.Count - $totalProcessed) / $rate
                    Write-Host "  Processed $totalProcessed / $($allFunctions.Count) functions (ETA: $([int]$remaining)s)" -ForegroundColor DarkGray
                }
                
                # Small delay to avoid overwhelming the server
                Start-Sleep -Milliseconds 50
                
            } catch {
                Write-Host "  Warning: Could not check completeness for $funcName : $($_.Exception.Message)" -ForegroundColor Yellow
                
                $result = [PSCustomObject]@{
                    Name = $funcName
                    Address = "0x$address"
                    Score = -1
                    HasCustomName = $false
                    HasPrototype = $false
                    HasPlateComment = $false
                    UndefinedVarsCount = 0
                    RecommendationsCount = 0
                    UndefinedVars = "ERROR"
                    Recommendations = $_.Exception.Message
                }
                
                $allResults += $result
                $totalProcessed++
            }
        }
        
        $endTime = Get-Date
        $totalTime = $endTime - $startTime
        
        Write-Host ""
        Write-Host "=============================================" -ForegroundColor Green
        Write-Host "COMPLETENESS SCAN COMPLETE" -ForegroundColor Green
        Write-Host "=============================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Total functions scanned: $totalProcessed" -ForegroundColor Cyan
        Write-Host "Total time: $([int]$totalTime.TotalMinutes)m $([int]($totalTime.TotalSeconds % 60))s" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "SCORE DISTRIBUTION:" -ForegroundColor Yellow
        Write-Host "  100:    $($scoreDistribution["100"]) functions" -ForegroundColor Green
        Write-Host "  90-99:  $($scoreDistribution["90-99"]) functions" -ForegroundColor Green
        Write-Host "  80-89:  $($scoreDistribution["80-89"]) functions" -ForegroundColor DarkGreen
        Write-Host "  70-79:  $($scoreDistribution["70-79"]) functions" -ForegroundColor Yellow
        Write-Host "  60-69:  $($scoreDistribution["60-69"]) functions" -ForegroundColor Yellow
        Write-Host "  50-59:  $($scoreDistribution["50-59"]) functions" -ForegroundColor DarkYellow
        Write-Host "  40-49:  $($scoreDistribution["40-49"]) functions" -ForegroundColor Red
        Write-Host "  30-39:  $($scoreDistribution["30-39"]) functions" -ForegroundColor Red
        Write-Host "  20-29:  $($scoreDistribution["20-29"]) functions" -ForegroundColor DarkRed
        Write-Host "  10-19:  $($scoreDistribution["10-19"]) functions" -ForegroundColor DarkRed
        Write-Host "  0-9:    $($scoreDistribution["0-9"]) functions" -ForegroundColor DarkRed
        Write-Host ""
        
        # Calculate summary stats
        $avgScore = ($allResults | Where-Object { $_.Score -ge 0 } | Measure-Object -Property Score -Average).Average
        $wellDocumented = ($allResults | Where-Object { $_.Score -ge 80 }).Count
        $needsWork = ($allResults | Where-Object { $_.Score -ge 0 -and $_.Score -lt 80 }).Count
        
        Write-Host "SUMMARY:" -ForegroundColor Yellow
        Write-Host "  Average completeness score: $([math]::Round($avgScore, 1))%" -ForegroundColor Cyan
        Write-Host "  Well-documented (>= 80): $wellDocumented functions" -ForegroundColor Green
        Write-Host "  Needs work (< 80): $needsWork functions" -ForegroundColor Yellow
        Write-Host ""
        
        # Output to file if requested
        if (-not [string]::IsNullOrEmpty($RefreshOutput)) {
            $ext = [System.IO.Path]::GetExtension($RefreshOutput).ToLower()
            
            if ($ext -eq ".json") {
                $jsonOutput = @{
                    scan_date = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    total_functions = $totalProcessed
                    average_score = [math]::Round($avgScore, 1)
                    well_documented_count = $wellDocumented
                    needs_work_count = $needsWork
                    score_distribution = $scoreDistribution
                    functions = $allResults
                }
                $jsonOutput | ConvertTo-Json -Depth 5 | Out-File -FilePath $RefreshOutput -Encoding UTF8
                Write-Host "Results written to: $RefreshOutput (JSON format)" -ForegroundColor Green
            } elseif ($ext -eq ".csv") {
                $allResults | Export-Csv -Path $RefreshOutput -NoTypeInformation -Encoding UTF8
                Write-Host "Results written to: $RefreshOutput (CSV format)" -ForegroundColor Green
            } else {
                # Plain text format
                $textOutput = @(
                    "# Ghidra Function Completeness Report"
                    "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                    "# Total functions: $totalProcessed"
                    "# Average score: $([math]::Round($avgScore, 1))%"
                    "#"
                    "# Score Distribution:"
                    "#   100:    $($scoreDistribution["100"])"
                    "#   90-99:  $($scoreDistribution["90-99"])"
                    "#   80-89:  $($scoreDistribution["80-89"])"
                    "#   70-79:  $($scoreDistribution["70-79"])"
                    "#   60-69:  $($scoreDistribution["60-69"])"
                    "#   50-59:  $($scoreDistribution["50-59"])"
                    "#   40-49:  $($scoreDistribution["40-49"])"
                    "#   30-39:  $($scoreDistribution["30-39"])"
                    "#   20-29:  $($scoreDistribution["20-29"])"
                    "#   10-19:  $($scoreDistribution["10-19"])"
                    "#   0-9:    $($scoreDistribution["0-9"])"
                    "#"
                    ""
                    "# Functions sorted by score (lowest first):"
                    ""
                )
                
                $sortedResults = $allResults | Sort-Object Score
                foreach ($r in $sortedResults) {
                    $textOutput += "$($r.Name) @ $($r.Address) - Score: $($r.Score)% | CustomName: $($r.HasCustomName) | Prototype: $($r.HasPrototype) | PlateComment: $($r.HasPlateComment) | UndefinedVars: $($r.UndefinedVarsCount)"
                }
                
                $textOutput | Out-File -FilePath $RefreshOutput -Encoding UTF8
                Write-Host "Results written to: $RefreshOutput (text format)" -ForegroundColor Green
            }
        } else {
            # Console output - show lowest scoring functions
            Write-Host "LOWEST SCORING FUNCTIONS (need most work):" -ForegroundColor Yellow
            $lowestScoring = $allResults | Where-Object { $_.Score -ge 0 } | Sort-Object Score | Select-Object -First 20
            foreach ($r in $lowestScoring) {
                $scoreColor = if ($r.Score -lt 30) { "Red" } elseif ($r.Score -lt 50) { "DarkYellow" } else { "Yellow" }
                Write-Host "  $($r.Name) @ $($r.Address) - Score: $($r.Score)%" -ForegroundColor $scoreColor
            }
            Write-Host ""
            Write-Host "Use -RefreshOutput <file.json|file.csv> to save full results to a file" -ForegroundColor DarkGray
        }
        
    } catch {
        Write-Host "ERROR: Failed to scan functions: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.InnerException) {
            Write-Host "Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
        }
    }
    
    exit 0
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
} elseif ($All) {
    Write-Host "Function filter: ALL functions (including named)" -ForegroundColor Cyan
} else {
    Write-Host "Function filter: FUN_ and Ordinal_ only (default)" -ForegroundColor Cyan
}
if ($ExcludeLibraryFunctions) {
    Write-Host "Library functions: EXCLUDED (_, __, ___)" -ForegroundColor Yellow
}
if ($IncludeOnlyLibraryFunctions) {
    Write-Host "Library functions: ONLY INCLUDED (_, __, ___)" -ForegroundColor Yellow
}
if (-not $IncludeThunks) {
    Write-Host "Thunk functions: EXCLUDED (default)" -ForegroundColor Cyan
} else {
    Write-Host "Thunk functions: INCLUDED" -ForegroundColor Yellow
}
if (-not $IncludeExternals) {
    Write-Host "External functions: EXCLUDED (default)" -ForegroundColor Cyan
} else {
    Write-Host "External functions: INCLUDED" -ForegroundColor Yellow
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
$thunkFunctionsFiltered = 0
$externalFunctionsFiltered = 0
$listFunctionsUrl = "$GhidraUrl/list_functions_enhanced"
$completenessApiUrl = "$GhidraUrl/analyze_function_completeness"

try {
    Write-Host "Fetching functions from Ghidra..." -ForegroundColor Blue
    
    # Make single REST API call - list_functions_enhanced returns JSON with thunk/external flags
    $requestUrl = "$listFunctionsUrl"
    
    # Make REST API call
    $response = Invoke-WebRequest -Uri $requestUrl -Method GET -TimeoutSec 60
    
    if ($response.StatusCode -eq 200) {
        $content = $response.Content
        Write-Host "Response length: $($content.Length) characters" -ForegroundColor Cyan
        
        # Parse JSON response
        $jsonResponse = $content | ConvertFrom-Json
        
        if ($jsonResponse.error) {
            Write-Host "ERROR: $($jsonResponse.error)" -ForegroundColor Red
            exit 1
        }
        
        $functions = $jsonResponse.functions
        Write-Host "Total functions received: $($functions.Count)" -ForegroundColor Cyan
        
        foreach ($func in $functions) {
            $funcName = $func.name
            $address = $func.address -replace '^0x', ''  # Remove 0x prefix if present
            $isThunk = $func.isThunk
            $isExternal = $func.isExternal
            
            # Filter thunk functions (excluded by default)
            if ($isThunk -and -not $IncludeThunks) {
                $thunkFunctionsFiltered++
                continue
            }
            
            # Filter external functions (excluded by default)
            if ($isExternal -and -not $IncludeExternals) {
                $externalFunctionsFiltered++
                continue
            }
            
            # Apply function type filtering
            if ($FunOnly) {
                # Only include functions that start with FUN_
                if (-not ($funcName -like "FUN_*")) {
                    continue
                }
            } elseif ($OrdinalsOnly) {
                # Only include functions that start with Ordinal_
                if (-not ($funcName -like "Ordinal_*")) {
                    continue
                }
            } elseif (-not $All) {
                # Default: Only include FUN_ and Ordinal_ prefixed functions
                if (-not (($funcName -like "FUN_*") -or ($funcName -like "Ordinal_*"))) {
                    continue
                }
            }
            # -All flag: include all functions (no prefix filtering)
            
            # Filter library functions if requested
            if ($ExcludeLibraryFunctions) {
                # Check if function name starts with ___, __, or _
                if ($funcName -match '^_+') {
                    $libraryFunctionsFiltered++
                    continue
                }
            }
            
            # Include only library functions if requested
            if ($IncludeOnlyLibraryFunctions) {
                # Check if function name starts with ___, __, or _
                if (-not ($funcName -match '^_+')) {
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
                $allFunctions += "[ ] $funcName @ $address"
                $totalFetched++
            }
        }
        
        Write-Host "Processed $($functions.Count) functions, found $totalFetched matching functions" -ForegroundColor Green
        if ($thunkFunctionsFiltered -gt 0) {
            Write-Host "  Filtered $thunkFunctionsFiltered thunk functions" -ForegroundColor DarkGray
        }
        if ($externalFunctionsFiltered -gt 0) {
            Write-Host "  Filtered $externalFunctionsFiltered external functions" -ForegroundColor DarkGray
        }
        if ($libraryFunctionsFiltered -gt 0) {
            Write-Host "  Filtered $libraryFunctionsFiltered library functions" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "ERROR: HTTP $($response.StatusCode) - $($response.StatusDescription)" -ForegroundColor Red
    }
        
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
            "# $ProgramName Function Todo List"
            "# Format: [ ] FUN_address @ address $(if (-not $FunOnly) { 'or [ ] Ordinal_number @ address' })"
            "# Generated by functions-extract.ps1 on $(Get-Date)"
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
            "# $ProgramName Function Todo List"
            "# Format: [ ] FUN_address @ address $(if (-not $FunOnly) { 'or [ ] Ordinal_number @ address' })"
            "# Generated by functions-extract.ps1 on $(Get-Date)"
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