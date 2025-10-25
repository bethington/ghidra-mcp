# PowerShell script to extract Ghidra functions via REST API and format for todo list
param(
    [string]$DllName = "D2Common.dll",
    [string]$OutputFile = "",
    [string]$GhidraUrl = "http://127.0.0.1:8089/list_functions",
    [int]$BatchSize = 10000,
    [switch]$Preview,
    [switch]$Help
)

# Auto-generate output file name if not provided
if ([string]::IsNullOrEmpty($OutputFile)) {
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($DllName)
    $OutputFile = "${baseName}PtrsTodo.txt"
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
    -Preview              Show preview without writing file
    -Help                 Show this help message

EXAMPLES:
    .\extract_ghidra_functions_REST.ps1
    .\extract_ghidra_functions_REST.ps1 -DllName "D2Client.dll"
    .\extract_ghidra_functions_REST.ps1 -DllName "D2Game.dll" -Preview
    .\extract_ghidra_functions_REST.ps1 -DllName "Packets.dll" -OutputFile "PacketsTodo.txt"
    .\extract_ghidra_functions_REST.ps1 -GhidraUrl "http://localhost:8089/list_functions"

DESCRIPTION:
    Extracts all FUN_ and Ordinal_ functions from Ghidra using REST API calls for the specified DLL
    and formats them as "[ ] FUN_035b14f0 @ 035b14f0" or "[ ] Ordinal_123 @ 035b14f0" for todo tracking.
    
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

Write-Host "GHIDRA FUNCTION EXTRACTOR - REST API VERSION" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "Output file: $OutputFile"
Write-Host "Ghidra URL: $GhidraUrl"
Write-Host "Batch size: $BatchSize"
Write-Host ""

$allFunctions = @()
$offset = 0
$totalFetched = 0

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
                # Match pattern: FUN_hexaddress at hexaddress OR Ordinal_number at hexaddress
                if ($line -match '^((?:FUN_[0-9a-fA-F]+|Ordinal_\d+))\s+at\s+([0-9a-fA-F]+)') {
                    $funcName = $matches[1]
                    $address = $matches[2]
                    $batchFunctions += "[ ] $funcName @ $address"
                }
            }
            
            if ($batchFunctions.Count -gt 0) {
                $allFunctions += $batchFunctions
                $totalFetched += $batchFunctions.Count
                Write-Host "Found $($batchFunctions.Count) FUN_/Ordinal_ functions in this batch" -ForegroundColor Green
            } else {
                Write-Host "No FUN_/Ordinal_ functions found in this batch" -ForegroundColor Yellow
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
        $header = @(
            "# $DllName Function Todo List"
            "# Format: [ ] FUN_address @ address or [ ] Ordinal_number @ address"
            "# Generated by extract_ghidra_functions_REST.ps1 on $(Get-Date)"
            "# Total functions: $($allFunctions.Count)"
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
        $header = @(
            "# $DllName Function Todo List"
            "# Format: [ ] FUN_address @ address or [ ] Ordinal_number @ address"
            "# Generated by extract_ghidra_functions_REST.ps1 on $(Get-Date)"
            "# No functions found"
            "#"
            ""
        )
        $header | Out-File -FilePath $OutputFile -Encoding UTF8
    }
}

Write-Host ""
Write-Host "STATISTICS:" -ForegroundColor Green
Write-Host "  Total functions found: $($allFunctions.Count)"
Write-Host "  Output file: $OutputFile"
if (Test-Path $OutputFile) {
    $fileSize = (Get-Item $OutputFile).Length
    Write-Host "  File size: $fileSize bytes"
}

Write-Host ""
Write-Host "EXTRACTION COMPLETE!" -ForegroundColor Green