# Run FindFunctionsAfterPadding.java against all open binaries in 1.01 folder
# This script iterates through each program and executes the padding finder script

param(
    [string]$GhidraUrl = "http://127.0.0.1:8089",
    [string]$OutputDir = "$PSScriptRoot\padding-results",
    [int]$TimeoutSeconds = 120
)

# Binaries in Classic/1.01 folder
$binaries = @(
    "Binkw32.dll",
    "Bnclient.dll", 
    "D2Client.dll",
    "D2CMP.dll",
    "D2Common.dll",
    "D2DDraw.dll",
    "D2Direct3D.dll",
    "D2Game.dll",
    "D2Gdi.dll",
    "D2Gfx.dll",
    "D2Glide.dll",
    "D2Lang.dll",
    "D2Launch.dll",
    "D2MCPClient.dll",
    "D2Multi.dll",
    "D2Net.dll",
    "D2Sound.dll",
    "D2VidTst.exe",
    "D2Win.dll",
    "Diablo II.exe",
    "Fog.dll",
    "Game.exe",
    "Ijl11.dll",
    "SmackW32.dll",
    "Storm.dll"
)

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    Write-Host "Created output directory: $OutputDir" -ForegroundColor Green
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FindFunctionsAfterPadding Runner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Ghidra URL: $GhidraUrl"
Write-Host "Output Directory: $OutputDir"
Write-Host "Timeout: $TimeoutSeconds seconds"
Write-Host "Total binaries: $($binaries.Count)"
Write-Host ""

$startTime = Get-Date
$successCount = 0
$failureCount = 0
$results = @()

foreach ($binary in $binaries) {
    Write-Host "[$([array]::IndexOf($binaries, $binary) + 1)/$($binaries.Count)] Running script on $binary..." -ForegroundColor Yellow
    
    try {
        # Switch to the program
        $switchUrl = "$GhidraUrl/switch_program"
        $switchPayload = @{ "name" = $binary } | ConvertTo-Json
        $switchResponse = Invoke-RestMethod -Uri $switchUrl -Method POST -Body $switchPayload -ContentType "application/json" -TimeoutSec 10
        
        if ($switchResponse.success -eq $true -or $switchResponse.message -like "*switched*") {
            Write-Host "  ✓ Switched to program: $binary" -ForegroundColor DarkGreen
        } else {
            Write-Host "  ✗ Failed to switch to program: $binary" -ForegroundColor Red
            $failureCount++
            $results += [PSCustomObject]@{
                Binary = $binary
                Status = "FAILED"
                Reason = "Failed to switch program"
                Output = ""
            }
            continue
        }
        
        # Run the script
        $scriptUrl = "$GhidraUrl/run_ghidra_script"
        $scriptPayload = @{
            "script_name" = "FindFunctionsAfterPadding"
        } | ConvertTo-Json
        
        Write-Host "  ⏳ Executing FindFunctionsAfterPadding..." -ForegroundColor DarkGray
        $scriptResponse = Invoke-RestMethod -Uri $scriptUrl -Method POST -Body $scriptPayload -ContentType "application/json" -TimeoutSec $TimeoutSeconds
        
        if ($scriptResponse) {
            $success = $scriptResponse.success -eq $true
            $output = $scriptResponse.console_output
            $errors = $scriptResponse.errors
            
            # Save output to file
            $outputFile = Join-Path $OutputDir "$($binary -replace '\.(dll|exe)$', '')_padding_results.txt"
            @(
                "Binary: $binary"
                "Timestamp: $(Get-Date)"
                "============================================"
                ""
                "SCRIPT OUTPUT:"
                $output
                ""
                $(if ($errors -and $errors.Count -gt 0) {
                    @("ERRORS:", ($errors | ConvertTo-Json))
                })
            ) | Out-File -FilePath $outputFile -Encoding UTF8
            
            if ($success) {
                Write-Host "  ✓ Script executed successfully" -ForegroundColor Green
                Write-Host "  📄 Output saved to: $(Split-Path -Leaf $outputFile)" -ForegroundColor DarkGray
                $successCount++
                $results += [PSCustomObject]@{
                    Binary = $binary
                    Status = "SUCCESS"
                    Reason = "Script completed"
                    Output = $outputFile
                }
            } else {
                Write-Host "  ⚠ Script completed with issues" -ForegroundColor Yellow
                if ($errors) {
                    Write-Host "  Errors: $($errors -join ', ')" -ForegroundColor Yellow
                }
                Write-Host "  📄 Output saved to: $(Split-Path -Leaf $outputFile)" -ForegroundColor DarkGray
                $failureCount++
                $results += [PSCustomObject]@{
                    Binary = $binary
                    Status = "PARTIAL"
                    Reason = "Script had errors"
                    Output = $outputFile
                }
            }
        }
        
    } catch {
        Write-Host "  ✗ Exception: $($_.Exception.Message)" -ForegroundColor Red
        $failureCount++
        $results += [PSCustomObject]@{
            Binary = $binary
            Status = "FAILED"
            Reason = $_.Exception.Message
            Output = ""
        }
    }
    
    Write-Host ""
}

$endTime = Get-Date
$totalTime = $endTime - $startTime

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "EXECUTION COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Time: $([int]$totalTime.TotalMinutes)m $([int]($totalTime.TotalSeconds % 60))s" -ForegroundColor Cyan
Write-Host "Successful: $successCount binaries" -ForegroundColor Green
Write-Host "Failed: $failureCount binaries" -ForegroundColor $(if ($failureCount -gt 0) { "Red" } else { "Green" })
Write-Host "Success Rate: $(if ($binaries.Count -gt 0) { [math]::Round(($successCount / $binaries.Count) * 100, 1) }%)%" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output Directory: $OutputDir" -ForegroundColor Green
Write-Host ""

# Save summary to file
$summaryFile = Join-Path $OutputDir "execution_summary.txt"
@(
    "FindFunctionsAfterPadding Execution Summary"
    "=========================================="
    "Execution Date: $(Get-Date)"
    "Total Time: $([int]$totalTime.TotalMinutes)m $([int]($totalTime.TotalSeconds % 60))s"
    "Binaries Processed: $($binaries.Count)"
    "Successful: $successCount"
    "Failed: $failureCount"
    "Success Rate: $(if ($binaries.Count -gt 0) { [math]::Round(($successCount / $binaries.Count) * 100, 1) }%)%"
    ""
    "Results:"
    "--------"
    ($results | Format-Table -AutoSize | Out-String)
) | Out-File -FilePath $summaryFile -Encoding UTF8

Write-Host "Summary saved to: $(Split-Path -Leaf $summaryFile)" -ForegroundColor Green
