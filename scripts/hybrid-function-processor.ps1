param(
    [string]$TodoFile = ".\FunctionsTodo.txt",
    [switch]$Preview,
    [switch]$Help
)

if ($Help) {
    Write-Host "HYBRID FUNCTION PROCESSOR - Simplified Version"
    Write-Host ""
    Write-Host "USAGE:"
    Write-Host "  .\hybrid-function-processor.ps1"
    Write-Host "  .\hybrid-function-processor.ps1 -Preview"
    exit 0
}

$script:BasePrompt = Get-Content "..\docs\prompts\OPTIMIZED_FUNCTION_DOCUMENTATION.md" -Raw

Write-Host "HYBRID FUNCTION PROCESSOR FOR GHIDRA" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green
Write-Host ""

if (-not (Test-Path $TodoFile)) {
    Write-Host "ERROR: Todo file not found: $TodoFile" -ForegroundColor Red
    exit 1
}

$content = Get-Content $TodoFile
$allPendingFunctions = $content | Where-Object { $_ -match '^\[ \] ((?:FUN_|Ordinal_)[0-9a-fA-F]+)' }

if ($allPendingFunctions.Count -eq 0) {
    Write-Host "No pending functions found" -ForegroundColor Yellow
    exit 0
}

Write-Host "Total Pending Functions: $($allPendingFunctions.Count)" -ForegroundColor Cyan
Write-Host ""

$Phase1Count = 5
$Phase2Count = 3

$phase1Functions = $allPendingFunctions | Select-Object -First $Phase1Count
$phase2Functions = $allPendingFunctions | Select-Object -Skip $Phase1Count -First $Phase2Count
$phase3Functions = $allPendingFunctions | Select-Object -Skip ($Phase1Count + $Phase2Count)

Write-Host "PHASE DISTRIBUTION:" -ForegroundColor Cyan
Write-Host "  Phase 1 (Adaptive): $($phase1Functions.Count) functions" -ForegroundColor Yellow
Write-Host "  Phase 2 (Formalize): $($phase2Functions.Count) functions" -ForegroundColor Yellow
Write-Host "  Phase 3 (Stateful): $($phase3Functions.Count) functions" -ForegroundColor Yellow
Write-Host ""

if ($Preview) {
    Write-Host "PREVIEW MODE - No functions will be processed" -ForegroundColor Magenta
    exit 0
}

Write-Host "PHASE 1: ADAPTIVE PROMPT ENHANCEMENT" -ForegroundColor Green
Write-Host ""

$allInsights = @()
$successCount = 0

for ($i = 0; $i -lt $phase1Functions.Count; $i++) {
    $func = $phase1Functions[$i]
    $funcName = if ($func -match '\[(X| )\]\s+([\w_]+)') { $matches[2] } else { $func }
    
    Write-Host "[$($i+1)/$($phase1Functions.Count)] Processing: $funcName" -ForegroundColor Yellow
    
    $adaptivePrompt = $script:BasePrompt
    
    if ($allInsights.Count -gt 0) {
        $adaptivePrompt += "`n`nPrevious Phase 1 insights: `n"
        $allInsights | Select-Object -Last 3 | ForEach-Object {
            $adaptivePrompt += "- $_`n"
        }
    }
    
    $adaptivePrompt += "`nTarget function: $funcName`n"
    
    try {
        $env:NODE_OPTIONS = "--max-old-space-size=8192"
        $output = echo $adaptivePrompt | claude -p --mcp-config "..\mcp-config.json" --dangerously-skip-permissions 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [+] Success" -ForegroundColor Green
            $allInsights += "Processed $funcName"
            $successCount++
        } else {
            Write-Host "  [-] Failed" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  [-] Exception: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        $env:NODE_OPTIONS = $null
    }
}

$phase1Results = @{
    'timestamp' = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    'functions_processed' = $phase1Functions.Count
    'insights' = $allInsights
}

$phase1Results | ConvertTo-Json | Out-File -FilePath ".\raw_insights.json" -Encoding UTF8
Write-Host "[+] Phase 1 results saved to: raw_insights.json" -ForegroundColor Green

Write-Host ""
Write-Host "PHASE 2: PATTERN FORMALIZATION" -ForegroundColor Cyan
Write-Host ""

$knowledgeBase = @{
    'structures' = @{}
    'patterns' = @()
    'history' = @()
}

for ($i = 0; $i -lt $phase2Functions.Count; $i++) {
    $func = $phase2Functions[$i]
    $funcName = if ($func -match '\[(X| )\]\s+([\w_]+)') { $matches[2] } else { $func }
    
    Write-Host "[$($i+1)/$($phase2Functions.Count)] Validating: $funcName" -ForegroundColor Yellow
    
    $formalizationPrompt = $script:BasePrompt + "`n`nValidate patterns with $funcName`n"
    
    try {
        $env:NODE_OPTIONS = "--max-old-space-size=8192"
        $output = echo $formalizationPrompt | claude -p --mcp-config "..\mcp-config.json" --dangerously-skip-permissions 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [+] Validated" -ForegroundColor Green
            $knowledgeBase.history += $funcName
        } else {
            Write-Host "  [-] Failed" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  [-] Exception" -ForegroundColor Red
    }
    finally {
        $env:NODE_OPTIONS = $null
    }
}

$knowledgeBase | ConvertTo-Json | Out-File -FilePath ".\knowledge_base.json" -Encoding UTF8
Write-Host "[+] Knowledge base saved to: knowledge_base.json" -ForegroundColor Green

Write-Host ""
Write-Host "PHASE 3: STATEFUL AGENT" -ForegroundColor Magenta
Write-Host ""

$phase3Results = @()
$phase3Success = 0

for ($i = 0; $i -lt $phase3Functions.Count; $i++) {
    $func = $phase3Functions[$i]
    $funcName = if ($func -match '\[(X| )\]\s+([\w_]+)') { $matches[2] } else { $func }
    
    Write-Host "[$($i+1)/$($phase3Functions.Count)] Processing: $funcName" -ForegroundColor Magenta
    
    $statefulPrompt = $script:BasePrompt + "`n`nStateful agent processes $funcName`n"
    
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $env:NODE_OPTIONS = "--max-old-space-size=8192"
        $output = echo $statefulPrompt | claude -p --mcp-config "..\mcp-config.json" --dangerously-skip-permissions 2>&1
        
        $timer.Stop()
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [+] Done in $([math]::Round($timer.Elapsed.TotalSeconds, 1))s" -ForegroundColor Green
            $phase3Success++
        } else {
            Write-Host "  [-] Failed" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  [-] Exception" -ForegroundColor Red
    }
    finally {
        $env:NODE_OPTIONS = $null
    }
}

$finalResults = @{
    'timestamp' = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    'total_phase3' = $phase3Functions.Count
    'successful' = $phase3Success
}

$finalResults | ConvertTo-Json | Out-File -FilePath ".\final_results.json" -Encoding UTF8
Write-Host "[+] Final results saved to: final_results.json" -ForegroundColor Green

Write-Host ""
Write-Host "HYBRID PROCESSING COMPLETE" -ForegroundColor Green
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Phase 1: $($phase1Functions.Count) functions" -ForegroundColor Yellow
Write-Host "  Phase 2: $($phase2Functions.Count) functions" -ForegroundColor Yellow
Write-Host "  Phase 3: $phase3Success/$($phase3Functions.Count) functions" -ForegroundColor Yellow
Write-Host ""
