param(
    [switch]$Reverse,
    [switch]$Single,
    [string]$Function,
    [switch]$Help
)

$todoFile = ".\\D2CommonPtrsTodo.txt"
$mcpConfigFile = "..\\mcp-config.json"
$promptFile = "..\\docs\\prompts\\OPTIMIZED_FUNCTION_DOCUMENTATION.md"

function Show-Help {
    Write-Host "function-process.ps1 - Function Processing with MCP"
    Write-Host ""
    Write-Host "OPTIONS:"
    Write-Host "  -Single           Process one function and stop"
    Write-Host "  -Function <name>  Process specific function"
    Write-Host "  -Reverse          Process from bottom to top"
    Write-Host "  -Help             Show this help"
    exit 0
}

function Process-Function {
    param([string]$funcName, [string]$address = "")
    
    if ($address) {
        Write-Host "Processing: $funcName @ $address" -ForegroundColor Green
    } else {
        Write-Host "Processing: $funcName" -ForegroundColor Green
    }
    
    # Load the optimized prompt template
    if (-not (Test-Path $promptFile)) {
        Write-Host "ERROR: Prompt file not found at $promptFile" -ForegroundColor Red
        return $false
    }
    
    $basePrompt = Get-Content $promptFile -Raw
    
    # Inject the specific function name into the prompt
    $prompt = $basePrompt -replace 'get_current_function\(\)', "search_functions_by_name(`"$funcName`")"
    $prompt = $prompt + "`n`n## TARGET FUNCTION`nFunction to document: $funcName`n`nProceed with complete documentation of this function."
    
    try {
        $env:NODE_OPTIONS = "--max-old-space-size=8192"
        Write-Host "Invoking Claude..." -ForegroundColor Cyan
        $output = echo $prompt | claude --mcp-config $mcpConfigFile --dangerously-skip-permissions 2>&1
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -eq 0) {
            Write-Host "Success!" -ForegroundColor Green
            Write-Host $output
            return $true
        } else {
            Write-Host "Failed with exit code $exitCode" -ForegroundColor Red
            return $false
        }
    }
    finally {
        $env:NODE_OPTIONS = $null
    }
}

if ($Help) { Show-Help }

if ($Function) {
    $success = Process-Function $Function
    if ($success) {
        $content = Get-Content $todoFile -Raw
        $updated = $content -replace "\[ \] ($Function)", "[X] $1"
        Set-Content $todoFile $updated -NoNewline
    }
    exit 0
}

while ($true) {
    $content = Get-Content $todoFile
    $pending = $content | Where-Object { $_ -match '^\[ \] ((?:FUN_|Ordinal_)[0-9a-fA-F]+)' }
    
    if ($pending.Count -eq 0) { break }
    
    $line = if ($Reverse) { $pending | Select-Object -Last 1 } else { $pending | Select-Object -First 1 }
    $matches = [regex]::Match($line, '^\[ \] ((?:FUN_|Ordinal_)[0-9a-fA-F]+) @ ([0-9a-fA-F]+)')
    $funcName = $matches.Groups[1].Value
    $address = $matches.Groups[2].Value
    
    Write-Host "
$($pending.Count) remaining" -ForegroundColor Yellow
    $success = Process-Function $funcName $address
    
    if ($success) {
        $content = Get-Content $todoFile -Raw
        $updated = $content -replace "\[ \] ($funcName)", "[X] $1"
        Set-Content $todoFile $updated -NoNewline
    }
    
    if ($Single) { break }
    Start-Sleep -Seconds 2
}
