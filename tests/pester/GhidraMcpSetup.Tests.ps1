#Requires -Version 5.1

# Tier-1 Pester suite for ghidra-mcp-setup.ps1
# Covers: AST syntax, -Help output, preflight pass/fail, version-mismatch
# rejection, and a regression guard for the Show-Usage stray-code bug.

BeforeAll {
    $script:RepoRoot   = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $script:ScriptPath = Join-Path $script:RepoRoot 'ghidra-mcp-setup.ps1'

    if (-not (Test-Path -LiteralPath $script:ScriptPath)) {
        throw "ghidra-mcp-setup.ps1 not found at $script:ScriptPath"
    }

    # Required Ghidra JAR list mirrors REQUIRED_GHIDRA_JARS in the script.
    $script:RequiredJars = @(
        'Ghidra\Features\Base\lib\Base.jar',
        'Ghidra\Features\Decompiler\lib\Decompiler.jar',
        'Ghidra\Framework\Docking\lib\Docking.jar',
        'Ghidra\Framework\Generic\lib\Generic.jar',
        'Ghidra\Framework\Project\lib\Project.jar',
        'Ghidra\Framework\SoftwareModeling\lib\SoftwareModeling.jar',
        'Ghidra\Framework\Utility\lib\Utility.jar',
        'Ghidra\Framework\Gui\lib\Gui.jar',
        'Ghidra\Framework\FileSystem\lib\FileSystem.jar',
        'Ghidra\Framework\Graph\lib\Graph.jar',
        'Ghidra\Framework\DB\lib\DB.jar',
        'Ghidra\Framework\Emulation\lib\Emulation.jar',
        'Ghidra\Features\PDB\lib\PDB.jar',
        'Ghidra\Features\FunctionID\lib\FunctionID.jar',
        'Ghidra\Framework\Help\lib\Help.jar'
    )

    function New-FakeGhidraLayout {
        param(
            [Parameter(Mandatory = $true)][string]$Root,
            [Parameter(Mandatory = $true)][string]$Version,
            [string[]]$OmitJars = @()
        )

        $null = New-Item -ItemType Directory -Path $Root -Force

        # Launcher probe used by preflight and the main deploy guard.
        Set-Content -LiteralPath (Join-Path $Root 'ghidraRun.bat') -Value '@echo fake' -Encoding ASCII

        # application.properties is authoritative for Get-VersionFromGhidraProperties.
        $appPropsDir = Join-Path $Root 'Ghidra'
        $null = New-Item -ItemType Directory -Path $appPropsDir -Force
        Set-Content -LiteralPath (Join-Path $appPropsDir 'application.properties') `
            -Value "application.version=$Version" -Encoding ASCII

        foreach ($rel in $script:RequiredJars) {
            if ($OmitJars -contains $rel) { continue }
            $full = Join-Path $Root $rel
            $null = New-Item -ItemType Directory -Path (Split-Path $full -Parent) -Force
            $null = New-Item -ItemType File -Path $full -Force
        }

        return $Root
    }

    function Invoke-SetupScript {
        # Runs the script in a child powershell.exe with NoProfile, captures
        # combined stdout+stderr and the exit code. Keeps tests hermetic by
        # avoiding in-process dot-sourcing (the script calls `exit` in most
        # top-level branches, which would terminate the Pester host).
        param([Parameter(Mandatory = $true)][string[]]$ScriptArgs)

        $powershell = (Get-Command powershell.exe).Source
        $args       = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:ScriptPath) + $ScriptArgs

        $output = & $powershell @args 2>&1 | Out-String
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output   = $output
        }
    }

    # pom.xml ghidra.version at the time of the test run. Used to construct
    # mismatch scenarios without hard-coding a version that drifts on bumps.
    [xml]$pomXml = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'pom.xml')
    $script:PomGhidraVersion = "$($pomXml.project.properties.'ghidra.version')".Trim()
    if (-not $script:PomGhidraVersion) {
        throw "Could not read ghidra.version from pom.xml"
    }
}

Describe 'Syntax' {
    It 'parses without AST errors' {
        $errors = $null
        $tokens = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptPath, [ref]$tokens, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }
}

Describe '-Help' {
    BeforeAll {
        $script:HelpResult = Invoke-SetupScript -ScriptArgs @('-Help')
    }

    It 'exits 0' {
        $script:HelpResult.ExitCode | Should -Be 0
    }

    It 'prints the Usage banner' {
        $script:HelpResult.Output | Should -Match 'GhidraMCP Setup - Usage'
    }

    It 'documents the Ghidra-lifecycle switches (SkipRestart, AutoOpen, ServerPassword)' {
        $script:HelpResult.Output | Should -Match '-SkipRestart'
        $script:HelpResult.Output | Should -Match '-AutoOpen'
        $script:HelpResult.Output | Should -Match '-ServerPassword'
    }

    It 'does not leak internal function names into Usage (regression for line 86-91 bug)' {
        # Before the fix, Show-Usage spilled Install-PythonRequirementsFile
        # and $InstallDebuggerDeps references into its own output.
        $script:HelpResult.Output | Should -Not -Match 'Install-PythonRequirementsFile'
        $script:HelpResult.Output | Should -Not -Match '\$InstallDebuggerDeps'
    }
}

Describe 'Preflight' {
    It 'exits 1 when GhidraPath is bogus' {
        $bogus = Join-Path $TestDrive 'does-not-exist'
        $result = Invoke-SetupScript -ScriptArgs @('-Preflight', '-GhidraPath', $bogus)
        $result.ExitCode | Should -Be 1
    }

    It 'exits 1 when a required Ghidra JAR is missing from a fixture layout' {
        $fake = Join-Path $TestDrive 'ghidra-missing-decompiler'
        New-FakeGhidraLayout -Root $fake -Version $script:PomGhidraVersion `
            -OmitJars @('Ghidra\Features\Decompiler\lib\Decompiler.jar') | Out-Null
        $result = Invoke-SetupScript -ScriptArgs @('-Preflight', '-GhidraPath', $fake)
        $result.ExitCode | Should -Be 1
        $result.Output   | Should -Match 'Decompiler\.jar'
    }

    It 'exits 0 against a complete fixture Ghidra layout matching pom.xml version' {
        $fake = Join-Path $TestDrive 'ghidra-good'
        New-FakeGhidraLayout -Root $fake -Version $script:PomGhidraVersion | Out-Null
        $result = Invoke-SetupScript -ScriptArgs @('-Preflight', '-GhidraPath', $fake)
        $result.ExitCode | Should -Be 0
        $result.Output   | Should -Match 'Preflight checks passed'
    }
}

Describe 'Version validation' {
    It 'rejects an explicit -GhidraVersion that disagrees with pom.xml' {
        $result = Invoke-SetupScript -ScriptArgs @('-Preflight', '-GhidraVersion', '99.99.99')
        $result.ExitCode | Should -Be 1
        $result.Output   | Should -Match 'Version mismatch'
    }

    It 'rejects a GhidraPath whose version suffix is a different major.minor' {
        # Use a path pattern the script recognizes as versioned
        # (ghidra_X.Y.Z_PUBLIC) but never actually touches the filesystem for.
        $badPath = Join-Path $TestDrive 'ghidra_0.1.0_PUBLIC'
        New-FakeGhidraLayout -Root $badPath -Version '0.1.0' | Out-Null
        $result = Invoke-SetupScript -ScriptArgs @('-Preflight', '-GhidraPath', $badPath)
        $result.ExitCode | Should -Be 1
        $result.Output   | Should -Match 'Version mismatch'
    }
}
