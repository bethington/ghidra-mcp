@echo off
REM Batch apply UnifyOrdinalNames script to all Storm.dll versions in Ghidra project

setlocal enabledelayedexpansion

REM Configuration
set GHIDRA_PATH=C:\Users\benam\tools\ghidra_11.4.1_PUBLIC
set SCRIPT_PATH=C:\Users\benam\source\mcp\ghidra-mcp\ghidra_scripts\UnifyOrdinalNames_ProjectFolder.java
set PROJECT_PATH=C:\Users\benam\ghidra_projects\Diablo2

echo ========================================
echo BATCH UNIFY ORDINAL NAMES
echo ========================================
echo Ghidra Path: %GHIDRA_PATH%
echo Script: %SCRIPT_PATH%
echo Project: %PROJECT_PATH%
echo.

REM Find all Storm.dll versions in project
cd /d "%PROJECT_PATH%"

echo Scanning for Storm.dll versions...
for /r . %%F in (Storm.dll) do (
    set "FILE=%%F"
    set "FILE=!FILE:%PROJECT_PATH%=!"
    echo Found: !FILE!
)
echo.

REM Use analyzeHeadless to process each version
echo Processing each version with UnifyOrdinalNames script...
echo.

REM This would be called for each Storm.dll found, but Ghidra's analyzeHeadless
REM would need to be run in headless mode, which requires additional setup

echo.
echo Note: To apply this script to all versions:
echo 1. Open each Storm.dll version in Ghidra manually
echo 2. Run UnifyOrdinalNames_ProjectFolder.java from the Script Manager
echo 3. Or use Ghidra's analyzeHeadless in a loop for automation
echo.
echo Example for one file:
echo %GHIDRA_PATH%\support\analyzeHeadless "%PROJECT_PATH%" Storm_Project ^
echo   -scriptPath "%~dp0" ^
echo   -preScript UnifyOrdinalNames_ProjectFolder.java
echo.

pause
