@echo off
setlocal

:: Copy Ghidra JAR files to project lib directory
echo Copying Ghidra JAR files to project lib directory...

:: Create lib directory if it doesn't exist
if not exist "lib" mkdir lib

:: Set source directory - use parameter if provided, otherwise check .env, then prompt
if "%~1"=="" (
    :: Try to read GHIDRA_PATH from .env file
    if exist ".env" (
        for /f "tokens=1,* delims==" %%a in ('findstr /r "^GHIDRA_PATH=" .env') do set GHIDRA_DIR=%%b
    )
    if not defined GHIDRA_DIR (
        echo ERROR: No Ghidra path specified.
        echo.
        echo Usage: copy-ghidra-libs.bat "C:\path\to\ghidra_12.0.2_PUBLIC"
        echo    Or: Set GHIDRA_PATH in .env file ^(copy from .env.template^)
        exit /b 1
    )
    echo Using GHIDRA_PATH from .env: !GHIDRA_DIR!
) else (
    set GHIDRA_DIR=%~1
    echo Using provided Ghidra directory: !GHIDRA_DIR!
)

:: Enable delayed expansion for variables
setlocal enabledelayedexpansion

:: Copy Framework JAR files
echo Copying Base.jar...
copy "%GHIDRA_DIR%\Ghidra\Features\Base\lib\Base.jar" "lib\" /Y

echo Copying Decompiler.jar...
copy "%GHIDRA_DIR%\Ghidra\Features\Decompiler\lib\Decompiler.jar" "lib\" /Y

echo Copying Docking.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\Docking\lib\Docking.jar" "lib\" /Y

echo Copying Generic.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\Generic\lib\Generic.jar" "lib\" /Y

echo Copying Project.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\Project\lib\Project.jar" "lib\" /Y

echo Copying SoftwareModeling.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\SoftwareModeling\lib\SoftwareModeling.jar" "lib\" /Y

echo Copying Utility.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\Utility\lib\Utility.jar" "lib\" /Y

echo Copying Gui.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\Gui\lib\Gui.jar" "lib\" /Y

echo Copying FileSystem.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\FileSystem\lib\FileSystem.jar" "lib\" /Y

echo Copying Graph.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\Graph\lib\Graph.jar" "lib\" /Y

echo Copying DB.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\DB\lib\DB.jar" "lib\" /Y

echo Copying Emulation.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\Emulation\lib\Emulation.jar" "lib\" /Y

:: Copy Feature JAR files
echo Copying PDB.jar...
copy "%GHIDRA_DIR%\Ghidra\Features\PDB\lib\PDB.jar" "lib\" /Y

echo Copying FunctionID.jar...
copy "%GHIDRA_DIR%\Ghidra\Features\FunctionID\lib\FunctionID.jar" "lib\" /Y

echo.
echo All Ghidra JAR files have been copied successfully!
echo.
