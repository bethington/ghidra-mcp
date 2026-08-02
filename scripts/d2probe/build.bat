@echo off
REM 32-bit to match Game.exe.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" >nul 2>&1
cd /d C:\tmp\d2probe
cl /nologo /EHsc /W3 /Fe:probe.exe probe.cpp /link dsound.lib ole32.lib user32.lib gdi32.lib advapi32.lib
echo BUILD_EXIT=%ERRORLEVEL%
