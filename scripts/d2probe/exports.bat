@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" >nul 2>&1
dumpbin /exports C:\Windows\SysWOW64\dsound.dll
