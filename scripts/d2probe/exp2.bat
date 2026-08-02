@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" >nul 2>&1
echo ##### BUILT #####
dumpbin /exports C:\tmp\d2fr\build\Release\SGD2FreeRes.dll
echo ##### SHIPPED #####
dumpbin /exports C:\Diablo2\ProjectD2\SGD2FreeRes.dll
echo ##### BUILT imports #####
dumpbin /imports C:\tmp\d2fr\build\Release\SGD2FreeRes.dll
