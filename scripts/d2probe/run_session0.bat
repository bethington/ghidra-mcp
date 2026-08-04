@echo off
schtasks /create /tn D2Probe0 /tr "C:\tmp\d2probe\probe.exe" /sc once /st 23:59 /ru SYSTEM /rl HIGHEST /f
echo CREATE_EXIT=%ERRORLEVEL%
schtasks /run /tn D2Probe0
echo RUN_EXIT=%ERRORLEVEL%
