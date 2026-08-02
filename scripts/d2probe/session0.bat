@echo off
REM Run the probe as SYSTEM, which lands it in Session 0 -- no interactive
REM desktop and no per-session audio endpoint. That is the closest local
REM approximation of a headless Windows container.
del /q C:\tmp\d2probe\probe_result.txt 2>nul
schtasks /create /tn D2Probe0 /tr "C:\tmp\d2probe\probe.exe" /sc once /st 23:59 /ru SYSTEM /rl HIGHEST /f
schtasks /run /tn D2Probe0
REM Give it a moment; the probe itself sleeps ~120ms and exits.
ping -n 6 127.0.0.1 >nul
schtasks /delete /tn D2Probe0 /f
copy /y C:\tmp\d2probe\probe_result.txt C:\tmp\d2probe\session0_result.txt >nul
echo DONE > C:\tmp\d2probe\session0_done.txt
