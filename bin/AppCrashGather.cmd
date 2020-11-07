@echo off
set SplunkApp=TA-AppCrashGather
powershell.exe -file "%SPLUNK_HOME%\etc\apps\%SplunkApp%\bin\AppCrashGather.ps1'"