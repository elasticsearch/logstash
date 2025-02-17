@echo off
setlocal enabledelayedexpansion
setlocal enableextensions

cd /d "%~dp0.."
for /f %%i in ('cd') do set RESULT=%%i

"%JAVACMD%" -cp "!RESULT!\tools\benchmark-cli\build\libs\benchmark-cli.jar;*" ^
  org.logstash.benchmark.cli.Main %*

endlocal
