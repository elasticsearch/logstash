@echo off
setlocal enabledelayedexpansion
setlocal enableextensions
set params='%*'

call "%~dp0setup.bat" || exit /b 1
if errorlevel 1 (
	if not defined nopauseonerror (
		pause
	)
	exit /B %ERRORLEVEL%
)

rem if explicit jvm.options is not found use default location
if "%LS_JVM_OPTIONS_CONFIG%" == "" (
  set LS_JVM_OPTIONS_CONFIG="%LS_HOME%\config\jvm.options"
)

rem extract the options from the JVM options file %LS_JVM_OPTIONS_CONFIG%
rem such options are the lines beginning with '-', thus "findstr /b"
if exist %LS_JVM_OPTIONS_CONFIG% (
  for /F "usebackq delims=" %%a in (`findstr /b \- %LS_JVM_OPTIONS_CONFIG%`) do set options=!options! %%a
  set "LS_JAVA_OPTS=!options! %LS_JAVA_OPTS%"
) else (
  echo "warning: no jvm.options file found"
)
set JAVA_OPTS=%LS_JAVA_OPTS%

%JRUBY_BIN% "%LS_HOME%\lib\bootstrap\rspec.rb" %*
if errorlevel 1 (
  exit /B 1
)

endlocal