@echo off
setlocal enabledelayedexpansion
setlocal enableextensions
set params='%*'


if "%1" == "-V" goto version
if "%1" == "--version" goto version

call "%~dp0setup.bat" || exit /b 1
if errorlevel 1 (
	if not defined nopauseonerror (
		pause
	)
	exit /B %ERRORLEVEL%
)

"%JAVACMD%" %JAVA_OPTS% -cp "%CLASSPATH%" org.logstash.Logstash %*

goto :end

:version
set LOGSTASH_VERSION_FILE1="%LS_HOME%\logstash-core\versions-gem-copy.yml"
set LOGSTASH_VERSION_FILE2="%LS_HOME%\versions.yml"

set "LOGSTASH_VERSION=Version not detected"
if exist !LOGSTASH_VERSION_FILE1! (
	rem this file is present in zip, deb and rpm artifacts and after bundle install
	rem but might not be for a git checkout type install
	for /F "tokens=1,2 delims=: " %%a in ('type !LOGSTASH_VERSION_FILE1!') do (
		if "%%a"=="logstash" set LOGSTASH_VERSION=%%b
	)
) else (
	if exist !LOGSTASH_VERSION_FILE2! (
		rem this file is present for a git checkout type install
		rem but its not in zip, deb and rpm artifacts (and in integration tests)
		for /F "tokens=1,2 delims=: " %%a in ('type !LOGSTASH_VERSION_FILE2!') do (
			if "%%a"=="logstash" set LOGSTASH_VERSION=%%b
		)
	)
)
echo logstash !LOGSTASH_VERSION!
goto :end

:end
endlocal
exit /B %ERRORLEVEL%
