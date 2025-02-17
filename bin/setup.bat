@echo off

set SCRIPT=%0

rem ### 1: determine logstash home

rem  to do this, we strip from the path until we
rem find bin, and then strip bin (there is an assumption here that there is no
rem nested directory under bin also named bin)

for %%I in (%SCRIPT%) do set LS_HOME=%%~dpI

:ls_home_loop
for %%I in ("%LS_HOME:~1,-1%") do set DIRNAME=%%~nxI
if not "%DIRNAME%" == "bin" (
  for %%I in ("%LS_HOME%..") do set LS_HOME=%%~dpfI
  goto ls_home_loop
)
for %%I in ("%LS_HOME%..") do set LS_HOME=%%~dpfI

rem ### 2: set java

if defined LS_JAVA_HOME (
  set JAVACMD=%LS_JAVA_HOME%\bin\java.exe
  echo Using LS_JAVA_HOME defined java: %LS_JAVA_HOME%
  if exist "%LS_HOME%\jdk" (
    if not exist "%LS_HOME%\JDK_VERSION" (
      echo "File %LS_HOME%\JDK_VERSION doesn't exists"
      exit /b 1
    )
    set /p BUNDLED_JDK_VERSION=<"%LS_HOME%\JDK_VERSION"
    echo "WARNING: Logstash comes bundled with the recommended JDK(%BUNDLED_JDK_VERSION%), but is overridden by the version defined in LS_JAVA_HOME. Consider clearing LS_JAVA_HOME to use the bundled JDK."
  )
) else (
  if exist "%LS_HOME%\jdk" (
    set JAVACMD=%LS_HOME%\jdk\bin\java.exe
    echo "Using bundled JDK: !JAVACMD!"
  ) else (
    for %%I in (java.exe) do set JAVACMD="%%~$PATH:I"
    echo "Using system java: !JAVACMD!"
  )
)

if not exist "%JAVACMD%" (
  echo could not find java; set LS_JAVA_HOME or ensure java is in PATH 1>&2
  exit /b 1
)

rem do not let JAVA_TOOL_OPTIONS slip in (as the JVM does by default)
if defined JAVA_TOOL_OPTIONS (
  echo "warning: ignoring JAVA_TOOL_OPTIONS=$JAVA_TOOL_OPTIONS"
  set JAVA_TOOL_OPTIONS=
)

rem JAVA_OPTS is not a built-in JVM mechanism but some people think it is so we
rem warn them that we are not observing the value of %JAVA_OPTS%
if defined JAVA_OPTS (
  echo|set /p="warning: ignoring JAVA_OPTS=%JAVA_OPTS%; "
  echo pass JVM parameters via LS_JAVA_OPTS
)

rem ### 3: set jruby

set JRUBY_BIN="%LS_HOME%\vendor\jruby\bin\jruby"
if not exist %JRUBY_BIN% (
  echo "could not find jruby in %LS_HOME%\vendor\jruby" 1>&2
  exit /b 1
)
rem iterate over the command line args and look for the argument
rem after --path.settings to see if the jvm.options file is in
rem that path and set LS_JVM_OPTS accordingly
:loop
for /F "usebackq tokens=1-2* delims= " %%A in (!params!) do (
    set current=%%A
    set next=%%B
    set params='%%B %%C'

    if "!current!" == "--path.settings" (
    	if exist !next!\jvm.options (
    	  set "LS_JVM_OPTS=!next!\jvm.options"
    	)
    )

    if not "x!params!" == "x" (
		goto loop
	)
)

rem setup CLASSPATH for Java process
set "JRUBY_HOME=%LS_HOME%\vendor\jruby"

set "CLASSPATH=%JRUBY_HOME%\lib\jruby.jar"
for %%i in ("%LS_HOME%\logstash-core\lib\jars\*.jar") do (
	call :concat "%%i"
)

@setlocal
for /F "usebackq delims=" %%a in (`CALL "%JAVACMD%" -cp "!CLASSPATH!" "org.logstash.launchers.JvmOptionsParser" "!LS_HOME!" "!LS_JVM_OPTS!" ^|^| echo jvm_options_parser_failed`) do set LS_JAVA_OPTS=%%a
@endlocal & set "MAYBE_JVM_OPTIONS_PARSER_FAILED=%LS_JAVA_OPTS%" & set LS_JAVA_OPTS=%LS_JAVA_OPTS%

if "%MAYBE_JVM_OPTIONS_PARSER_FAILED%" == "jvm_options_parser_failed" (
  echo "error: jvm options parser failed; exiting"
  exit /b 1
)
set JAVA_OPTS=%LS_JAVA_OPTS%

:concat
IF not defined CLASSPATH (
  set CLASSPATH=%~1
) ELSE (
  set CLASSPATH=%CLASSPATH%;%~1
)
goto :eof

set RUBYLIB=%LS_HOME%\lib