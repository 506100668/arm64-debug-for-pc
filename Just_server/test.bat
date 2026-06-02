@echo off
setlocal EnableExtensions

set "REMOTE_BIN=/data/local/tmp/test"
set "RUN_TIMEOUT=%~1"
if "%RUN_TIMEOUT%"=="" set "RUN_TIMEOUT=0"

where adb >nul 2>nul
if errorlevel 1 (
  echo ERROR: adb not found in PATH.
  exit /b 1
)

adb get-state 1>nul 2>nul
if errorlevel 1 (
  echo ERROR: no adb device connected.
  exit /b 1
)

adb shell "if [ ! -f %REMOTE_BIN% ]; then exit 127; fi; chmod 755 %REMOTE_BIN%" 1>nul 2>nul
if errorlevel 1 (
  echo ERROR: %REMOTE_BIN% not found or chmod failed.
  exit /b 1
)

if "%RUN_TIMEOUT%"=="0" (
  echo [INFO] running %REMOTE_BIN% with realtime TTY output
  adb shell -tt "%REMOTE_BIN%"
) else (
  echo [INFO] running %REMOTE_BIN% with realtime TTY output, timeout %RUN_TIMEOUT%s
  adb shell -tt "timeout -s TERM %RUN_TIMEOUT%s %REMOTE_BIN%"
)

set "RC=%ERRORLEVEL%"

if "%RC%"=="0" exit /b 0

if "%RC%"=="124" (
  echo WARN: process timed out after %RUN_TIMEOUT%s.
)

echo ERROR: remote program exited with code %RC%
exit /b %RC%
