@echo off
setlocal EnableExtensions

set "REMOTE_SRC=/sdcard/Download/test"
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

adb shell "if [ ! -f %REMOTE_SRC% ]; then exit 127; fi" 1>nul 2>nul
if errorlevel 1 (
  echo ERROR: %REMOTE_SRC% not found.
  exit /b 1
)

adb shell "su -c 'rm -f %REMOTE_BIN%; cp %REMOTE_SRC% %REMOTE_BIN% && chmod 755 %REMOTE_BIN%'" 1>nul 2>nul
if errorlevel 1 (
  echo ERROR: install %REMOTE_SRC% to %REMOTE_BIN% failed.
  exit /b 1
)

if "%RUN_TIMEOUT%"=="0" (
  echo [INFO] running %REMOTE_BIN% with realtime TTY output
  adb shell -tt su -c "%REMOTE_BIN%"
) else (
  echo [INFO] running %REMOTE_BIN% with realtime TTY output, timeout %RUN_TIMEOUT%s
  adb shell -tt su -c "timeout -s TERM %RUN_TIMEOUT%s %REMOTE_BIN%"
)

set "RC=%ERRORLEVEL%"

if "%RC%"=="0" exit /b 0

if "%RC%"=="124" (
  echo WARN: process timed out after %RUN_TIMEOUT%s.
)

echo ERROR: remote program exited with code %RC%
exit /b %RC%
