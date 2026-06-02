@echo off
setlocal EnableExtensions

set "SCRIPT_DIR=%~dp0"
set "SRC=%SCRIPT_DIR%server.cpp"
set "OUT=%SCRIPT_DIR%Just_server_arm64"

if not exist "%SRC%" (
  echo ERROR: missing server.cpp
  exit /b 1
)

set "CLANG="
if not "%ANDROID_NDK_HOME%"=="" (
  if exist "%ANDROID_NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android23-clang++.cmd" set "CLANG=%ANDROID_NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android23-clang++.cmd"
  if "%CLANG%"=="" if exist "%ANDROID_NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android21-clang++.cmd" set "CLANG=%ANDROID_NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android21-clang++.cmd"
)
if "%CLANG%"=="" if exist "%USERPROFILE%\AppData\Local\Android\Sdk\ndk\23.1.7779620\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android23-clang++.cmd" set "CLANG=%USERPROFILE%\AppData\Local\Android\Sdk\ndk\23.1.7779620\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android23-clang++.cmd"
if "%CLANG%"=="" if exist "%USERPROFILE%\AppData\Local\Android\Sdk\ndk\21.1.6352462\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android21-clang++.cmd" set "CLANG=%USERPROFILE%\AppData\Local\Android\Sdk\ndk\21.1.6352462\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android21-clang++.cmd"

if "%CLANG%"=="" (
  echo ERROR: clang not found. Please set ANDROID_NDK_HOME.
  exit /b 1
)

echo Using clang: "%CLANG%"
echo Building "%SRC%" ^> "%OUT%"
call "%CLANG%" "%SRC%" -o "%OUT%" -static-libstdc++ -llog
if errorlevel 1 (
  echo ERROR: build failed
  exit /b 1
)

if not exist "%OUT%" (
  echo ERROR: output not generated
  exit /b 1
)

echo OK: "%OUT%"
exit /b 0
