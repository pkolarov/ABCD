@echo off
REM build_tests.bat
REM Build DDS native test suite using Visual Studio 2022 Build Tools.
REM Produces Tests\build\dds_native_tests.exe (x64 Debug).
REM
REM Usage:
REM   cd platform\windows\native\Tests
REM   build_tests.bat
REM

setlocal enabledelayedexpansion

REM --- Locate VS 2022 build tools ---
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found. Install Visual Studio 2022 Build Tools.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VS_INSTALL=%%i"
)

if not defined VS_INSTALL (
    echo ERROR: Visual Studio 2022 installation not found.
    exit /b 1
)

REM --- Initialize x64 environment ---
call "%VS_INSTALL%\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (
    echo ERROR: vcvarsall.bat failed.
    exit /b 1
)

REM --- Create output directory ---
set "OUT_DIR=%~dp0build"
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

REM --- Compile ---
echo.
echo === Building DDS Native Tests (x64 Debug) ===
echo.

cl.exe /nologo ^
    /std:c++17 ^
    /EHsc ^
    /W3 ^
    /Zi ^
    /Od ^
    /MDd ^
    /D_DEBUG ^
    /DWIN32 ^
    /D_WINDOWS ^
    /DUNICODE ^
    /D_UNICODE ^
    /I"%~dp0..\DdsBridgeIPC" ^
    /I"%~dp0..\DdsAuthBridge" ^
    /I"%~dp0..\Helpers" ^
    /Fe:"%OUT_DIR%\dds_native_tests.exe" ^
    /Fd:"%OUT_DIR%\dds_native_tests.pdb" ^
    /Fo:"%OUT_DIR%\\" ^
    "%~dp0test_main.cpp" ^
    "%~dp0..\DdsBridgeIPC\ipc_protocol.cpp"

if errorlevel 1 (
    echo.
    echo ERROR: Compilation failed.
    exit /b 1
)

echo.
echo === Build succeeded: %OUT_DIR%\dds_native_tests.exe ===
echo.

endlocal
exit /b 0
