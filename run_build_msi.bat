@echo off
REM Wrapper: initialize VS arm64 env + clang on PATH, then invoke Build-Msi.ps1
set "PATH=C:\Program Files (x86)\Microsoft Visual Studio\Installer;%PATH%"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" arm64 > NUL
if errorlevel 1 (
    echo VCVARS_FAILED
    exit /b 1
)
set "PATH=C:\Program Files\LLVM\bin;%PATH%"
set "PATH=%USERPROFILE%\.dotnet\tools;%PATH%"
set "PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64;%PATH%"
cd /d C:\ABCD\platform\windows\installer
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build-Msi.ps1 -Platform arm64 > C:\ABCD\target\msi_build.log 2>&1
echo MSI_EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
