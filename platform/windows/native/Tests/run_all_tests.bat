@echo off
REM run_all_tests.bat
REM Run the DDS native test suite.
REM
REM Usage:
REM   cd platform\windows\native\Tests
REM   run_all_tests.bat
REM

setlocal

set "TEST_EXE=%~dp0build\dds_native_tests.exe"

if not exist "%TEST_EXE%" (
    echo ERROR: Test executable not found at %TEST_EXE%
    echo        Run build_tests.bat first.
    exit /b 1
)

echo.
echo === Running DDS Native Tests ===
echo.

"%TEST_EXE%"
set "RESULT=%ERRORLEVEL%"

if %RESULT% equ 0 (
    echo All tests passed.
) else (
    echo Some tests FAILED [exit code %RESULT%].
)

endlocal
exit /b %RESULT%
