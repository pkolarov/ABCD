@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" arm64 > NUL
if errorlevel 1 (
    echo VCVARS_FAILED
    exit /b 1
)
set "PATH=C:\Program Files\LLVM\bin;%PATH%"
cd /d C:\ABCD
cargo test --workspace --no-fail-fast > C:\ABCD\target\rust_test3.log 2>&1
echo CARGO_EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
