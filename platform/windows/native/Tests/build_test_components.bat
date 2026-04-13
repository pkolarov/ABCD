@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cd /d C:\ABCD\platform\windows\native\Tests
cl /EHsc /std:c++17 /Od /Zi /DUNICODE /D_UNICODE ^
   /I..\DdsBridgeIPC /I..\DdsAuthBridge ^
   test_components.cpp ^
   ..\DdsAuthBridge\CredentialVault.cpp ^
   ..\DdsAuthBridge\FileLog.cpp ^
   bcrypt.lib crypt32.lib advapi32.lib shell32.lib secur32.lib ole32.lib netapi32.lib ^
   /Fe:test_components.exe /link /SUBSYSTEM:CONSOLE
