@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cd /d C:\ABCD\platform\windows\native\Tests
cl /EHsc /std:c++17 /Od /Zi /I..\DdsBridgeIPC /I..\DdsAuthBridge /I..\DdsTrayAgent test_hmac_roundtrip.cpp ..\DdsTrayAgent\WebAuthnHelper.cpp ..\DdsAuthBridge\CredentialVault.cpp ..\DdsAuthBridge\FileLog.cpp webauthn.lib bcrypt.lib crypt32.lib advapi32.lib shell32.lib user32.lib gdi32.lib /Fe:test_hmac_roundtrip.exe /link /SUBSYSTEM:CONSOLE
