@echo off
rem Build hvctl.exe (x64). Run from any shell; sets up the VS2026 toolchain.
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d "%~dp0"
cl /nologo /EHsc /W4 /O2 /Fe:hvctl.exe hvctl.cpp snapshot.cpp
endlocal
