@echo off
setlocal EnableExtensions
set "app=%~dp0system\huawei-revive.pyz"
set "package=%~dp0firmware\p 30 pro\VOGUE-L29D 10.0.0.186(C185E8R5P1)_Firmware_EMUI10.0.0_05016EUP"
set "proof=%~dp0plans\p30-pro-package-proof.json"
set "python_runtime=C:\Users\ATHENA 2.0\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if not exist "%python_runtime%" set "python_runtime=python"
echo This reads the complete package and can take several minutes.
"%python_runtime%" "%app%" huawei-package-verify --package-root "%package%" --output "%proof%"
if errorlevel 1 goto failed
call "%~dp0BUILD P30 WORKFLOW.bat"
exit /b 0
:failed
echo.
echo P30 Pro package verification failed.
echo.
pause
