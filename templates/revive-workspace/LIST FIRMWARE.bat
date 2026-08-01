@echo off
setlocal EnableExtensions
set "app=%~dp0system\huawei-revive.pyz"
set "library=%~dp0firmware"
set "catalog=%library%\available-firmware.json"
set "python_runtime=C:\Users\ATHENA 2.0\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if exist "%python_runtime%" goto run
set "python_runtime=python"
:run
"%python_runtime%" "%app%" firmware-list --library-root "%library%" --catalog-output "%catalog%"
if errorlevel 1 echo Firmware scan failed.
echo.
pause
