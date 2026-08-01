@echo off
setlocal EnableExtensions
set "app=%~dp0system\huawei-revive.pyz"
set "model=%~dp0firmware\p 30 pro"
set "output=%~dp0plans\p30-pro-workflow.json"
set "python_runtime=C:\Users\ATHENA 2.0\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if not exist "%python_runtime%" set "python_runtime=python"
"%python_runtime%" "%app%" revive-workflow p30-pro --model-root "%model%" --output "%output%"
if errorlevel 1 echo P30 Pro workflow preparation failed.
echo.
pause
