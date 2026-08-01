@echo off
setlocal EnableExtensions
set "app=%~dp0system\huawei-revive.pyz"
set "library=%~dp0firmware"
set "python_runtime=C:\Users\ATHENA 2.0\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if not exist "%python_runtime%" set "python_runtime=python"
echo Add a firmware model
echo.
set /p "folder=Folder name: "
set /p "name=Model name: "
set /p "manufacturer=Manufacturer: "
set /p "variant=Model code (optional): "
if "%variant%"=="" goto no_variant
"%python_runtime%" "%app%" firmware-add-model --library-root "%library%" --folder "%folder%" --name "%name%" --manufacturer "%manufacturer%" --variant "%variant%"
goto done
:no_variant
"%python_runtime%" "%app%" firmware-add-model --library-root "%library%" --folder "%folder%" --name "%name%" --manufacturer "%manufacturer%"
:done
echo.
pause
