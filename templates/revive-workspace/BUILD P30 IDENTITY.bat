@echo off
setlocal EnableExtensions
set "app=%~dp0system\huawei-revive.pyz"
set "model=%~dp0firmware\p 30 pro"
set "board=%model%\VOGUE-AL00A-BD 1.0.0.82_Board Software_general_9.1.0_r1_EMUI9.1.0_05022MXS\fastbootimage\oeminfo.mbn"
set "metadata=%model%\VOGUE-L29D 10.0.0.186(C185E8R5P1)_Firmware_EMUI10.0.0_05016EUP\revive-extracted\metadata"
set "output=%model%\VOG-L29C185.bin"
set "manifest=%model%\VOG-L29C185.bin.manifest.json"
set "python_runtime=C:\Users\ATHENA 2.0\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if not exist "%python_runtime%" set "python_runtime=python"
if exist "%output%" goto verify
"%python_runtime%" "%app%" huawei-oeminfo-build --template "%board%" --base-version "%metadata%\BASE_VER.mbn" --cust-version "%metadata%\CUST_VER.mbn" --preload-version "%metadata%\PRELOAD_VER.mbn" --output "%output%" --manifest "%manifest%"
if errorlevel 1 goto failed
:verify
"%python_runtime%" "%app%" revive-workflow p30-pro --model-root "%model%" --output "%~dp0plans\p30-pro-workflow.json"
if errorlevel 1 goto failed
echo.
echo P30 Pro identity file and workflow verified. No phone command was run.
goto done
:failed
echo.
echo P30 Pro identity preparation failed.
:done
echo.
pause
