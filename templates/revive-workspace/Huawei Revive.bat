@echo off
setlocal EnableExtensions
title Huawei Revive
:menu
cls
echo ========================================
echo             Huawei Revive
echo ========================================
echo  1. List available firmware
echo  2. Add a new model
echo  0. Exit
echo ========================================
set /p "choice=Select: "
if "%choice%"=="1" call "%~dp0LIST FIRMWARE.bat"
if "%choice%"=="2" call "%~dp0ADD MODEL.bat"
if "%choice%"=="0" exit /b 0
goto menu
