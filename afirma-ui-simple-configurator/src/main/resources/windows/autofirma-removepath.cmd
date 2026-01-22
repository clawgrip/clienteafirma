@echo off
setlocal EnableExtensions DisableDelayedExpansion

if "%~1"=="" (
    echo Error: falta la ruta a eliminar
    exit /b 1
)

REM Normalizar ruta objetivo
set "TARGET=%~1"
if "%TARGET:~-1%"=="\" set "TARGET=%TARGET:~0,-1%"

REM Leer PATH del registro (sistema)
for /f "tokens=2,*" %%A in ('
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path
') do set "SYSPATH=%%B"

REM Construir PATH nuevo de forma segura
set "NEWPATH="
set "REST=%SYSPATH%"

:loop
if not defined REST goto done

for /f "delims=;" %%P in ("%REST%") do (
    set "ITEM=%%P"
)

call set "REST=%%REST:*;=%%"

if "%ITEM:~-1%"=="\" set "ITEM=%ITEM:~0,-1%"

if /I not "%ITEM%"=="%TARGET%" (
    if defined NEWPATH (
        set "NEWPATH=%NEWPATH%;%ITEM%"
    ) else (
        set "NEWPATH=%ITEM%"
    )
)

goto loop

:done

REM Guardar PATH reconstruido
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" ^
 /v Path /t REG_EXPAND_SZ /d "%NEWPATH%" /f >nul

echo Ruta eliminada correctamente del PATH
exit /b 0
