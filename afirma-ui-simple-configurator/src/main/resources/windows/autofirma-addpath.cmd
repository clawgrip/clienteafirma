@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ===========================
REM Validar parametro
REM ===========================
if "%~1"=="" (
    echo Error: Debe pasar la ruta como parametro
    exit /b 1
)

set "TARGET=%~1"

REM Normalizar TARGET (sin barra final)
if "%TARGET:~-1%"=="\" set "TARGET=%TARGET:~0,-1%"

REM ===========================
REM Leer PATH de sistema REAL
REM ===========================
for /f "tokens=2,*" %%A in (
    'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^>nul'
) do set "SYSPATH=%%B"

if not defined SYSPATH (
    echo Error: No se pudo leer el PATH del sistema
    exit /b 1
)

REM ===========================
REM Comprobar si ya existe
REM ===========================
echo ;!SYSPATH!; | findstr /I /C:";!TARGET!;" >nul
if not errorlevel 1 (
    echo La ruta ya existe en el PATH del sistema
    exit /b 0
)

REM ===========================
REM Construir nuevo PATH
REM ===========================
set "NEWPATH=!SYSPATH!"

REM Asegurar punto y coma final
if not "!NEWPATH:~-1!"==";" set "NEWPATH=!NEWPATH!;"

set "NEWPATH=!NEWPATH!!TARGET!"

REM ===========================
REM Guardar en el registro
REM ===========================
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" ^
 /v PATH /t REG_EXPAND_SZ /d "!NEWPATH!" /f >nul 2>&1

if errorlevel 1 (
    echo Error al anadir la ruta al PATH
    exit /b 1
)

echo Ruta anadida correctamente al PATH del sistema
exit /b 0
