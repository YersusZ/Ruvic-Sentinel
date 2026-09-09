@echo off
REM Robin Client Monitor - servicio Windows (NSSM + sc failure)
REM Uso:
REM   install-service-windows.bat [APP_DIR]
REM Env (enrollment RF-CORE-01/02):
REM   ENROLLTOKEN / ENROLLSERVER / ENROLLTENANT / ENROLLNAME
REM   ENROLLINSECURE=1  (solo lab)
setlocal EnableExtensions

set "SERVICE_NAME=robin-client-monitor"

REM APP_DIR sin barra final. SET sin comillas acepta el backslash de MSI.
REM No concatenar un punto tras expansiones de parametro (cmd aborta).
set ARG1=%~1
set _dp=%~dp0
set APP_DIR=%_dp:~0,-1%
if defined ARG1 set APP_DIR=%ARG1%
if "%APP_DIR:~-1%x"=="\x" set APP_DIR=%APP_DIR:~0,-1%

set "BIN=%APP_DIR%\robin-client-monitor.exe"
set "NSSM="
if exist "%APP_DIR%\nssm.exe" set "NSSM=%APP_DIR%\nssm.exe"
if not defined NSSM if exist "%APP_DIR%\nssm\nssm.exe" set "NSSM=%APP_DIR%\nssm\nssm.exe"
if not defined NSSM if exist "%~dp0nssm.exe" set "NSSM=%~dp0nssm.exe"
if not defined NSSM if exist "%~dp0nssm\nssm.exe" set "NSSM=%~dp0nssm\nssm.exe"

if not defined NSSM (
  echo ERROR: no encuentro nssm.exe
  echo Colocalo en %APP_DIR%\nssm\ o junto a este .bat.
  echo Descarga: https://nssm.cc/download
  exit /b 1
)

if not exist "%BIN%" (
  echo ERROR: no existe %BIN%
  echo Copia robin-client-monitor.exe y config_client.json a %APP_DIR%
  exit /b 1
)

net session >nul 2>&1
if errorlevel 1 (
  echo ERROR: ejecuta este script como Administrador.
  exit /b 1
)

if not defined ENROLLTOKEN goto :svc_install
echo Enrollment RF-CORE-01/02...
set "ENROLL_ARGS=--enroll %ENROLLTOKEN%"
if defined ENROLLSERVER set "ENROLL_ARGS=%ENROLL_ARGS% --enroll-server %ENROLLSERVER%"
if defined ENROLLTENANT set "ENROLL_ARGS=%ENROLL_ARGS% --enroll-tenant %ENROLLTENANT%"
if defined ENROLLNAME set "ENROLL_ARGS=%ENROLL_ARGS% --enroll-name %ENROLLNAME%"
if "%ENROLLINSECURE%"=="1" set "ENROLL_ARGS=%ENROLL_ARGS% --enroll-insecure"
pushd "%APP_DIR%"
"%BIN%" %ENROLL_ARGS%
if errorlevel 1 echo AVISO: enrollment fallo; se usara config_client.json.
popd

:svc_install
REM No pasar flags del agente a "nssm install": NSSM 2.24 puede crashear
REM o interpretar "-1" como opcion propia. Usar AppParameters.
sc.exe query "%SERVICE_NAME%" >nul 2>&1
if errorlevel 1 (
  "%NSSM%" install "%SERVICE_NAME%" "%BIN%"
  if errorlevel 1 (
    echo ERROR: nssm install fallo.
    exit /b 1
  )
) else (
  echo El servicio ya existe; se actualiza la configuracion.
)

"%NSSM%" set "%SERVICE_NAME%" Application "%BIN%"
"%NSSM%" set "%SERVICE_NAME%" AppParameters "--max-retries -1 --retry-delay 2"
"%NSSM%" set "%SERVICE_NAME%" AppDirectory "%APP_DIR%"
"%NSSM%" set "%SERVICE_NAME%" AppExit Default Restart
"%NSSM%" set "%SERVICE_NAME%" AppRestartDelay 3000
"%NSSM%" set "%SERVICE_NAME%" Start SERVICE_AUTO_START
"%NSSM%" set "%SERVICE_NAME%" DisplayName "Robin Client Monitor"

"%NSSM%" start "%SERVICE_NAME%"

REM Recuperacion SCM (ademas del restart de NSSM): 3 reintentos, reset 24h.
sc.exe failure "%SERVICE_NAME%" reset= 86400 actions= restart/3000/restart/10000/restart/30000 >nul 2>&1
sc.exe failureflag "%SERVICE_NAME%" 1 >nul 2>&1

echo(
echo Listo. Estado:
"%NSSM%" status "%SERVICE_NAME%"

endlocal
exit /b 0
