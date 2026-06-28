@echo off
setlocal enabledelayedexpansion
rem ============================================================================
rem  pawjob build helper.
rem
rem  The two projects must be built at different bitness:
rem    pawjob.dll -> Win32 (x86)  : the cheat module, loaded into csgo.exe
rem    steam.dll    -> x64          : the loader, injected into steam.exe
rem                                  (Steam is 64-bit since Jan 1, 2026)
rem ============================================================================

set "ROOT=%~dp0"
set "ROOT=%ROOT:~0,-1%"

rem --- locate MSBuild (VS 2022, any edition, prefer amd64) -----------------
set "MSBUILD="
call :findmsbuild "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
call :findmsbuild "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe"
call :findmsbuild "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe"
call :findmsbuild "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe"
call :findmsbuild "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe"
call :findmsbuild "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
call :findmsbuild "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
call :findmsbuild "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
call :findmsbuild "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD (
  echo [build] MSBuild.exe for Visual Studio 2022 not found. >&2
  echo [build] Install VS 2022 with the "Desktop development with C++" workload. >&2
  exit /b 1
)

echo [build] MSBuild: %MSBUILD%
echo [build] Root:    %ROOT%
echo.

rem --- steam loader (x64) ---------------------------------------------------
echo === Building steam (Release^|x64) ===
"%MSBUILD%" "%ROOT%\steam\steam.vcxproj" -t:Rebuild -p:Configuration=Release -p:Platform=x64 -p:SolutionDir="%ROOT%\\" -m -nologo -v:minimal
if errorlevel 1 ( echo [build] steam FAILED. >&2 & exit /b 1 )
echo.

rem --- cheat module (Win32 / x86) ------------------------------------------
echo === Building pawjob (Release^|Win32) ===
"%MSBUILD%" "%ROOT%\pawjob\pawjob.vcxproj" -t:Rebuild -p:Configuration=Release -p:Platform=Win32 -p:SolutionDir="%ROOT%\\" -m -nologo -v:minimal
if errorlevel 1 ( echo [build] pawjob FAILED. >&2 & exit /b 1 )
echo.

echo === Build OK ===
echo   loader  (x64, inject into steam.exe): %ROOT%\x64\Release\steam.dll
echo   module  (x86, for csgo.exe):          %ROOT%\Release\pawjob.dll
endlocal
exit /b 0

:findmsbuild
if not defined MSBUILD if exist "%~1" set "MSBUILD=%~1"
goto :eof
