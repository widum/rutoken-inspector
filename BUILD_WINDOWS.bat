@echo off
setlocal
cd /d "%~dp0"
where go >nul 2>&1 || (echo Install Go 1.23 or newer. & exit /b 1)
if not exist assets mkdir assets
set GOOS=windows
set CGO_ENABLED=0
set GOARCH=386
go build -trimpath -ldflags="-H=windowsgui -s -w" -o assets\RutokenInspector_x86_worker.exe .
if errorlevel 1 exit /b 1
set GOARCH=amd64
go build -trimpath -ldflags="-H=windowsgui -s -w" -o RutokenInspector3_v3.4.1_Win11.exe .
if errorlevel 1 exit /b 1
echo Build completed.
