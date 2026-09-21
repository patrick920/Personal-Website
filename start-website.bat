@echo off
REM ===========================================================================
REM  start-website.bat
REM  Double-click this file to run the website on your own computer.
REM
REM  It starts the local server and opens the site in your default browser.
REM  Close the black console window (or press Ctrl+C in it) to stop serving.
REM ===========================================================================

REM Run from the folder this script lives in, no matter where it was launched.
cd /d "%~dp0"

REM Check Node.js is installed before trying to use it.
where node >nul 2>nul
if errorlevel 1 (
    echo.
    echo   Node.js was not found on this computer.
    echo   Install it from https://nodejs.org/ then run this file again.
    echo.
    pause
    exit /b 1
)

REM Open the browser after a short pause, so the server is listening first.
start "" /b cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:3000"

echo.
echo   Starting the local website server...
echo   Press Ctrl+C in this window to stop it.
echo.

node server.js

REM Keep the window open if the server exits with an error.
if errorlevel 1 pause
