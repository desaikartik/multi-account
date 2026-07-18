@echo off
REM Managed Switcher - start the backend against the LOCAL MongoDB (127.0.0.1:27017).
REM Reads backend\.env (MONGODB_URI, MAILER=console, keys, PORT=8787).
REM Requires MongoDB running locally (the "MongoDB Server (MongoDB)" Windows service).
cd /d "%~dp0"
echo Starting Managed Switcher backend on http://127.0.0.1:8787  (repo=mongo, console mailer)
echo Admin console: http://127.0.0.1:8787/console
echo Press Ctrl+C to stop.
node server.js
