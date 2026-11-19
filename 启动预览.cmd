@echo off
setlocal
cd /d "%~dp0"
if not exist node_modules (
  echo Run npm ci in this project directory first.
  pause
  exit /b 1
)
call npm run dev
