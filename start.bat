@echo off
REM Start the Apexion client proxy (Windows)
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (echo Run: python setup.py   first & exit /b 1)
.venv\Scripts\python.exe apexion_addon.py
