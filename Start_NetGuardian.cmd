@echo off
cd /d "%~dp0"
python netguardian.py --gui
if errorlevel 1 pause
