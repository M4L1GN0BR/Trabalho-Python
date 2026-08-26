@echo off
rem Atalho: abre o dashboard com o relatorio real do DefectDojo carregado.
rem Nao roda scan (usa o relatorio ja existente em data\defectdojo-scan).
cd /d "%~dp0"
call .venv\Scripts\activate
python run_defectdojo.py
pause
