@REM NightSync - ASPM (Application Security Posture Management)
@REM Copyright (C) 2026 Felipe Barbosa Alves (RM570378),
@REM                    Murilo Garcia Godoy (RM564840),
@REM                    Lucas Moura Goncalves de Amorim (RM570161),
@REM                    Caio de Paula Goes (RM569052)
@REM
@REM This file is part of NightSync, free software under the GNU General
@REM Public License as published by the Free Software Foundation, either
@REM version 3 of the License, or (at your option) any later version.
@REM
@REM NightSync is distributed in the hope that it will be useful, but
@REM WITHOUT ANY WARRANTY; without even the implied warranty of
@REM MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
@REM General Public License for more details.
@REM
@REM You should have received a copy of the GNU General Public License
@REM along with this program. If not, see <https://www.gnu.org/licenses/>.
@REM
@REM SPDX-License-Identifier: GPL-3.0-or-later

@echo off
rem Atalho: abre o dashboard com o relatorio real do DefectDojo carregado.
rem Nao roda scan (usa o relatorio ja existente em data\defectdojo-scan).
cd /d "%~dp0"
call .venv\Scripts\activate
python run_defectdojo.py
pause
