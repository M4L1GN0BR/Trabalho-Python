# NightSync - ASPM (Application Security Posture Management)
# Copyright (C) 2026 Felipe Barbosa Alves (RM570378),
#                    Murilo Garcia Godoy (RM564840),
#                    Lucas Moura Goncalves de Amorim (RM570161),
#                    Caio de Paula Goes (RM569052)
#
# This file is part of NightSync, free software under the GNU General
# Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.
#
# NightSync is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Detector de SQL Injection — baseado em evidências, sem extração de dados.

Somente uso autorizado. Detecta possíveis SQLi por:
- Erros de banco na resposta (error-based)
- Diferencial booleano entre payloads true/false
- Diferença de tempo (time-based, 1 payload com SLEEP curto)

Conhecimento adquirido aplicado:
- Testa automaticamente TODOS os parâmetros descobertos na página (inputs por
  name E id, selects, textareas, padrões .get() do JS e formulários POST),
  não só o parâmetro informado (lição NovaMart).
- Segue redirects (allow_redirects=True): hosts estáticos (ex.: Vercel)
  respondem 308 e, sem seguir, o scanner leria a página "Redirecting..." em
  vez do conteúdo real.

NÃO extrai dados (sem union/dump), NÃO grava nada, NÃO tenta bypass.
"""

import time

import requests

from .xss_detector import _discover_params, _discover_post_params

HEADERS = {"User-Agent": "ASPM-Scanner/1.0"}

BOOLEAN_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ('" OR "1"="1', '" OR "1"="2'),
    ("1' AND '1'='1", "1' AND '1'='2"),
]

ERROR_PAYLOADS = ["'", '"', "1'", "1) AND 1=1-- -", "' AND 1=CONVERT(int, @@version)-- -"]

SQL_ERROR_SIGNALS = [
    "syntax error", "mysql", "sqlite", "postgres", "psycopg2", "sqlalchemy",
    "unclosed quotation mark", "you have an error in your sql", "sqlstate",
    "microsoft odbc", "driver error", "pg_", "oracle", "sqlite3",
]

TIME_PAYLOAD = "' OR SLEEP(3)-- -"

# Limite de parâmetros descobertos testados por varredura (custo/latência).
MAX_DISCOVERED_PARAMS = 5


def _get(url, param, payload, timeout, method="GET"):
    try:
        if method == "POST":
            r = requests.post(
                url,
                data={param: payload},
                headers=HEADERS,
                timeout=timeout,
                allow_redirects=True,
            )
        else:
            r = requests.get(
                url,
                params={param: payload},
                headers=HEADERS,
                timeout=timeout,
                allow_redirects=True,
            )
        return {"status": r.status_code, "len": len(r.text), "body": r.text[:3000]}
    except requests.exceptions.Timeout:
        return {"status": "timeout", "len": 0, "body": ""}
    except Exception:
        return {"status": "erro", "len": 0, "body": ""}


def _test_param(url, param, method, timeout):
    """Roda a bateria de testes de SQLi em um único parâmetro."""
    baseline = _get(url, param, "1", timeout, method)
    baseline_signals = [
        s for s in SQL_ERROR_SIGNALS if s in baseline["body"].lower()
    ]

    booleans = []
    for true_p, false_p in BOOLEAN_PAYLOADS:
        r_true = _get(url, param, true_p, timeout, method)
        r_false = _get(url, param, false_p, timeout, method)
        # descarta pares em que alguma resposta falhou/errou (len=0 geraria
        # falso positivo de diff)
        if r_true["status"] == 200 and r_false["status"] == 200:
            booleans.append(
                {
                    "true": true_p,
                    "len_true": r_true["len"],
                    "false": false_p,
                    "len_false": r_false["len"],
                    "diff": abs(r_true["len"] - r_false["len"]),
                }
            )

    errors = []
    for payload in ERROR_PAYLOADS:
        r = _get(url, param, payload, timeout, method)
        # só reporta sinais que aparecem com payload e não no baseline
        signals = [
            s for s in SQL_ERROR_SIGNALS
            if s in r["body"].lower() and s not in baseline_signals
        ]
        errors.append({"payload": payload, "signals": signals})

    start = time.time()
    r_tb = _get(url, param, TIME_PAYLOAD, timeout, method)
    elapsed = round(time.time() - start, 1)

    return {
        "method": method,
        "baseline_len": baseline["len"],
        "booleans": booleans,
        "errors": errors,
        "time_based": {"elapsed": elapsed, "status": r_tb["status"]},
    }


def sqli_detection_test(url, param="id", timeout=6):
    """
    Executa os testes de detecção de SQLi no parâmetro informado E nos
    parâmetros descobertos na página (inputs name/id, selects, textareas,
    padrões .get() do JS e formulários method=POST).

    Retorna dict {param: resultado} — um resultado por parâmetro testado.
    """
    params_get = [param] if param else []
    params_post = []

    try:
        r0 = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        html0 = r0.text
        for p in _discover_params(html0):
            if p not in params_get:
                params_get.append(p)
        params_post = _discover_post_params(html0)
    except Exception:
        pass

    results = {}
    for p in params_get[: MAX_DISCOVERED_PARAMS + 1]:
        results[p] = _test_param(url, p, "GET", timeout)
    for p in params_post:
        if p not in results and len(results) < MAX_DISCOVERED_PARAMS + 2:
            results[p] = _test_param(url, p, "POST", timeout)
    return results


def sqli_findings(results):
    """
    Converte o resultado em achados padronizados (possível SQLi, sem confirmação
    de exploração). Agrega sobre os parâmetros testados.
    """
    from .engine import _finding

    if not results:
        return []

    for p, r in results.items():
        method = r.get("method", "GET")
        error_hits = [e for e in r.get("errors", []) if e.get("signals")]
        tb = r.get("time_based", {})
        time_hit = (
            tb.get("status") == 200
            and isinstance(tb.get("elapsed"), (int, float))
            and tb["elapsed"] >= 2.5
        )
        bool_hits = [
            b for b in r.get("booleans", [])
            if isinstance(b.get("diff"), int) and b["diff"] > 150
        ]

        if error_hits:
            return [
                _finding(
                    "SQL Injection",
                    "Possível SQLi (error-based)",
                    f"Sinal de erro de banco em {len(error_hits)} payload(s) no parâmetro '{p}'",
                    "Alta",
                    f"Payloads de quebra de sintaxe no parâmetro '{p}' ({method}) retornaram "
                    f"sinais de erro de banco ({', '.join(error_hits[0]['signals'][:3])}). "
                    "Indica possível injeção SQL — validar manualmente.",
                    "Achado Ativo",
                    [f"param: {p} ({method})", f"payload: {error_hits[0]['payload']}",
                     "sinais: " + ", ".join(error_hits[0]["signals"][:3])],
                )
            ]

        if time_hit:
            return [
                _finding(
                    "SQL Injection",
                    "Possível SQLi (time-based)",
                    f"Resposta em {tb.get('elapsed')}s com SLEEP(3) no parâmetro '{p}'",
                    "Alta",
                    f"O payload time-based (SLEEP(3)) no parâmetro '{p}' ({method}) provocou "
                    "atraso significativo na resposta, padrão típico de injeção SQL cega — "
                    "validar manualmente.",
                    "Achado Ativo",
                    [f"param: {p} ({method})", f"elapsed: {tb.get('elapsed')}s",
                     "payload: " + TIME_PAYLOAD],
                )
            ]

        if bool_hits:
            return [
                _finding(
                    "SQL Injection",
                    "Possível SQLi (boolean)",
                    f"{len(bool_hits)} par(es) true/false com diferença no parâmetro '{p}'",
                    "Média",
                    f"Payloads booleanos (true vs false) no parâmetro '{p}' ({method}) "
                    "produziram respostas com tamanhos significativamente diferentes, padrão "
                    "compatível com injeção booleana — validar manualmente.",
                    "Achado Ativo",
                    [f"param: {p} ({method})",
                     f"diferença máxima: {max(b['diff'] for b in bool_hits)} bytes"],
                )
            ]

    params_str = ", ".join(results.keys()) or "nenhum"
    return [
        _finding(
            "SQL Injection",
            "Teste de SQLi",
            "Sem indício de SQLi",
            "Baixa",
            f"Os testes error-based, boolean e time-based não indicaram injeção SQL "
            f"nos parâmetros testados ({params_str}).",
            "Controle OK",
            ["error-based, boolean e time-based sem sinais"],
        )
    ]
