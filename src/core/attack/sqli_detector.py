"""
Detector de SQL Injection — baseado em evidências, sem extração de dados.

Somente uso autorizado. Detecta possíveis SQLi por:
- Erros de banco na resposta (error-based)
- Diferencial booleano entre payloads true/false
- Diferença de tempo (time-based, 1 payload com SLEEP curto)

NÃO extrai dados (sem union/dump), NÃO grava nada, NÃO tenta bypass.
"""

import time

import requests

HEADERS = {"User-Agent": "ASPM-Scanner/1.0"}

BOOLEAN_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ('" OR "1"="1', '" OR "1"="2'),
    ("1' AND '1'='1", "1' AND '1'='2"),
]

ERROR_PAYLOADS = ["'", '"', "1'", "1) AND 1=1--", "' AND 1=CONVERT(int, @@version)--"]

SQL_ERROR_SIGNALS = [
    "syntax error", "mysql", "sqlite", "postgres", "psycopg2", "sqlalchemy",
    "unclosed quotation mark", "you have an error in your sql", "sqlstate",
    "microsoft odbc", "driver error", "pg_", "oracle", "sqlite3",
]

TIME_PAYLOAD = "' OR SLEEP(3)--"


def _get(url, param, payload, timeout):
    try:
        r = requests.get(
            url,
            params={param: payload},
            headers=HEADERS,
            timeout=timeout,
            allow_redirects=False,
        )
        return {"status": r.status_code, "len": len(r.text), "body": r.text[:3000]}
    except requests.exceptions.Timeout:
        return {"status": "timeout", "len": 0, "body": ""}
    except Exception:
        return {"status": "erro", "len": 0, "body": ""}


def sqli_detection_test(url, param="id", timeout=6):
    """
    Executa os testes de detecção de SQLi em um parâmetro.

    Retorna dict com baseline, booleans, errors e time_based.
    """
    baseline = _get(url, param, "1", timeout)

    booleans = []
    for true_p, false_p in BOOLEAN_PAYLOADS:
        r_true = _get(url, param, true_p, timeout)
        r_false = _get(url, param, false_p, timeout)
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
        r = _get(url, param, payload, timeout)
        signals = [s for s in SQL_ERROR_SIGNALS if s in r["body"].lower()]
        errors.append({"payload": payload, "signals": signals})

    start = time.time()
    r_tb = _get(url, param, TIME_PAYLOAD, timeout)
    elapsed = round(time.time() - start, 1)

    return {
        "baseline_len": baseline["len"],
        "booleans": booleans,
        "errors": errors,
        "time_based": {"elapsed": elapsed, "status": r_tb["status"]},
    }


def sqli_findings(results):
    """
    Converte o resultado em achados padronizados (possível SQLi, sem confirmação de exploração).
    """
    from .engine import _finding

    if not results:
        return []

    error_hits = [e for e in results.get("errors", []) if e.get("signals")]
    tb = results.get("time_based", {})
    time_hit = (
        tb.get("status") != "timeout"
        and isinstance(tb.get("elapsed"), (int, float))
        and tb["elapsed"] >= 2.5
    )
    bool_hits = [
        b for b in results.get("booleans", [])
        if isinstance(b.get("diff"), int) and b["diff"] > 150
    ]

    if error_hits:
        return [
            _finding(
                "SQL Injection",
                "Possível SQLi (error-based)",
                f"Sinal de erro de banco em {len(error_hits)} payload(s)",
                "Alta",
                f"Payloads de quebra de sintaxe retornaram sinais de erro de banco "
                f"({', '.join(error_hits[0]['signals'][:3])}). Indica possível injeção SQL "
                f"no parâmetro testado — validar manualmente.",
                "Achado Ativo",
                [f"payload: {error_hits[0]['payload']}", "sinais: " + ", ".join(error_hits[0]["signals"][:3])],
            )
        ]

    if time_hit:
        return [
            _finding(
                "SQL Injection",
                "Possível SQLi (time-based)",
                f"Resposta em {tb.get('elapsed')}s com SLEEP(3)",
                "Alta",
                "O payload time-based (SLEEP(3)) provocou atraso significativo na resposta, "
                "padrão típico de injeção SQL cega — validar manualmente.",
                "Achado Ativo",
                [f"elapsed: {tb.get('elapsed')}s", "payload: " + TIME_PAYLOAD],
            )
        ]

    if bool_hits:
        return [
            _finding(
                "SQL Injection",
                "Possível SQLi (boolean)",
                f"{len(bool_hits)} par(es) true/false com diferença",
                "Média",
                "Payloads booleanos (true vs false) produziram respostas com tamanhos "
                "significativamente diferentes, padrão compatível com injeção booleana — "
                "validar manualmente.",
                "Achado Ativo",
                [f"diferença máxima: {max(b['diff'] for b in bool_hits)} bytes"],
            )
        ]

    return [
        _finding(
            "SQL Injection",
            "Teste de SQLi",
            "Sem indício de SQLi",
            "Baixa",
            "Os testes error-based, boolean e time-based não indicaram injeção SQL "
            f"no parâmetro (baseline {results.get('baseline_len', 0)} bytes).",
            "Controle OK",
            ["error-based, boolean e time-based sem sinais"],
        )
    ]
