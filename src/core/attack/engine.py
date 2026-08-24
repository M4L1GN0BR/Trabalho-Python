"""
Engine dos testes ofensivos — orquestra os módulos e agrega achados.

Somente uso autorizado (laboratório). Cada módulo tem limites próprios
(requisições, timeouts) e nenhuma ação destrutiva.

Uso:
    python src/main.py attack --url https://alvo-autorizado.com
"""

from urllib.parse import urlparse

from .recon_active import active_recon, recon_findings
from .idor_tester import idor_test, idor_findings
from .api_fuzzer import api_fuzz, fuzz_findings
from .rate_limit_tester import rate_limit_test, rate_findings
from .cors_checker import cors_check, cors_findings
from .http_methods import http_methods_test, methods_findings
from .path_traversal import path_traversal_test, traversal_findings
from .open_redirect import open_redirect_test, redirect_findings
from .sqli_detector import sqli_detection_test, sqli_findings
from .xss_detector import xss_detection_test, xss_findings
from .credential_stuffer import credential_stuff_test, creds_findings

MODULE_LABELS = {
    "recon": "Recon Ativo (portas)",
    "idor": "IDOR / Enumeração de IDs",
    "fuzz": "API Fuzzing (caminhos comuns)",
    "rate": "Rate Limit",
    "cors": "CORS Misconfiguration",
    "methods": "HTTP Methods / TRACE",
    "traversal": "Path Traversal (LFI)",
    "redirect": "Open Redirect",
    "sqli": "SQL Injection (detecção)",
    "xss": "XSS Refletido (detecção)",
    "creds": "Credenciais comuns (LAB)",
}


def _finding(category, item, status, priority, description, tipo, evidencias=None):
    """Cria um achado no formato padronizado do dashboard."""
    return {
        "Tipo": tipo,
        "Categoria": category,
        "Item": item,
        "Status": status,
        "Prioridade": priority,
        "Evidências": ", ".join(evidencias) if evidencias else "Nenhuma evidência forte encontrada.",
        "Descrição": description,
    }


def run_attack_modules(
    url,
    modules=None,
    id_param="id",
    traversal_param="file",
    web_param="id",
    user_field="username",
    pass_field="password",
    timeout=5,
):
    """
    Executa os módulos ofensivos selecionados contra um alvo autorizado.

    Parâmetros
    ----------
    url : str
        URL do alvo (ex: https://alvo-autorizado.com). Para o módulo `creds`,
        informe o endpoint de login.
    modules : list, optional
        Subconjunto de ["recon", "idor", "fuzz", "rate", "cors", "methods",
        "traversal", "redirect", "sqli", "xss", "creds"]. Padrão: todos.
    id_param : str
        Nome do parâmetro de ID usado no teste de IDOR.
    traversal_param : str
        Nome do parâmetro usado no teste de path traversal.
    web_param : str
        Nome do parâmetro usado nos testes de SQLi e XSS.
    user_field / pass_field : str
        Nomes dos campos de usuário/senha no endpoint de login (creds).
    timeout : int
        Timeout base das requisições.

    Retorna
    -------
    dict
        {"target", "modules_executados", "module_results", "findings", "total_findings"}
    """
    modules = modules or list(MODULE_LABELS.keys())
    host = (urlparse(url).hostname or "").strip()

    results = {}
    findings = []

    if "recon" in modules and host:
        ports = active_recon(host, timeout=timeout)
        results["recon"] = {"host": host, "portas_abertas": ports}
        findings.extend(recon_findings(ports, host))

    if "idor" in modules:
        idor = idor_test(url, id_param=id_param, timeout=timeout)
        results["idor"] = idor
        findings.extend(idor_findings(idor, id_param))

    if "fuzz" in modules:
        fuzz = api_fuzz(url, timeout=timeout)
        results["fuzz"] = fuzz
        findings.extend(fuzz_findings(fuzz))

    if "rate" in modules:
        statuses = rate_limit_test(url)
        results["rate"] = statuses
        findings.extend(rate_findings(statuses))

    if "cors" in modules:
        cors = cors_check(url)
        results["cors"] = cors
        findings.extend(cors_findings(cors))

    if "methods" in modules:
        methods = http_methods_test(url)
        results["methods"] = methods
        findings.extend(methods_findings(methods))

    if "traversal" in modules:
        traversal = path_traversal_test(url, param=traversal_param)
        results["traversal"] = traversal
        findings.extend(traversal_findings(traversal))

    if "redirect" in modules:
        redirect = open_redirect_test(url)
        results["redirect"] = redirect
        findings.extend(redirect_findings(redirect))

    if "sqli" in modules:
        sqli = sqli_detection_test(url, param=web_param)
        results["sqli"] = sqli
        findings.extend(sqli_findings(sqli))

    if "xss" in modules:
        xss = xss_detection_test(url, param=web_param)
        results["xss"] = xss
        findings.extend(xss_findings(xss))

    if "creds" in modules:
        creds = credential_stuff_test(
            url, user_field=user_field, pass_field=pass_field
        )
        results["creds"] = creds
        findings.extend(creds_findings(creds))

    return {
        "target": url,
        "modules_executados": [MODULE_LABELS[m] for m in modules if m in MODULE_LABELS],
        "module_results": results,
        "findings": findings,
        "total_findings": len(findings),
    }
