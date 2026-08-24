"""
Detector de XSS refletido — marcadores inofensivos, sem exploração.

Somente uso autorizado. Envia marcadores (com e sem tags HTML) e verifica
se são refletidos sem encoding na resposta. NÃO rouba cookies, NÃO executa
payloads destrutivos e NÃO usa exploração real.
"""

import requests

HEADERS = {"User-Agent": "ASPM-Scanner/1.0"}

MARKER = "ASPMXSSMARKER"

XSS_PAYLOADS = [
    MARKER,
    f"<b>{MARKER}</b>",
    f'\"><b>{MARKER}</b>',
    f"'><svg/onload={MARKER}>",
]


def xss_detection_test(url, param="q", timeout=5):
    """
    Testa reflexo de marcadores em um parâmetro (GET).

    Retorna lista de dicts {"payload", "status", "refletido", "refletido_sem_encoding"}.
    """
    out = []
    for payload in XSS_PAYLOADS:
        try:
            r = requests.get(
                url,
                params={param: payload},
                headers=HEADERS,
                timeout=timeout,
                allow_redirects=False,
            )
            body = r.text[:5000]
            reflected = MARKER in body
            raw = (
                f"<b>{MARKER}</b>" in body
                or ("<svg" in body.lower() and MARKER in body)
            )
            out.append(
                {
                    "payload": payload,
                    "status": r.status_code,
                    "refletido": reflected,
                    "refletido_sem_encoding": raw,
                }
            )
        except Exception:
            out.append(
                {"payload": payload, "status": "erro", "refletido": False, "refletido_sem_encoding": False}
            )
    return out


def xss_findings(results):
    """
    Converte o resultado em achados padronizados.
    """
    from .engine import _finding

    if not results:
        return []

    raw = [r for r in results if r.get("refletido_sem_encoding")]
    reflected_encoded = [
        r for r in results
        if r.get("refletido") and not r.get("refletido_sem_encoding")
    ]

    if raw:
        return [
            _finding(
                "XSS",
                "Possível XSS refletido",
                f"Marcador refletido sem encoding ({len(raw)} payload(s))",
                "Média",
                "O marcador de teste foi refletido na resposta sem codificação HTML, "
                "padrão compatível com XSS refletido — validar manualmente em laboratório.",
                "Achado Ativo",
                [f"payload: {raw[0]['payload']}", "resposta contém a tag HTML original"],
            )
        ]

    if reflected_encoded:
        return [
            _finding(
                "XSS",
                "Reflexo com encoding",
                "Marcador refletido, mas codificado",
                "Baixa",
                "O marcador foi refletido, porém com codificação HTML (escaped). "
                "Indica saída sanitizada — reforçar encoding em todas as saídas.",
                "Melhoria Recomendada",
                ["marcador refletido sem execução possível (escape presente)"],
            )
        ]

    return [
        _finding(
            "XSS",
            "Teste de XSS",
            "Sem reflexo de marcador",
            "Baixa",
            "Os marcadores de XSS não foram refletidos na resposta do parâmetro testado.",
            "Controle OK",
            [f"{len(results)} payloads testados"],
        )
    ]
