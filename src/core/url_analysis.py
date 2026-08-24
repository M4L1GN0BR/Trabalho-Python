"""
Módulo de análise de URL (reconhecimento passivo).

Contém a lógica de discovery de endpoints, classificação baseada em evidências,
verificação de headers de segurança, TLS/SSL e cálculo de score.
Não depende de Streamlit.
"""

import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
import tldextract

from .secrets import SECRET_REGEX_PATTERNS

COMMON_PATHS = [
    "/admin",
    "/login",
    "/dashboard",
    "/robots.txt",
    "/sitemap.xml",
    "/swagger",
    "/swagger-ui",
    "/api",
    "/api/",
    "/api/docs",
    "/graphql",
    "/config",
    "/.env",
    "/phpinfo.php",
    "/backup",
    "/backups",
    "/test",
    "/dev",
    "/debug",
    "/server-status",
    "/wp-admin",
    "/wp-login.php",
    "/administrator",
]

ADMIN_INDICATORS = [
    "admin panel",
    "administrator",
    "painel administrativo",
    "área administrativa",
    "dashboard administrativo",
    "admin dashboard",
    "manage users",
    "gerenciar usuários",
    "user management",
    "controle de acesso",
]

PUBLIC_CONTENT_INDICATORS = [
    "notícia",
    "news",
    "blog",
    "matéria",
    "artigo",
    "faculdade",
    "universidade",
    "curso",
    "graduação",
    "administração",
    "institucional",
    "sobre nós",
    "portal",
    "aluno",
    "conteúdo",
    "educação",
    "fiap",
]

TECHNICAL_EXPOSURE_INDICATORS = [
    "index of /",
    "directory listing",
    "api documentation",
    "swagger ui",
    "openapi",
    "graphql playground",
    "phpinfo()",
    "database error",
    "stack trace",
    "traceback",
    "debug mode",
    "environment",
    "secret_key",
    "db_password",
    "aws_access_key",
    "private key",
]

# Evidências fortes de vazamento sensível.
# Essas regras ajudam a diferenciar uma página pública comum de uma vulnerabilidade real.
SENSITIVE_EVIDENCE_PATTERNS = [
    "DB_PASSWORD",
    "DATABASE_URL",
    "SECRET_KEY",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "API_KEY",
    "ACCESS_TOKEN",
    "GITHUB_TOKEN",
    "JWT_SECRET",
    "password=",
    "passwd=",
    "db_user",
    "db_pass",
    "authorization: bearer",
]


def normalize_url(url):
    url = url.strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    return url


def get_base_domain(url):
    parsed = urlparse(url)
    extracted = tldextract.extract(parsed.netloc)

    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    return parsed.netloc


def strip_html(html):
    if not html:
        return ""

    html = re.sub(r"<script.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<style.*?</style>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def extract_html_title(html):
    if not html:
        return ""

    match = re.search(r"<title>(.*?)</title>", html, flags=re.DOTALL | re.IGNORECASE)

    if not match:
        return ""

    return strip_html(match.group(1))


def has_login_form(html):
    if not html:
        return False

    html_lower = html.lower()

    has_form = "<form" in html_lower
    has_password = 'type="password"' in html_lower or "type='password'" in html_lower
    has_user_field = (
        "username" in html_lower
        or "email" in html_lower
        or "login" in html_lower
        or "usuario" in html_lower
        or "usuário" in html_lower
        or "user_login" in html_lower
    )

    return has_form and has_password and has_user_field


def count_indicators(text, indicators):
    text = str(text).lower()
    return sum(1 for indicator in indicators if indicator.lower() in text)


def find_evidence(text, indicators):
    """
    Procura evidências textuais em um conteúdo e retorna os indicadores encontrados.
    Diferente de contar palavras, essa função guarda exatamente o que foi encontrado
    para mostrar no dashboard e justificar a classificação.
    """
    found = []
    raw_text = str(text)

    for indicator in indicators:
        if indicator.lower() in raw_text.lower():
            found.append(indicator)

    return sorted(set(found))


def find_regex_evidence(text):
    """
    Procura evidências por regex, como chaves AWS, tokens GitHub e chaves privadas.
    Esses padrões são sinais mais fortes de vazamento real do que apenas encontrar
    uma rota chamada /admin ou /api.
    """
    found = []
    raw_text = str(text)

    for pattern in SECRET_REGEX_PATTERNS:
        if re.search(pattern, raw_text):
            found.append(pattern)

    return sorted(set(found))


def is_probably_json_or_api_response(content_type, body):
    """
    Detecta resposta com aparência real de API ou documentação técnica.
    Uma rota /api só vira achado ativo se tiver conteúdo técnico real,
    como JSON, OpenAPI, Swagger ou GraphQL.
    """
    body = str(body).strip()
    content_type = str(content_type).lower()

    if "application/json" in content_type:
        return True

    if body.startswith("{") or body.startswith("["):
        return True

    if '"openapi"' in body.lower() or '"swagger"' in body.lower():
        return True

    return False


def build_evidence_summary(evidences):
    """
    Monta um texto amigável para a coluna Evidências.
    """
    if not evidences:
        return "Nenhuma evidência forte encontrada."

    return ", ".join(sorted(set(evidences)))


def classify_discovered_endpoint(path, target, status, html, content_type, final_url):
    """
    Classifica endpoints encontrados pelo discovery usando evidências reais.

    Regra central:
    - O nome da rota não prova vulnerabilidade.
    - /admin, /dashboard, /api, /dev e /wp-admin só viram problema se houver evidência.
    - Login comum, WordPress login, 401/403, robots.txt e páginas públicas são separados
      como falso positivo automático quando não há vazamento ou exposição técnica.

    Tipos retornados:
    - Achado Ativo: entra no score.
    - Melhoria Recomendada: hardening, não vulnerabilidade confirmada.
    - Falso Positivo Automático: não entra no score.
    - Controle OK: não entra no score.
    """
    title = extract_html_title(html)
    text = strip_html(html)
    combined = f"{title} {text}"
    combined_lower = combined.lower()
    final_url_lower = str(final_url).lower()

    sensitive_evidence = find_evidence(html, SENSITIVE_EVIDENCE_PATTERNS)
    regex_evidence = find_regex_evidence(html)
    technical_evidence = find_evidence(combined, TECHNICAL_EXPOSURE_INDICATORS)
    public_score = count_indicators(combined, PUBLIC_CONTENT_INDICATORS)
    login_form = has_login_form(html)
    api_like_response = is_probably_json_or_api_response(content_type, html)

    evidences = sorted(set(sensitive_evidence + regex_evidence + technical_evidence))

    # 401/403 normalmente significam bloqueio, não vazamento.
    if status in [401, 403]:
        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Acesso bloqueado ou protegido ({status})",
            "reason": (
                f"O endpoint {path} respondeu {status}, indicando restrição de acesso. "
                f"Não houve evidência de conteúdo sensível exposto."
            ),
            "evidencias": [],
        }

    # robots.txt e sitemap.xml são esperados em sites públicos.
    if path in ["/robots.txt", "/sitemap.xml"]:
        if sensitive_evidence or regex_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Média",
                "status_text": f"Possível referência sensível ({status})",
                "reason": f"O arquivo {path} é público e contém possíveis referências sensíveis.",
                "evidencias": sensitive_evidence + regex_evidence,
            }

        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Arquivo público esperado ({status})",
            "reason": f"O arquivo {path} é comum em sites públicos e não representa vulnerabilidade crítica sozinho.",
            "evidencias": [],
        }

    # WordPress login/admin comum não é falha sem evidência.
    if path in ["/wp-admin", "/wp-login.php"]:
        if evidences:
            return {
                "tipo": "Achado Ativo",
                "priority": "Média",
                "status_text": f"WordPress com evidência técnica ({status})",
                "reason": f"O endpoint {path} apresentou evidência técnica ou sensível que exige revisão.",
                "evidencias": evidences,
            }

        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Login WordPress esperado ({status})",
            "reason": (
                f"O endpoint {path} indica presença de WordPress/login, mas não há evidência de bypass, "
                f"acesso sem autenticação, enumeração ou falha explorável."
            ),
            "evidencias": [],
        }

    # APIs e documentações só são achado se houver evidência real de exposição.
    if path in ["/api", "/api/", "/api/docs", "/swagger", "/swagger-ui", "/graphql"]:
        # 1) Dado sensível ou credencial: achado ativo alto.
        if sensitive_evidence or regex_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Alta",
                "status_text": f"API com possível dado sensível ({status})",
                "reason": f"O endpoint {path} aparenta conter dado sensível.",
                "evidencias": sensitive_evidence + regex_evidence,
            }

        # 2) Evidência técnica real: Swagger UI, OpenAPI, GraphQL Playground, debug.
        #    Só aqui o endpoint vira achado ativo — documentação/interface de API exposta.
        if (
            technical_evidence
            or "swagger ui" in combined_lower
            or "openapi" in combined_lower
            or "graphql playground" in combined_lower
            or "graphiql" in combined_lower
        ):
            return {
                "tipo": "Achado Ativo",
                "priority": "Média",
                "status_text": f"Documentação/API exposta ({status})",
                "reason": f"O endpoint {path} apresenta evidência técnica de exposição de documentação ou interface de API.",
                "evidencias": technical_evidence
                or ["Resposta com indícios de documentação técnica/API"],
            }

        # 3) Resposta em formato API/JSON, mas SEM dado sensível e SEM exposição
        #    técnica: hardening, não vulnerabilidade confirmada.
        if api_like_response:
            return {
                "tipo": "Melhoria Recomendada",
                "priority": "Baixa",
                "status_text": f"API pública sem evidência sensível ({status})",
                "reason": (
                    f"O endpoint {path} respondeu com conteúdo no formato API/JSON, mas sem evidência "
                    f"de dado sensível, documentação privada ou exposição técnica. Revisar se o acesso "
                    f"deve ser restrito (autenticação/rede)."
                ),
                "evidencias": [
                    "Resposta em formato API/JSON sem dado sensível identificado"
                ],
            }

        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Sem evidência de API exposta ({status})",
            "reason": (
                f"O endpoint {path} respondeu, mas não apresentou JSON técnico, OpenAPI, Swagger, "
                f"GraphQL Playground, endpoints exploráveis ou dados sensíveis."
            ),
            "evidencias": [],
        }

    # Admin, login e dashboard: login comum não é vulnerabilidade.
    if path in ["/admin", "/login", "/dashboard", "/administrator"]:
        if "wp-login.php" in final_url_lower:
            return {
                "tipo": "Falso Positivo Automático",
                "priority": "Baixa",
                "status_text": f"Redireciona para login esperado ({status})",
                "reason": (
                    f"O endpoint {path} redirecionou para wp-login.php. Isso indica tela de login comum, "
                    f"não vulnerabilidade confirmada."
                ),
                "evidencias": [],
            }

        if sensitive_evidence or regex_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Alta",
                "status_text": f"Dado sensível em área sensível ({status})",
                "reason": f"O endpoint {path} apresentou possíveis dados sensíveis.",
                "evidencias": sensitive_evidence + regex_evidence,
            }

        if technical_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Média",
                "status_text": f"Evidência técnica em área sensível ({status})",
                "reason": f"O endpoint {path} contém sinais técnicos de exposição.",
                "evidencias": technical_evidence,
            }

        if login_form:
            return {
                "tipo": "Falso Positivo Automático",
                "priority": "Baixa",
                "status_text": f"Tela de login identificada ({status})",
                "reason": (
                    f"O endpoint {path} possui formulário de login, mas login comum não prova vulnerabilidade, "
                    f"bypass ou acesso indevido."
                ),
                "evidencias": [],
            }

        if public_score > 0:
            return {
                "tipo": "Falso Positivo Automático",
                "priority": "Baixa",
                "status_text": f"Página pública ou institucional ({status})",
                "reason": (
                    f"O endpoint {path} respondeu, mas o conteúdo parece público, institucional "
                    f"ou informativo."
                ),
                "evidencias": [],
            }

        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Inconclusivo sem evidência crítica ({status})",
            "reason": (
                f"O endpoint {path} respondeu, mas não há evidência de acesso indevido, vazamento, "
                f"debug, erro interno ou painel administrativo acessível."
            ),
            "evidencias": [],
        }

    # dev, test e debug só são achado se tiver evidência técnica real.
    if path in ["/dev", "/test", "/debug"]:
        if sensitive_evidence or regex_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Alta",
                "status_text": f"Possível vazamento em endpoint técnico ({status})",
                "reason": f"O endpoint {path} apresentou possíveis dados sensíveis.",
                "evidencias": sensitive_evidence + regex_evidence,
            }

        if technical_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Alta",
                "status_text": f"Recurso técnico exposto ({status})",
                "reason": f"O endpoint {path} apresenta sinais técnicos como debug, stack trace, ambiente ou erro interno.",
                "evidencias": technical_evidence,
            }

        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Sem evidência técnica crítica ({status})",
            "reason": (
                f"O endpoint {path} respondeu, mas não apresentou debug, stack trace, arquivos internos "
                f"ou dados sensíveis."
            ),
            "evidencias": [],
        }

    # Arquivos sensíveis só são achado se o conteúdo realmente parecer sensível.
    if path in ["/.env", "/config", "/backup", "/backups", "/phpinfo.php"]:
        if sensitive_evidence or regex_evidence or technical_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Alta",
                "status_text": f"Exposição sensível ({status})",
                "reason": f"O endpoint {path} aparenta expor informação técnica ou configuração sensível.",
                "evidencias": evidences,
            }

        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Sem evidência sensível ({status})",
            "reason": f"O endpoint {path} respondeu, mas não há evidência suficiente de vazamento sensível.",
            "evidencias": [],
        }

    if status in [301, 302]:
        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Redireciona ({status})",
            "reason": f"O endpoint {path} apenas redireciona e não apresentou evidência direta de exposição sensível.",
            "evidencias": [],
        }

    return {
        "tipo": "Falso Positivo Automático",
        "priority": "Baixa",
        "status_text": f"Sem evidência crítica ({status})",
        "reason": f"O endpoint {path} respondeu, mas não há evidência suficiente para classificar como vulnerabilidade real.",
        "evidencias": [],
    }


def make_url_finding(
    category, item, status, priority, description, tipo="Achado Ativo", evidencias=None
):
    """
    Cria um item padronizado para URL Analysis.

    Campos:
    - Tipo: Achado Ativo, Melhoria Recomendada, Controle OK ou Falso Positivo Automático.
    - Evidências: mostra por que algo foi classificado como risco real.
    """
    if evidencias is None:
        evidencias = []

    return {
        "Tipo": tipo,
        "Categoria": category,
        "Item": item,
        "Status": status,
        "Prioridade": priority,
        "Evidências": build_evidence_summary(evidencias),
        "Descrição": description,
    }


def scan_common_paths(base_url):
    findings = []

    for path in COMMON_PATHS:
        try:
            target = base_url.rstrip("/") + path

            response = requests.get(
                target,
                timeout=5,
                allow_redirects=True,
                headers={"User-Agent": "ASPM-Scanner/1.0"},
            )

            status = response.status_code
            content_type = response.headers.get("Content-Type", "")
            html = response.text[:12000] if response.text else ""
            final_url = response.url

            if status in [200, 301, 302, 401, 403]:
                classification = classify_discovered_endpoint(
                    path=path,
                    target=target,
                    status=status,
                    html=html,
                    content_type=content_type,
                    final_url=final_url,
                )

                tipo = classification["tipo"]
                priority = classification["priority"]
                status_text = classification["status_text"]
                reason = classification["reason"]
                evidencias = classification.get("evidencias", [])

                description = (
                    f"Endpoint analisado: {target}. "
                    f"URL final: {final_url}. "
                    f"Status HTTP: {status}. "
                    f"Content-Type: {content_type}. "
                    f"Análise contextual: {reason}"
                )

                findings.append(
                    make_url_finding(
                        "Discovery",
                        path,
                        status_text,
                        priority,
                        description,
                        tipo,
                        evidencias,
                    )
                )

        except Exception:
            pass

    return findings


def calculate_score(findings):
    score = 100

    for finding in findings:
        if finding.get("Tipo") != "Achado Ativo":
            continue

        if finding["Prioridade"] == "Alta":
            score -= 15
        elif finding["Prioridade"] == "Média":
            score -= 6
        else:
            score -= 1

    score = max(score, 0)

    if score >= 85:
        classification = "Boa"
    elif score >= 65:
        classification = "Atenção"
    else:
        classification = "Crítica"

    return score, classification


def check_port(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "Aberta"
    except Exception:
        return "Fechada"


def check_ssl_certificate(host):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                cert = secure_sock.getpeercert()

        not_after = cert.get("notAfter")
        expiration = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiration - datetime.utcnow()).days

        if days_left >= 30:
            priority = "Baixa"
            status = "Válido"
            tipo = "Controle OK"
        elif days_left >= 0:
            priority = "Média"
            status = "Expirando"
            tipo = "Achado Ativo"
        else:
            priority = "Alta"
            status = "Expirado"
            tipo = "Achado Ativo"

        return {
            "status": status,
            "priority": priority,
            "description": f"Certificado TLS com {days_left} dias restantes.",
            "tipo": tipo,
        }

    except Exception as e:
        return {
            "status": "Erro",
            "priority": "Média",
            "description": str(e),
            "tipo": "Achado Ativo",
        }


# ═══════════════════════════════════════════════════════════════
# WAF / CDN (detecção passiva) e Cookies
# ═══════════════════════════════════════════════════════════════

# Headers característicos de WAF/CDN (nome do header -> WAF)
WAF_HEADER_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-iinfo": "Imperva Incapsula",
    "x-cdn": "Imperva Incapsula",
    "x-akamai-transformed": "Akamai",
    "x-amzn-requestid": "AWS WAF / CloudFront",
    "x-amz-cf-id": "AWS CloudFront",
    "x-dw-trace-id": "StackPath",
    "x-pantheon-styx-hostname": "Pantheon",
}

# Padrões no header Server (padrão -> WAF)
SERVER_WAF_PATTERNS = [
    ("cloudflare", "Cloudflare"),
    ("akamai", "Akamai"),
    ("incapsula", "Imperva Incapsula"),
    ("sucuri", "Sucuri"),
    ("barracuda", "Barracuda WAF"),
    ("bigip", "F5 BIG-IP ASM"),
    ("big-ip", "F5 BIG-IP ASM"),
    ("modsecurity", "ModSecurity"),
    ("naxsi", "NAXSI"),
    ("awaf", "AWS WAF"),
    ("citrix", "Citrix NetScaler"),
    ("fortiweb", "FortiWeb"),
    ("dotdefender", "DotDefender"),
]


def detect_waf(headers):
    """
    Detecta WAF/CDN de proteção de forma passiva (headers da resposta).

    Retorna lista de dicts {"nome": str, "evidencia": str}.
    """
    detected = []
    headers_lower = {str(k).lower(): str(v) for k, v in headers.items()}

    for header_name, waf_name in WAF_HEADER_SIGNATURES.items():
        if header_name in headers_lower:
            detected.append({"nome": waf_name, "evidencia": f"Header {header_name} presente"})

    server = headers_lower.get("server", "").lower()
    for pattern, waf_name in SERVER_WAF_PATTERNS:
        if pattern in server:
            detected.append({"nome": waf_name, "evidencia": f"Server header: {server[:60]}"})
            break

    # Dedup preservando a primeira ocorrência
    unicos = {}
    for d in detected:
        unicos.setdefault(d["nome"], d)
    return list(unicos.values())


def parse_set_cookie(value):
    """Divide um valor de Set-Cookie em (nome, atributos)."""
    parts = str(value).split(";")
    name = parts[0].split("=", 1)[0].strip() if parts and parts[0].strip() else "?"
    attrs = {}
    for part in parts[1:]:
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        elif part:
            attrs[part.lower()] = True
    return name, attrs


def analyze_cookies(set_cookie_values):
    """
    Analisa cookies de forma passiva (flags Secure, HttpOnly e SameSite).

    Parâmetros
    ----------
    set_cookie_values : list | str
        Valores de Set-Cookie (lista de headers ou string única).

    Retorna
    -------
    list[dict]
        Achados no formato interno: Item, Status, Prioridade, Tipo, Evidências, Descrição.
    """
    if isinstance(set_cookie_values, str):
        values = [set_cookie_values]
    else:
        values = list(set_cookie_values or [])

    findings = []
    if not values:
        return findings

    for raw in values:
        name, attrs = parse_set_cookie(raw)

        flags = []
        flags.append("Secure" if attrs.get("secure") else "Sem Secure")
        flags.append("HttpOnly" if attrs.get("httponly") else "Sem HttpOnly")
        samesite = attrs.get("samesite")
        flags.append(f"SameSite={samesite}" if samesite else "Sem SameSite")

        if attrs.get("secure") and attrs.get("httponly") and samesite:
            findings.append(
                {
                    "Item": f"Cookie {name}",
                    "Status": "Controle OK",
                    "Prioridade": "Baixa",
                    "Tipo": "Controle OK",
                    "Evidências": ", ".join(flags),
                    "Descrição": f"Cookie '{name}' com Secure, HttpOnly e SameSite={samesite}.",
                }
            )
        else:
            problemas = []
            if not attrs.get("secure"):
                problemas.append("sem Secure (envio permitido em HTTP)")
            if not attrs.get("httponly"):
                problemas.append("sem HttpOnly (acessível via JavaScript)")
            if not samesite:
                problemas.append("sem SameSite (menos proteção contra CSRF)")
            findings.append(
                {
                    "Item": f"Cookie {name}",
                    "Status": "Atenção",
                    "Prioridade": "Baixa",
                    "Tipo": "Melhoria Recomendada",
                    "Evidências": ", ".join(flags),
                    "Descrição": (
                        f"Cookie '{name}': {'; '.join(problemas)}. "
                        "Melhoria de hardening, não vulnerabilidade explorável confirmada."
                    ),
                }
            )

    return findings


def _query_crtsh(domain, timeout):
    """Consulta logs públicos de certificados (crt.sh)."""
    subdomains = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=timeout,
            headers={"User-Agent": "ASPM-Scanner/1.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                names = str(entry.get("name_value", "")).split("\n")
                for name in names:
                    name = name.strip().strip("*").lower()
                    if name.endswith(f".{domain}") or name == domain:
                        subdomains.add(name)
    except Exception:
        pass
    return subdomains


def _query_hackertarget(domain, timeout):
    """Consulta passiva ao HackerTarget (hostsearch) como fonte alternativa."""
    subdomains = set()
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=timeout,
            headers={"User-Agent": "ASPM-Scanner/1.0"},
        )
        if resp.status_code == 200 and resp.text:
            for line in resp.text.strip().splitlines():
                name = line.split(",")[0].strip().lower()
                if name.endswith(f".{domain}") or name == domain:
                    subdomains.add(name)
    except Exception:
        pass
    return subdomains


def enumerate_subdomains(domain, timeout=8, limit=40):
    """
    Enumera subdomínios de forma passiva via Certificate Transparency (crt.sh)
    com fallback no HackerTarget. Nenhum scan direto no alvo.

    Retorna lista ordenada de subdomínios (vazia se indisponível/offline).
    """
    domain = str(domain).strip().lower().lstrip("*.")
    if not domain:
        return []

    subdomains = _query_crtsh(domain, timeout)
    if not subdomains:
        # crt.sh costuma ficar sobrecarregado (502) — tenta fonte alternativa
        subdomains = _query_hackertarget(domain, timeout)

    return sorted(subdomains)[:limit]


def crawl_internal_links(url, max_pages=12, timeout=3):
    """
    Crawl passivo e limitado: segue links internos do mesmo domínio.

    Apenas requisições GET a páginas do próprio domínio, com limite de páginas
    (max_pages) para não virar varredura. Retorna lista de URLs visitadas.
    """
    visited = []
    seen = set()
    queue = [url]
    base_host = (urlparse(url).hostname or "").lower()

    while queue and len(visited) < max_pages:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        try:
            resp = requests.get(
                current,
                timeout=timeout,
                headers={"User-Agent": "ASPM-Scanner/1.0"},
            )
            visited.append(current)
            html = resp.text[:200000] if resp.text else ""
            for href in re.findall(r'href=["\']([^"\'#]+)["\']', html, re.I):
                full = urljoin(current, href.strip())
                parsed = urlparse(full)
                if parsed.scheme in ("http", "https") and (parsed.hostname or "").lower() == base_host:
                    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
                    if normalized not in seen and len(seen) < max_pages * 3:
                        queue.append(normalized)
        except Exception:
            break

    return visited


def analyze_url(url, subdomains=True, crawl=True, crawl_max=12):
    url = normalize_url(url)
    findings = []

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "ASPM-Scanner/1.0"},
        )

        headers = response.headers
        final_url = response.url
        parsed = urlparse(final_url)
        host = parsed.hostname
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        uses_https = parsed.scheme == "https"

        findings.append(
            make_url_finding(
                "HTTPS",
                "HTTPS",
                "OK" if uses_https else "Ausente",
                "Baixa" if uses_https else "Alta",
                "Site utiliza HTTPS." if uses_https else "Site não utiliza HTTPS.",
                "Controle OK" if uses_https else "Achado Ativo",
            )
        )

        if uses_https and host:
            cert_result = check_ssl_certificate(host)
            findings.append(
                make_url_finding(
                    "TLS",
                    "Certificado SSL",
                    cert_result["status"],
                    cert_result["priority"],
                    cert_result["description"],
                    cert_result["tipo"],
                )
            )

        security_headers = {
            "Content-Security-Policy": "Média",
            "Strict-Transport-Security": "Média",
            "X-Frame-Options": "Média",
            "X-Content-Type-Options": "Média",
            "Referrer-Policy": "Baixa",
            "Permissions-Policy": "Baixa",
        }

        for header, priority in security_headers.items():
            if header in headers:
                findings.append(
                    make_url_finding(
                        "Headers",
                        header,
                        "Presente",
                        "Baixa",
                        headers.get(header),
                        "Controle OK",
                    )
                )
            else:
                findings.append(
                    make_url_finding(
                        "Headers",
                        header,
                        "Ausente",
                        priority,
                        f"{header} ausente. Isso representa melhoria de hardening, não vulnerabilidade explorável confirmada.",
                        "Melhoria Recomendada",
                        [f"Header {header} ausente"],
                    )
                )

        if headers.get("Server"):
            findings.append(
                make_url_finding(
                    "Exposição",
                    "Server",
                    "Exposto",
                    "Baixa",
                    headers.get("Server"),
                    "Melhoria Recomendada",
                    ["Header Server exposto"],
                )
            )

        if headers.get("X-Powered-By"):
            findings.append(
                make_url_finding(
                    "Exposição",
                    "X-Powered-By",
                    "Exposto",
                    "Média",
                    headers.get("X-Powered-By"),
                    "Melhoria Recomendada",
                    ["Header X-Powered-By exposto"],
                )
            )

        # WAF / CDN de proteção (detecção passiva)
        wafs = detect_waf(headers)
        if wafs:
            nome_waf = ", ".join(w["nome"] for w in wafs)
            findings.append(
                make_url_finding(
                    "Rede",
                    "WAF / CDN de proteção",
                    f"Detectado: {nome_waf}",
                    "Baixa",
                    f"WAF/CDN de proteção identificado nos headers da resposta ({nome_waf}).",
                    "Controle OK",
                    [w["evidencia"] for w in wafs],
                )
            )
        else:
            findings.append(
                make_url_finding(
                    "Rede",
                    "WAF / CDN de proteção",
                    "Nenhum WAF detectado",
                    "Baixa",
                    "Nenhum WAF/CDN identificado nos headers. Avaliar proteção de borda como defesa em profundidade.",
                    "Melhoria Recomendada",
                    ["Nenhum header característico de WAF na resposta"],
                )
            )

        # Cookies (análise passiva de Secure, HttpOnly e SameSite)
        try:
            set_cookies = (
                response.raw.headers.getlist("Set-Cookie")
                if response.raw and response.raw.headers
                else []
            )
        except Exception:
            set_cookies = []
        for cookie_finding in analyze_cookies(set_cookies):
            findings.append(
                make_url_finding(
                    "Cookies",
                    cookie_finding["Item"],
                    cookie_finding["Status"],
                    cookie_finding["Prioridade"],
                    cookie_finding["Descrição"],
                    cookie_finding["Tipo"],
                    [cookie_finding["Evidências"]],
                )
            )

        if host:
            findings.append(
                make_url_finding(
                    "Rede",
                    "Porta 80",
                    check_port(host, 80),
                    "Baixa",
                    "Verificação HTTP.",
                    "Controle OK",
                )
            )

            findings.append(
                make_url_finding(
                    "Rede",
                    "Porta 443",
                    check_port(host, 443),
                    "Baixa",
                    "Verificação HTTPS.",
                    "Controle OK",
                )
            )

        findings.extend(scan_common_paths(base_url))

        # Subdomínios via Certificate Transparency (crt.sh) — passivo
        subdomain_list = []
        if host and subdomains:
            try:
                subdomain_list = enumerate_subdomains(host)
            except Exception:
                subdomain_list = []

        # Crawl interno limitado (passivo, mesmo domínio)
        crawl_links = []
        if crawl:
            try:
                crawl_links = crawl_internal_links(final_url or url, max_pages=crawl_max)
            except Exception:
                crawl_links = []

        score, classification = calculate_score(findings)

        return {
            "url_inicial": url,
            "url_final": final_url,
            "dominio": get_base_domain(final_url),
            "status_code": response.status_code,
            "score": score,
            "classificacao": classification,
            "findings": findings,
            "subdominios": subdomain_list,
            "crawl_links": crawl_links,
        }

    except Exception as e:
        return {
            "url_inicial": url,
            "url_final": "Erro",
            "dominio": "Erro",
            "status_code": "Erro",
            "score": 0,
            "classificacao": "Crítica",
            "findings": [
                make_url_finding("Erro", "Conexão", "Erro", "Alta", str(e), "Achado Ativo")
            ],
        }
