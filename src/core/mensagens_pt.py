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
Humanização de mensagens de ferramentas para pt-BR.

Traduz os identificadores e mensagens mais comuns do Semgrep e do Bandit
para descrições em português legíveis por executivos/analistas, em vez de
exibir o texto bruto (inglês técnico) das ferramentas.

Aprendizado do estudo DefectDojo: 52 checks distintos do Semgrep e 11
testes do Bandit. Cobrimos os mais frequentes e aplicamos um fallback
derivado do sufixo do identificador para os demais.
"""

# ── Semgrep (check_id → (título pt, descrição pt)) ──────────────────────────
SEMGREP_PT = {
    "html.security.plaintext-http-link.plaintext-http-link": (
        "Link HTTP sem criptografia em conteúdo HTML",
        "Recurso carregado por URL http:// (sem TLS). Em páginas sensíveis, links "
        "não criptografados permitem interceptação/adulteração por atacante na rede.",
    ),
    "python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape": (
        "XSS potencial em template (blocktranslate sem escape)",
        "Variável renderizada dentro de blocktranslate sem filtro de escape explícito. "
        "Se o dado vier do usuário, pode resultar em XSS armazenado.",
    ),
    "generic.secrets.security.detected-pgp-private-key-block.detected-pgp-private-key-block": (
        "Chave privada PGP no repositório",
        "Bloco de chave privada PGP encontrado no código. Chaves privadas nunca devem "
        "ser versionadas; verifique se é dado real ou fixture de teste.",
    ),
    "python.django.security.audit.avoid-mark-safe.avoid-mark-safe": (
        "Uso de mark_safe (possível XSS)",
        "mark_safe marca conteúdo como HTML seguro. Use apenas com dados confiáveis "
        "e sanitizados; entradas do usuário precisam de escape.",
    ),
    "generic.secrets.security.detected-generic-secret.detected-generic-secret": (
        "Segredo genérico detectado",
        "Possível credencial/token identificado por padrão genérico de segredo.",
    ),
    "python.django.security.django-no-csrf-token.django-no-csrf-token": (
        "View Django sem proteção CSRF",
        "Endpoint sem token CSRF. Views que alteram estado precisam de proteção "
        "contra cross-site request forgery.",
    ),
    "yaml.github-actions.security.run-shell-injection.run-shell-injection": (
        "Shell injection em GitHub Actions",
        "Contexto do evento interpolado em bloco run: de shell. Conteúdo controlado "
        "por PR/issue pode injetar comandos no CI.",
    ),
    "generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value": (
        "Chave de acesso AWS no repositório",
        "AWS Access Key ID encontrada no código. Roteie a chave imediatamente.",
    ),
    "generic.secrets.security.detected-aws-secret-access-key.detected-aws-secret-access-key": (
        "Chave secreta AWS no repositório",
        "AWS Secret Access Key encontrada no código. Roteie a chave imediatamente.",
    ),
    "yaml.github-actions.security.secrets-inherit.secrets-inherit": (
        "Secrets herdados em GitHub Actions",
        "Job filho herda todos os secrets do repositório, ampliando a superfície "
        "de exposição. Passe apenas os secrets necessários.",
    ),
    "python.lang.security.audit.non-literal-import.non-literal-import": (
        "Import dinâmico não literal",
        "Import de módulo com nome calculado em runtime. Dificulta análise e pode "
        "carregar código inesperado.",
    ),
    "python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query": (
        "Query SQL raw no SQLAlchemy",
        "Execução de query SQL construída manualmente. Se houver concatenação de "
        "entrada não sanitizada, é SQL Injection.",
    ),
    "python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape": (
        "XSS potencial em template (translate as sem escape)",
        "Variável renderizada via translate sem filtro de escape explícito.",
    ),
    "python.lang.security.audit.formatted-sql-query.formatted-sql-query": (
        "Query SQL formatada com f-string",
        "SQL construído com formatação de string. Use parâmetros/ORM para evitar "
        "SQL Injection.",
    ),
    "python.django.security.audit.unvalidated-password.unvalidated-password": (
        "Senha sem validação de força",
        "Senha aceita sem validação de comprimento/complexidade (política fraca).",
    ),
    "generic.unicode.security.bidi.contains-bidirectional-characters": (
        "Caracteres de direção bidirecional (trojan source)",
        "Caracteres Unicode de controle de direção podem esconder código malicioso "
        "(ataque trojan source).",
    ),
    "html.security.audit.missing-integrity.missing-integrity": (
        "Script externo sem atributo integrity (SRI)",
        "Script carregado de CDN sem Subresource Integrity. Adicione o hash para "
        "evitar adulteração de terceiros.",
    ),
    "generic.secrets.security.detected-generic-api-key.detected-generic-api-key": (
        "Chave de API genérica detectada",
        "Possível chave de API identificada por padrão genérico.",
    ),
    "yaml.renovate": (
        "Configuração do Renovate com política de atualização insuficiente",
        "Configuração do Renovate (bot de dependências) sem políticas como minimumReleaseAge, "
        "que evita pacotes recém-publicados (possivelmente maliciosos ou instáveis).",
    ),
    "yaml.dependabot": (
        "Configuração do Dependabot com política de atualização insuficiente",
        "Configuração do Dependabot sem políticas como cooldown/intervalo mínimo entre "
        "atualizações de dependências.",
    ),
    "yaml.github-actions": (
        "Configuração de GitHub Actions com risco",
        "Workflow de GitHub Actions com padrão de risco de CI/CD (interpolação em shell, "
        "secrets herdados ou eventos não confiáveis).",
    ),
    "package_managers.dependabot.dependabot-missing-cooldown": (
        "Dependabot sem período de espera (cooldown)",
        "A configuração do Dependabot não define um período de espera antes de aplicar "
        "atualizações de dependências recém-publicadas, que podem ser maliciosas ou "
        "instáveis. Adicione um bloco cooldown com default-days: 7 em cada "
        "package-ecosystem sob updates.",
    ),
    "package_managers.renovate.renovate-missing-minimum-release-age": (
        "Renovate sem idade mínima de release",
        "A configuração do Renovate não define uma idade mínima (minimumReleaseAge) antes "
        "de propor atualizações. Pacotes recém-publicados podem ser maliciosos ou "
        "instáveis. Adicione minimumReleaseAge: 7 dias em packageRules.",
    ),
    "package_managers.dependabot": (
        "Configuração do Dependabot com política de atualização insuficiente",
        "Configuração do Dependabot (bot de dependências) sem políticas como cooldown/"
        "intervalo mínimo entre atualizações, que evita pacotes recém-publicados.",
    ),
    "package_managers.renovate": (
        "Configuração do Renovate com política de atualização insuficiente",
        "Configuração do Renovate (bot de dependências) sem políticas como "
        "minimumReleaseAge, que evita pacotes recém-publicados (possivelmente "
        "maliciosos ou instáveis).",
    ),
}

# ── Bandit (test_name → (título pt, descrição pt)) ──────────────────────────
BANDIT_PT = {
    "hardcoded_password_funcarg": (
        "Senha hardcoded (argumento de função)",
        "Senha definida diretamente no código, passada como argumento. Use variáveis "
        "de ambiente ou cofre de segredos.",
    ),
    "hardcoded_password_string": (
        "Senha hardcoded (string)",
        "Senha literal no código-fonte. Use variáveis de ambiente ou gerenciador "
        "de segredos.",
    ),
    "blacklist": (
        "Uso de módulo/API desaconselhado",
        "O Bandit sinalizou o uso de uma chamada conhecida por riscos (ex.: "
        "subprocess, mktemp, eval). Revise o contexto de uso.",
    ),
    "django_mark_safe": (
        "Uso de mark_safe (possível XSS)",
        "mark_safe marca conteúdo como HTML seguro. Use apenas com dados confiáveis "
        "e sanitizados.",
    ),
    "hardcoded_sql_expressions": (
        "Expressão SQL hardcoded",
        "Expressão SQL construída por concatenação/strings. Prefira parâmetros "
        "parametrizados para evitar SQL Injection.",
    ),
    "try_except_pass": (
        "Exceção ignorada (pass)",
        "Bloco except sem tratamento ignora erros silenciosamente, dificultando "
        "detecção de falhas de segurança.",
    ),
    "hardcoded_tmp_directory": (
        "Diretório temporário hardcoded",
        "Uso de diretório temporário fixo pode ser alvo de symlink attacks. "
        "Prefira tempfile.",
    ),
    "hardcoded_bind_all_interfaces": (
        "Serviço escutando em todas as interfaces",
        "Bind em 0.0.0.0 expõe o serviço em todas as interfaces de rede. Em "
        "parsers/integrações, verifique se o bind é realmente necessário.",
    ),
    "subprocess_without_shell_equals_true": (
        "subprocess sem controle de shell",
        "Uso de subprocess sem shell explícito. Mantenha shell=False e passe "
        "argumentos como lista.",
    ),
    "hashlib": (
        "Hash fraco (MD5/SHA1)",
        "Uso de função de hash considerada fraca para segurança. Confirme se o "
        "hash é usado para criptografia ou apenas para chave/deduplicação.",
    ),
    "try_except_continue": (
        "Exceção ignorada (continue)",
        "Bloco except com continue descarta erros silenciosamente.",
    ),
}


def _match_entry(mapping, key):
    """
    Busca tolerante em um dicionário de traduções.

    O Semgrep pode reportar o check_id com ou sem o sufixo duplicado
    (ex.: ...run-shell-injection.run-shell-injection vs ...run-shell-injection).
    """
    key = str(key or "")
    if key in mapping:
        return mapping[key]
    # Remove sufixo duplicado: python.x.y.y -> python.x.y
    parts = key.split(".")
    if len(parts) >= 2 and parts[-1] == parts[-2]:
        cand = ".".join(parts[:-1])
        if cand in mapping:
            return mapping[cand]
    # Prefixo: chave contém a entrada ou a entrada contém a chave
    for k, v in mapping.items():
        if key.startswith(k) or k.startswith(key):
            return v
    return None


# Palavras do sufixo do check_id → frase em pt (fallback genérico)
_SUFFIX_WORDS = {
    "injection": "Injeção",
    "sql": "SQL",
    "xss": "XSS",
    "csrf": "CSRF",
    "ssrf": "SSRF",
    "eval": "uso de eval()",
    "exec": "execução de código",
    "secret": "segredo/credencial",
    "password": "senha",
    "hardcoded": "valor hardcoded",
    "deserialization": "desserialização insegura",
    "traversal": "path traversal",
    "redirect": "open redirect",
    "header": "cabeçalho HTTP",
    "cookie": "cookie",
    "crypto": "criptografia",
    "md5": "hash MD5",
    "sha1": "hash SHA1",
    "tls": "TLS",
    "ssl": "SSL",
    "ssl-verify": "verificação SSL",
    "verify": "verificação",
    "request": "requisição",
    "url": "URL",
    "import": "import",
    "cors": "CORS",
    "jwt": "JWT",
    "auth": "autenticação",
    "login": "login",
    "debug": "debug",
    "logging": "logging",
    "error": "tratamento de erro",
    "command": "comando",
    "subprocess": "subprocess",
    "shell": "shell",
    "pickle": "pickle",
    "yaml": "YAML",
    "raw": "query raw",
    "query": "query",
    "integrity": "integridade (SRI)",
    "http": "HTTP",
    "https": "HTTPS",
    "performance": "performance",
    "len": "len()",
    "count": "count()",
}


def _humanize_suffix(check_id):
    """Deriva um título legível a partir do sufixo do identificador."""
    parts = str(check_id or "").split(".")
    tail = parts[-1] if parts else ""
    words = tail.replace("-", " ").replace("_", " ").split()
    # Remove palavras de ruído
    words = [w for w in words if w not in ("detected", "audit", "security", "avoid", "python")]
    if not words:
        return check_id or "Achado de segurança"
    if len(words) == 1 and words[0] in _SUFFIX_WORDS:
        return "Possível " + _SUFFIX_WORDS[words[0]]
    return "Possível " + " ".join(words)


def humanize_semgrep(check_id, message):
    """Retorna (título pt, descrição pt) para um check do Semgrep."""
    entry = _match_entry(SEMGREP_PT, check_id)
    if entry:
        return entry
    # Fallback: título derivado + mensagem original resumida
    title = _humanize_suffix(check_id)
    desc = str(message or "").strip()
    if len(desc) > 220:
        desc = desc[:220].rsplit(" ", 1)[0] + "..."
    return title, desc


def humanize_bandit(test_name, issue_text):
    """Retorna (título pt, descrição pt) para um teste do Bandit."""
    entry = _match_entry(BANDIT_PT, test_name)
    if entry:
        return entry
    title = "Possível " + str(test_name or "achado").replace("_", " ")
    desc = str(issue_text or "").strip()
    if len(desc) > 220:
        desc = desc[:220].rsplit(" ", 1)[0] + "..."
    return title, desc


def humanize(tool, title, evidence):
    """
    Ponto único de humanização por ferramenta.

    Parâmetros
    ----------
    tool : str
        Nome da ferramenta (Semgrep/Bandit ou variações).
    title : str
        Identificador do achado (check_id/test_name).
    evidence : str
        Mensagem original da ferramenta.

    Retorna
    -------
    tuple (título_pt, descrição_pt)
    """
    tool_lower = str(tool or "").lower()
    if "semgrep" in tool_lower:
        return humanize_semgrep(title, evidence)
    if "bandit" in tool_lower:
        return humanize_bandit(title, evidence)
    # Outras ferramentas: mantém, mas limita tamanho
    desc = str(evidence or "").strip()
    if len(desc) > 220:
        desc = desc[:220].rsplit(" ", 1)[0] + "..."
    return str(title or "Achado"), desc


def humanize_auto(title, evidence):
    """
    Humaniza sem conhecer a ferramenta, detectando pelo formato do título.

    - Semgrep: check_id com domínios (ex.: python.lang.security..., html.security...)
    - Bandit: test_name com underscore (ex.: hardcoded_password_string)

    Usado pelo fallback local da IA, que recebe apenas título e descrição.
    """
    raw = str(title or "")
    if any(
        marker in raw
        for marker in (
            ".security.", ".lang.", "generic.", "html.", "yaml.", ".django.",
            "package_managers.",
        )
    ):
        return humanize_semgrep(raw, evidence)
    if raw in BANDIT_PT or ("_" in raw and raw.lower() == raw):
        return humanize_bandit(raw, evidence)
    # Fallback genérico
    desc = str(evidence or "").strip()
    if len(desc) > 220:
        desc = desc[:220].rsplit(" ", 1)[0] + "..."
    return raw, desc
