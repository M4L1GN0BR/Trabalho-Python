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
Evidence Engine — normaliza e centraliza evidências de todos os findings.

Converte os achados de cada ferramenta (Semgrep, Bandit, SCA, Secrets, URL)
em um formato único de evidência que alimenta o Risk Engine e a IA.
"""

import hashlib


def _hash_id(*parts):
    """Gera um ID estável a partir das partes."""
    raw = "|".join(str(p) for p in parts if p)
    return hashlib.md5(raw.encode("utf-8", errors="replace")).hexdigest()[:12]


def normalize_semgrep(item):
    """Normaliza um achado do Semgrep em evidência."""
    extra = item.get("extra") or {}
    start = item.get("start") or {}
    return {
        "id": _hash_id("semgrep", item.get("check_id"), item.get("path"), start.get("line")),
        "tool": "Semgrep",
        "category": "SAST",
        "file": item.get("path", ""),
        "line": start.get("line"),
        "function": extra.get("metavars", {}).get("$FUNC", {}).get("abstract_content", "") if extra.get("metavars") else "",
        "endpoint": "",
        "url": "",
        "dependency": "",
        "cve": "",
        "vulnerable_version": "",
        "evidence": extra.get("message", ""),
        "code_snippet": extra.get("lines", ""),
        "http_response": "",
        "status_code": None,
        "severity": extra.get("severity", "WARNING"),
        "confidence": extra.get("confidence", ""),
        "priority": "",
        "title": item.get("check_id", ""),
    }


def normalize_bandit(item):
    """Normaliza um achado do Bandit em evidência."""
    return {
        "id": _hash_id("bandit", item.get("test_name"), item.get("filename"), item.get("line_number")),
        "tool": "Bandit",
        "category": "SAST",
        "file": item.get("filename", ""),
        "line": item.get("line_number"),
        "function": item.get("test_name", ""),
        "endpoint": "",
        "url": "",
        "dependency": "",
        "cve": "",
        "vulnerable_version": "",
        "evidence": item.get("issue_text", ""),
        "code_snippet": item.get("code", ""),
        "http_response": "",
        "status_code": None,
        "severity": item.get("issue_severity", "LOW"),
        "confidence": item.get("issue_confidence", ""),
        "priority": "",
        "title": item.get("test_name", ""),
    }


def normalize_sca(dep_name, dep_version, vuln):
    """Normaliza uma vulnerabilidade de SCA em evidência."""
    return {
        "id": _hash_id("sca", dep_name, vuln.get("id")),
        "tool": "SCA",
        "category": "SCA",
        "file": "",
        "line": None,
        "function": "",
        "endpoint": "",
        "url": "",
        "dependency": dep_name,
        "cve": vuln.get("id", ""),
        "vulnerable_version": dep_version,
        "evidence": vuln.get("description", ""),
        "code_snippet": "",
        "http_response": "",
        "status_code": None,
        "severity": "HIGH" if "CVE" in str(vuln.get("id", "")) else "MEDIUM",
        "confidence": "Alta",
        "priority": "",
        "title": f"{dep_name} {dep_version} - {vuln.get('id', '')}",
    }


def normalize_secret(item, origin="Gitleaks"):
    """Normaliza um segredo encontrado em evidência."""
    return {
        "id": _hash_id(origin.lower(), item.get("Regra") or item.get("RuleID"), item.get("Arquivo") or item.get("File"), item.get("Linha") or item.get("StartLine")),
        "tool": origin,
        "category": "Secrets",
        "file": item.get("Arquivo") or item.get("File") or item.get("file") or "",
        "line": item.get("Linha") or item.get("StartLine") or item.get("line"),
        "function": item.get("Regra") or item.get("RuleID") or item.get("rule") or "",
        "endpoint": "",
        "url": "",
        "dependency": "",
        "cve": "",
        "vulnerable_version": "",
        "evidence": item.get("Descrição") or item.get("Description") or item.get("description") or "Segredo detectado",
        "code_snippet": "",
        "http_response": "",
        "status_code": None,
        "severity": "HIGH",
        "confidence": "Alta",
        "priority": item.get("Prioridade", "Alta"),
        "title": item.get("Regra") or item.get("RuleID") or "Segredo",
    }


def normalize_url_finding(item):
    """Normaliza um achado de URL Analysis em evidência."""
    sev_map = {"Alta": "HIGH", "Média": "MEDIUM", "Baixa": "LOW"}
    return {
        "id": _hash_id("url", item.get("Categoria"), item.get("Item"), item.get("Status")),
        "tool": "URL Analysis",
        "category": item.get("Categoria", "URL"),
        "file": "",
        "line": None,
        "function": "",
        "endpoint": item.get("Item", ""),
        "url": item.get("URL", ""),
        "dependency": "",
        "cve": "",
        "vulnerable_version": "",
        "evidence": item.get("Descrição", ""),
        "code_snippet": "",
        "http_response": item.get("Evidências", ""),
        "status_code": None,
        "severity": sev_map.get(item.get("Prioridade", "Baixa"), "LOW"),
        "confidence": "Média",
        "priority": item.get("Prioridade", "Baixa"),
        "title": f"{item.get('Categoria', '')} - {item.get('Item', '')}",
    }


def build_evidence_store(semgrep_data=None, bandit_data=None, sca_data=None,
                         secrets_data=None, url_findings=None):
    """
    Constrói a lista unificada de evidências a partir de todas as ferramentas.

    Parâmetros
    ----------
    semgrep_data : dict
        JSON do Semgrep ({"results": [...]}).
    bandit_data : dict
        JSON do Bandit ({"results": [...]}).
    sca_data : dict
        JSON do SCA ({"dependencies": [{"name", "version", "vulns": [...]}]}).
    secrets_data : list
        Lista de segredos (formato interno ou Gitleaks).
    url_findings : list
        Lista de findings de URL Analysis.

    Retorna
    -------
    list[dict]
        Lista de evidências normalizadas.
    """
    evidences = []

    if semgrep_data:
        for item in semgrep_data.get("results") or []:
            if isinstance(item, dict):
                evidences.append(normalize_semgrep(item))

    if bandit_data:
        for item in bandit_data.get("results") or []:
            if isinstance(item, dict):
                evidences.append(normalize_bandit(item))

    if sca_data:
        for dep in sca_data.get("dependencies") or []:
            if not isinstance(dep, dict):
                continue
            name = dep.get("name", "")
            version = dep.get("version", "")
            for vuln in dep.get("vulns") or []:
                if isinstance(vuln, dict):
                    evidences.append(normalize_sca(name, version, vuln))

    if secrets_data:
        for item in secrets_data:
            if isinstance(item, dict):
                evidences.append(normalize_secret(item))

    if url_findings:
        for item in url_findings:
            if isinstance(item, dict):
                evidences.append(normalize_url_finding(item))

    # Enriquece cada evidência com a categoria OWASP Top 10
    from .owasp import enrich_evidences
    enriched = enrich_evidences(evidences)

    # Enriquece com contexto de arquivo e candidatos a falso positivo
    return enrich_evidence_context(enriched)


# ──────────────────────────────────────────────
# Contexto de arquivo e falsos positivos
# ──────────────────────────────────────────────

# Marcadores de path que indicam código de teste/fixture (aprendizado
# do estudo de caso DefectDojo: 85 chaves PGP "vazadas" estavam em
# fixtures de teste de parsers).
TEST_PATH_MARKERS = (
    "test", "unittests", "fixtures", "spec", "tests/",
    "test_", "_test", "conftest", "mock", "sample", "examples",
)

# Marcadores de função/texto que indicam uso não-criptográfico de hashes
# (ex.: hash para chave de deduplicação — o Bandit sinaliza hashlib.md5
# mesmo quando o hash não protege segredo algum).
HASH_NON_SECURITY_MARKERS = (
    "dupe", "duplicate", "dedup", "fingerprint", "cache_key",
    "cachekey", "checksum", "hash_key", "_key", "id_key",
)


def is_test_file(file_path):
    """
    Detecta se um caminho de arquivo pertence a código de teste/fixture.

    Baseado no estudo real do DefectDojo, onde dezenas de "segredos"
    eram na verdade fixtures de teste de parsers.
    """
    path = str(file_path or "").replace("\\", "/").lower()
    return any(marker in path for marker in TEST_PATH_MARKERS)


def detect_fp_candidate(evidence):
    """
    Heurísticas de falso positivo por contexto.

    Retorna
    -------
    tuple (bool, str)
        (é_candidato, motivo). Motivo vazio = não é candidato.
    """
    tool = str(evidence.get("tool", "")).lower()
    title = str(evidence.get("title", "")).lower()
    function = str(evidence.get("function", "")).lower()
    evidence_text = str(evidence.get("evidence", "")).lower()
    file_path = str(evidence.get("file", "")).lower()
    category = str(evidence.get("category", "")).lower()
    code = str(evidence.get("code_snippet", "")).lower()

    combined = " ".join([title, function, evidence_text, code])

    # 1. Hash usado para deduplicação/chave (não criptografia)
    if ("hashlib" in combined or "md5" in combined or "sha1" in combined):
        for marker in HASH_NON_SECURITY_MARKERS:
            if marker in combined:
                return True, "Hash usado para chave/deduplicação, não para criptografia"

    # 2. Bind em 0.0.0.0 dentro de parsers de dados (não é serviço de rede)
    if "0.0.0.0" in combined and ("parser" in file_path or "parser" in category or "import" in title):
        return True, "Bind 0.0.0.0 em parser/integração de dados, não em serviço exposto"

    # 3. Segredos em arquivos de teste/fixture
    if is_test_file(evidence.get("file")):
        return True, "Arquivo de teste/fixture (provável dado simulado)"

    # 4. mark_safe em widgets/forms (HTML gerado pelo framework, escapado)
    if "mark_safe" in combined and ("form" in file_path or "widget" in file_path):
        return True, "mark_safe em form/widget com HTML gerado pelo framework"

    return False, ""


def enrich_evidence_context(evidences):
    """
    Adiciona contexto de arquivo, candidatos a falso positivo e descrições
    humanizadas (pt-BR) a cada evidência.

    Campos adicionados:
    - in_test_file (bool): achado em código de teste/fixture
    - fp_candidate (bool): provável falso positivo por contexto
    - fp_reason (str): motivo da heurística
    - title_pt (str): título legível em português
    - evidence_pt (str): descrição legível em português
    """
    from .mensagens_pt import humanize

    enriched = []
    for ev in evidences:
        ev = dict(ev)
        ev["in_test_file"] = is_test_file(ev.get("file"))
        candidate, reason = detect_fp_candidate(ev)
        ev["fp_candidate"] = candidate
        ev["fp_reason"] = reason
        title_pt, evidence_pt = humanize(
            ev.get("tool"), ev.get("title"), ev.get("evidence")
        )
        ev["title_pt"] = title_pt
        ev["evidence_pt"] = evidence_pt
        enriched.append(ev)
    return enriched


# Compatibilidade: contagem considerando contexto (ignora FPs prováveis)
def count_by_severity_active(evidences):
    """Conta severidade ignorando candidatos a falso positivo por contexto."""
    active = [e for e in evidences if not e.get("fp_candidate")]
    return count_by_severity(active), len(evidences) - len(active)


def count_by_tool(evidences):
    """Conta evidências por ferramenta."""
    from collections import Counter
    return dict(Counter(e["tool"] for e in evidences))


def count_by_severity(evidences):
    """Conta evidências por severidade (Alta/Média/Baixa)."""
    sev = {"Alta": 0, "Média": 0, "Baixa": 0}
    for e in evidences:
        s = str(e.get("severity", "")).upper()
        if s in ("CRITICAL", "HIGH", "ERROR"):
            sev["Alta"] += 1
        elif s in ("MEDIUM", "WARNING"):
            sev["Média"] += 1
        else:
            sev["Baixa"] += 1
    return sev
