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
Correlação de riscos entre ferramentas (camada ASPM).

Cruza achados de Semgrep, Bandit, SCA, Secrets e URL Analysis para
gerar riscos compostos. Quando o ativo é de criticidade Alta/Crítica,
a prioridade de cada correlação sobe um nível.

Função pura (depende apenas de pandas) — não usa Streamlit.
"""


def correlate_findings(
    semgrep_df,
    bandit_df,
    sca_df,
    secrets_df,
    url_findings,
    asset_name="Geral",
    asset_criticidade="Média",
):
    """
    Correlaciona achados entre ferramentas.
    Se o ativo for de criticidade Alta/Crítica, a prioridade sobe.
    """
    correlacoes = []
    criticidade_boost = asset_criticidade in ("Alta", "Crítica")

    def boost(p, boost_active):
        if not boost_active:
            return p
        return {
            "Baixa": "Média",
            "Média": "Alta",
            "Alta": "Crítica",
            "Crítica": "Crítica",
        }.get(p, p)

    # 1. Segredos + qualquer achado SAST
    if not secrets_df.empty and (not semgrep_df.empty or not bandit_df.empty):
        p = boost("Alta", criticidade_boost)
        correlacoes.append(
            {
                "risco": f"[{asset_name}] Código com segredos expostos e vulnerabilidades ativas",
                "evidencias": f"{len(secrets_df)} segredo(s) + {len(semgrep_df) + len(bandit_df)} achado(s) SAST",
                "prioridade": p,
                "acao": "Remover segredos do código antes de corrigir vulnerabilidades",
                "ativo": asset_name,
            }
        )

    # 2. SCA crítico + segredos
    if not sca_df.empty and not secrets_df.empty:
        sca_altas = (
            len(sca_df[sca_df["Prioridade"] == "Alta"])
            if "Prioridade" in sca_df.columns
            else 0
        )
        if sca_altas > 0:
            p = boost("Alta", criticidade_boost)
            correlacoes.append(
                {
                    "risco": f"[{asset_name}] Dependências vulneráveis + credenciais expostas",
                    "evidencias": f"{sca_altas} CVE(s) crítica(s) + {len(secrets_df)} segredo(s)",
                    "prioridade": p,
                    "acao": "Atualizar dependências críticas e rodar Gitleaks no repositório",
                    "ativo": asset_name,
                }
            )

    # 3. URL: endpoint exposto + segredo
    if url_findings:
        expostos = [
            f
            for f in url_findings
            if f.get("Status") in ["Expõe", "Expõe recurso"]
            or f.get("Prioridade") == "Alta"
        ]
        if expostos and not secrets_df.empty:
            p = boost("Crítica", criticidade_boost)
            correlacoes.append(
                {
                    "risco": f"[{asset_name}] Endpoint exposto com credenciais no repositório",
                    "evidencias": f"{len(expostos)} endpoint(s) exposto(s) + {len(secrets_df)} segredo(s)",
                    "prioridade": p,
                    "acao": "Revisar acesso ao endpoint e rodar scan de segredos imediatamente",
                    "ativo": asset_name,
                }
            )

    # 4. Múltiplas fontes = postura fragilizada
    fontes_com_achados = sum(
        [
            not semgrep_df.empty,
            not bandit_df.empty,
            not sca_df.empty,
            not secrets_df.empty,
            bool(url_findings),
        ]
    )
    if fontes_com_achados >= 3:
        total = (
            len(semgrep_df)
            + len(bandit_df)
            + len(sca_df)
            + len(secrets_df)
            + len(url_findings)
        )
        if total > 5:
            p = boost("Alta", criticidade_boost)
            correlacoes.append(
                {
                    "risco": f"[{asset_name}] Postura fragilizada em {fontes_com_achados} camadas",
                    "evidencias": f"{fontes_com_achados} fontes com achados - {total} no total",
                    "prioridade": p,
                    "acao": "Remediação por prioridade: segredos > SAST > SCA > Hardening",
                    "ativo": asset_name,
                }
            )

    # 5. Ativo crítico com qualquer achado real
    if criticidade_boost:
        total_achados = len(semgrep_df) + len(bandit_df) + len(sca_df) + len(secrets_df)
        if total_achados > 0:
            correlacoes.append(
                {
                    "risco": f"[{asset_name}] Ativo de criticidade {asset_criticidade} com {total_achados} achado(s)",
                    "evidencias": f"Ativo {asset_criticidade} requer atenção prioritária em todos os achados",
                    "prioridade": boost("Média", criticidade_boost),
                    "acao": "Revisar todos os achados deste ativo com prioridade máxima",
                    "ativo": asset_name,
                }
            )

    return correlacoes
