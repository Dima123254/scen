# -*- coding: utf-8 -*-
"""Построение сценариев угроз по УБИ, нарушителю и активу (ФСТЭК Прил. 11 + фильтр по уровню)."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from config.bdu_realization_methods import (
    BDU_OFFICIAL_SECTION_URL,
    pick_bdu_realization_methods_for_ubi,
)
from config.attacker_level_mapping import (
    UBI_TO_FINAL_TECHNIQUE,
    fstec_technique_parent_tactic,
    get_allowed_technique_ids,
    tactics_for_level_and_ubi,
)
from config.fstec_techniques_database import FSTEC_TACTICS_AND_TECHNIQUES
from config.mapping_config import UBI_TO_TACTIC_MAPPING, normalize_fstec_tactic
from core.models import Asset, Attacker, CompanyData
from core.threat_mapper import mitre_techniques_for_tactic, mitre_tactic_name, ubi_tactics

logger = logging.getLogger(__name__)

DEFAULT_CHAIN = ["Т1", "Т2", "Т3", "Т4", "Т5", "Т6", "Т7", "Т8", "Т9", "Т10"]


class ThreatScenarioBuilder:
    """Формирует цепочки тактик и сценарии с техниками Приложения 11 (фильтр по уровню Н1–Н4)."""

    def __init__(self, settings: dict[str, Any] | None = None) -> None:
        self._settings = settings or {}
        eng = self._settings.get("engine") or {}
        self._default_chain: list[str] = list(
            eng.get("default_tactic_chain") or DEFAULT_CHAIN
        )
        self._merge_ubi = bool(eng.get("merge_ubi_tactics_into_chain", True))
        self._dedupe = bool(eng.get("deduplicate_tactics", True))
        self._id_prefix = str((self._settings.get("scenarios") or {}).get("id_prefix", "SCN"))
        self.techniques_db = FSTEC_TACTICS_AND_TECHNIQUES

    def get_techniques_for_tactic(self, tactic: str) -> list[str]:
        """Техники MITRE для тактики (сквозное сопоставление с ATT&CK)."""
        return mitre_techniques_for_tactic(tactic)

    def _get_allowed_technique_set(self, level: str) -> set[str] | None:
        """None означает все техники (уровень Н4)."""
        ids = get_allowed_technique_ids(level)
        if ids is None:
            return None
        return set(ids)

    def _allowed_techniques_for_tactic(
        self, tactic_id: str, allowed: set[str] | None
    ) -> dict[str, str]:
        """Словарь id→название только для техник, разрешённых уровню."""
        block = self.techniques_db.get(tactic_id, {})
        all_t = dict(block.get("techniques") or {})
        if allowed is None:
            return all_t
        return {k: v for k, v in all_t.items() if k in allowed}

    def build_tactic_chain(self, ubi: str, attacker_level: str | None = None) -> list[str]:
        """Цепочка тактик с учётом УБИ и допустимых для уровня тактик."""
        level = attacker_level or "Н2"
        finals = UBI_TO_FINAL_TECHNIQUE.get(ubi, ["T10.1"])
        allowed_tac = set(tactics_for_level_and_ubi(level, finals))

        chain: list[str] = []
        seen: set[str] = set()
        for t in self._default_chain:
            if self._dedupe and t in seen:
                continue
            if t not in allowed_tac:
                continue
            seen.add(t)
            chain.append(t)

        if self._merge_ubi and ubi in UBI_TO_TACTIC_MAPPING:
            for ut in ubi_tactics(ubi):
                if ut not in chain:
                    chain.append(ut)
        return chain

    def _select_relevant_techniques(
        self,
        tactic_id: str,
        available_techniques: dict[str, str],
        ubi_id: str,
        final_techniques: list[str],
        asset: Asset,
    ) -> list[dict[str, str]]:
        """Выбор релевантных техник (не весь список)."""
        finals_here = [
            f
            for f in final_techniques
            if fstec_technique_parent_tactic(f) == tactic_id
        ]
        selected: list[dict[str, str]] = []
        if finals_here:
            for ft in finals_here:
                if ft in available_techniques:
                    selected.append({"id": ft, "name": available_techniques[ft]})
            if selected:
                return selected
            if tactic_id == "Т10":
                items = list(available_techniques.items())[:2]
                return [{"id": k, "name": v} for k, v in items]

        zone = asset.zone.value
        if tactic_id == "Т1":
            if ubi_id == "УБИ.11":
                priority = ["T1.1", "T1.2", "T1.9", "T1.12", "T1.15", "T1.4", "T1.11"]
            else:
                priority = ["T1.1", "T1.2", "T1.4", "T1.11", "T1.8", "T1.9"]
        elif tactic_id == "Т2":
            if zone == "DMZ":
                priority = ["T2.1", "T2.3", "T2.5", "T2.4", "T2.8"]
            else:
                priority = ["T2.8", "T2.10", "T2.11", "T2.1", "T2.4"]
        elif tactic_id == "Т3":
            priority = ["T3.1", "T3.4", "T3.5", "T3.3", "T3.14"]
        elif tactic_id == "Т4":
            priority = ["T4.1", "T4.2", "T4.3", "T4.5"]
        elif tactic_id == "Т5":
            priority = ["T5.1", "T5.2", "T5.3", "T5.7", "T5.6"]
        elif tactic_id == "Т6":
            priority = ["T6.1", "T6.2", "T6.3", "T6.5", "T6.7"]
        elif tactic_id == "Т7":
            priority = ["T7.1", "T7.2", "T7.3", "T7.11", "T7.17"]
        elif tactic_id == "Т8":
            priority = ["T8.2", "T8.4", "T8.3", "T8.7", "T8.8"]
        elif tactic_id == "Т9":
            priority = ["T9.1", "T9.2", "T9.3", "T9.5", "T9.8", "T9.13"]
        elif tactic_id == "Т10":
            priority = list(available_techniques.keys())[:3]
        else:
            priority = list(available_techniques.keys())[:3]

        for tech_id in priority:
            if tech_id in available_techniques:
                selected.append(
                    {"id": tech_id, "name": available_techniques[tech_id]}
                )
                if len(selected) >= 3:
                    break
        return selected

    def _build_fstec_techniques_by_tactic(
        self,
        ubi: str,
        attacker: Attacker,
        asset: Asset,
        _company: CompanyData,
    ) -> dict[str, list[dict[str, str]]]:
        level = attacker.level.value
        final_techniques = list(UBI_TO_FINAL_TECHNIQUE.get(ubi, ["T10.1"]))
        tactics_order = tactics_for_level_and_ubi(level, final_techniques)
        allowed_set = self._get_allowed_technique_set(level)
        out: dict[str, list[dict[str, str]]] = {}

        for tactic_id in tactics_order:
            avail = self._allowed_techniques_for_tactic(tactic_id, allowed_set)
            if not avail:
                continue
            picked = self._select_relevant_techniques(
                tactic_id,
                avail,
                ubi,
                final_techniques,
                asset,
            )
            if picked:
                out[tactic_id] = picked
        return out

    def build_scenario(
        self,
        ubi: str,
        attacker: Attacker,
        asset: Asset,
        company: CompanyData,
        index: int = 0,
    ) -> dict[str, Any]:
        level = attacker.level.value
        chain = self.build_tactic_chain(ubi, attacker_level=level)
        fstec_by_tactic = self._build_fstec_techniques_by_tactic(
            ubi, attacker, asset, company
        )
        bdu_realization = pick_bdu_realization_methods_for_ubi(ubi)

        techniques_by_tactic: dict[str, list[str]] = {}
        mitre_by_tactic: dict[str, str] = {}
        for t in chain:
            base = normalize_fstec_tactic(t)
            if base in fstec_by_tactic:
                techniques_by_tactic[t] = [x["id"] for x in fstec_by_tactic[base]]
            else:
                techniques_by_tactic[t] = self.get_techniques_for_tactic(t)
            mitre_by_tactic[t] = mitre_tactic_name(t)

        aid = hashlib.sha256(
            f"{attacker.type}|{attacker.level.value}|{attacker.category}".encode()
        ).hexdigest()[:8]
        scenario_id = f"{self._id_prefix}-{ubi}-{asset.id}-{aid}-{index}"

        return {
            "scenario_id": scenario_id,
            "ubi": ubi,
            "ubi_description": UBI_TO_TACTIC_MAPPING.get(ubi, {}).get("description", ""),
            "ubi_final_fstec_techniques": list(
                UBI_TO_FINAL_TECHNIQUE.get(ubi, ["T10.1"])
            ),
            "attacker": {
                "type": attacker.type,
                "level": attacker.level.value,
                "category": attacker.category,
                "goals": attacker.goals,
                "interfaces": list(attacker.interfaces),
            },
            "asset": {
                "id": asset.id,
                "name": asset.name,
                "zone": asset.zone.value,
                "interfaces": list(asset.interfaces),
                "data_types": list(asset.data_types),
            },
            "company_name": company.meta.company_name,
            "system_name": company.meta.system_name,
            "tactic_chain": chain,
            "techniques_by_tactic": techniques_by_tactic,
            "fstec_techniques_by_tactic": fstec_by_tactic,
            "bdu_realization_methods": bdu_realization,
            "bdu_realization_source_url": BDU_OFFICIAL_SECTION_URL,
            "mitre_tactic_by_fstec": mitre_by_tactic,
        }


def build_all_scenarios(
    company: CompanyData,
    builder: ThreatScenarioBuilder,
    max_per_ubi: int = 10,
) -> list[dict[str, Any]]:
    """Декартово произведение УБИ × нарушители × активы с ограничением per УБИ."""
    ubis = list(company.threats)
    scenarios: list[dict[str, Any]] = []
    for ubi in ubis:
        count = 0
        for attacker in company.attackers:
            for asset in company.assets:
                if count >= max_per_ubi:
                    logger.warning(
                        "max_scenarios_per_ubi reached for %s (%s)", ubi, max_per_ubi
                    )
                    break
                scenarios.append(
                    builder.build_scenario(ubi, attacker, asset, company, count)
                )
                count += 1
            if count >= max_per_ubi:
                break
    return scenarios
