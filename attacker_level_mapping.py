# -*- coding: utf-8 -*-
"""Маппинг техник по уровням возможностей нарушителей (Приложение 8 ФСТЭК)."""

from __future__ import annotations

import re
from typing import Any

TECHNIQUES_BY_LEVEL: dict[str, dict[str, Any]] = {
    "Н1": {
        "allowed_tactics": ["Т1", "Т2", "Т3", "Т7", "Т10"],
        "allowed_techniques": [
            "T1.1",
            "T1.2",
            "T1.8",
            "T1.11",
            "T2.1",
            "T2.4",
            "T2.7",
            "T2.8",
            "T2.10",
            "T3.1",
            "T3.3",
            "T7.1",
            "T7.2",
            "T7.3",
            "T10.1",
            "T10.7",
            "T10.8",
            "T10.9",
            "T10.11",
        ],
    },
    "Н2": {
        "allowed_tactics": ["Т1", "Т2", "Т3", "Т4", "Т5", "Т6", "Т7", "Т8", "Т9", "Т10"],
        "allowed_techniques": [
            "T1.1",
            "T1.2",
            "T1.8",
            "T1.11",
            "T2.1",
            "T2.4",
            "T2.7",
            "T2.8",
            "T2.10",
            "T3.1",
            "T3.3",
            "T7.1",
            "T7.2",
            "T7.3",
            "T10.1",
            "T10.7",
            "T10.8",
            "T10.9",
            "T10.11",
            "T1.3",
            "T1.4",
            "T1.5",
            "T1.6",
            "T1.7",
            "T1.9",
            "T1.12",
            "T2.3",
            "T2.5",
            "T2.9",
            "T2.11",
            "T2.13",
            "T3.4",
            "T3.5",
            "T3.6",
            "T3.14",
            "T3.15",
            "T3.16",
            "T4.1",
            "T4.2",
            "T4.3",
            "T4.5",
            "T5.1",
            "T5.2",
            "T5.3",
            "T5.6",
            "T5.7",
            "T6.1",
            "T6.2",
            "T6.3",
            "T6.5",
            "T6.6",
            "T6.7",
            "T7.4",
            "T7.6",
            "T7.10",
            "T7.11",
            "T7.12",
            "T7.13",
            "T7.17",
            "T8.2",
            "T8.3",
            "T8.4",
            "T8.7",
            "T8.8",
            "T9.1",
            "T9.2",
            "T9.3",
            "T9.5",
            "T9.7",
            "T9.8",
            "T9.12",
            "T10.2",
            "T10.3",
            "T10.4",
            "T10.10",
        ],
    },
    "Н3": {
        "allowed_tactics": ["Т1", "Т2", "Т3", "Т4", "Т5", "Т6", "Т7", "Т8", "Т9", "Т10"],
        "allowed_techniques": [
            "T1.1",
            "T1.2",
            "T1.8",
            "T1.11",
            "T2.1",
            "T2.4",
            "T2.7",
            "T2.8",
            "T2.10",
            "T3.1",
            "T3.3",
            "T7.1",
            "T7.2",
            "T7.3",
            "T10.1",
            "T10.7",
            "T10.8",
            "T10.9",
            "T10.11",
            "T1.3",
            "T1.4",
            "T1.5",
            "T1.6",
            "T1.7",
            "T1.9",
            "T1.12",
            "T2.3",
            "T2.5",
            "T2.9",
            "T2.11",
            "T2.13",
            "T3.4",
            "T3.5",
            "T3.6",
            "T3.14",
            "T3.15",
            "T3.16",
            "T4.1",
            "T4.2",
            "T4.3",
            "T4.5",
            "T5.1",
            "T5.2",
            "T5.3",
            "T5.6",
            "T5.7",
            "T6.1",
            "T6.2",
            "T6.3",
            "T6.5",
            "T6.6",
            "T6.7",
            "T7.4",
            "T7.6",
            "T7.10",
            "T7.11",
            "T7.12",
            "T7.13",
            "T7.17",
            "T8.2",
            "T8.3",
            "T8.4",
            "T8.7",
            "T8.8",
            "T9.1",
            "T9.2",
            "T9.3",
            "T9.5",
            "T9.7",
            "T9.8",
            "T9.12",
            "T10.2",
            "T10.3",
            "T10.4",
            "T10.10",
            "T1.10",
            "T1.13",
            "T1.14",
            "T1.15",
            "T1.16",
            "T2.6",
            "T2.12",
            "T2.14",
            "T3.7",
            "T3.8",
            "T3.9",
            "T3.10",
            "T3.11",
            "T3.12",
            "T3.13",
            "T4.4",
            "T4.6",
            "T4.7",
            "T5.4",
            "T5.5",
            "T5.8",
            "T5.9",
            "T5.10",
            "T5.11",
            "T5.12",
            "T5.13",
            "T6.4",
            "T6.8",
            "T6.9",
            "T7.5",
            "T7.7",
            "T7.8",
            "T7.9",
            "T7.14",
            "T7.15",
            "T7.16",
            "T7.18",
            "T7.19",
            "T7.20",
            "T7.21",
            "T8.1",
            "T8.5",
            "T8.6",
            "T9.4",
            "T9.6",
            "T9.9",
            "T9.10",
            "T9.11",
            "T9.13",
            "T9.14",
            "T10.5",
            "T10.6",
            "T10.12",
            "T10.13",
            "T10.14",
            "T10.15",
        ],
    },
    "Н4": {
        "allowed_tactics": ["Т1", "Т2", "Т3", "Т4", "Т5", "Т6", "Т7", "Т8", "Т9", "Т10"],
        "allowed_techniques": "ALL",
    },
}

UBI_TO_FINAL_TECHNIQUE: dict[str, list[str]] = {
    "УБИ.1": ["T10.1", "T9.1", "T9.2", "T9.3", "T9.5", "T9.13"],
    "УБИ.2": ["T10.1", "T10.2"],
    "УБИ.3": ["T10.3", "T10.4", "T10.7"],
    "УБИ.4": ["T10.7"],
    "УБИ.5": ["T10.8"],
    "УБИ.6": ["T10.10", "T10.12", "T10.14"],
    "УБИ.7": ["T10.11"],
    "УБИ.8": ["T10.12", "T10.13", "T10.14"],
    "УБИ.9": ["T10.7"],
    "УБИ.10": ["T10.9"],
    "УБИ.11": ["T1.1", "T1.2", "T1.9", "T1.12", "T1.15", "T10.1"],
}


def fstec_technique_parent_tactic(tech_id: str) -> str | None:
    """Сопоставляет идентификатор техники (T9.1, T10.15) с тактикой ФСТЭК (Т9, Т10)."""
    m = re.match(r"^T(\d+)\.", str(tech_id))
    if not m:
        return None
    return f"Т{m.group(1)}"


def get_allowed_technique_ids(level: str) -> list[str] | None:
    """Список разрешённых техник или None, если разрешены все (Н4)."""
    cfg = TECHNIQUES_BY_LEVEL.get(level) or TECHNIQUES_BY_LEVEL["Н2"]
    allowed = cfg.get("allowed_techniques")
    if allowed == "ALL":
        return None
    return list(allowed) if isinstance(allowed, list) else []


def all_fstec_technique_ids() -> list[str]:
    """Все идентификаторы техник из базы Приложения 11."""
    from config.fstec_techniques_database import FSTEC_TACTICS_AND_TECHNIQUES

    out: list[str] = []
    for block in FSTEC_TACTICS_AND_TECHNIQUES.values():
        out.extend((block.get("techniques") or {}).keys())
    return out


def level_allows_fstec_technique(level: str, tech_id: str) -> bool:
    """True, если техника допустима для уровня нарушителя."""
    allowed = get_allowed_technique_ids(level)
    if allowed is None:
        return True
    return str(tech_id) in allowed


def tactics_for_level_and_ubi(level: str, final_techniques: list[str]) -> list[str]:
    """Упорядоченный список тактик Т1–Т10 с учётом уровня и финальных техник УБИ."""
    base_order = [f"Т{i}" for i in range(1, 11)]
    cfg = TECHNIQUES_BY_LEVEL.get(level) or TECHNIQUES_BY_LEVEL["Н2"]
    tactics_set = set(cfg.get("allowed_tactics") or base_order)
    for ft in final_techniques:
        p = fstec_technique_parent_tactic(ft)
        if p:
            tactics_set.add(p)
    return [t for t in base_order if t in tactics_set]
