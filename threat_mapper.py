# -*- coding: utf-8 -*-
"""Маппинг УБИ ФСТЭК → тактики → техники MITRE."""

from __future__ import annotations

from typing import Any

from config.mapping_config import (
    FSTEC_TO_MITRE_MAPPING,
    UBI_TO_TACTIC_MAPPING,
    normalize_fstec_tactic,
)


def ubi_tactics(ubi: str) -> list[str]:
    """Тактики ФСТЭК, соответствующие коду УБИ."""
    entry = UBI_TO_TACTIC_MAPPING.get(ubi)
    if not entry:
        return []
    return list(entry["tactics"])


def ubi_description(ubi: str) -> str:
    """Текстовое описание УБИ из справочника."""
    entry = UBI_TO_TACTIC_MAPPING.get(ubi)
    if not entry:
        return ""
    return str(entry.get("description", ""))


def fstec_to_mitre(tactic: str) -> dict[str, Any]:
    """Сопоставление тактики ФСТЭК с блоком MITRE (родитель Т10.* → Т10)."""
    key = normalize_fstec_tactic(tactic)
    return dict(FSTEC_TO_MITRE_MAPPING.get(key, {}))


def mitre_techniques_for_tactic(tactic: str) -> list[str]:
    """Список идентификаторов техник MITRE для тактики."""
    block = fstec_to_mitre(tactic)
    techs = block.get("techniques") or []
    return list(techs)


def mitre_tactic_name(tactic: str) -> str:
    """Название тактики MITRE для тактики ФСТЭК."""
    block = fstec_to_mitre(tactic)
    return str(block.get("mitre_tactic", ""))
