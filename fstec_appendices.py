# -*- coding: utf-8 -*-
"""Табличные структуры приложений 6–11 методики (конфигурируемые данные)."""

from __future__ import annotations

from typing import Any

from config.mapping_config import ATTACKER_LEVELS, ATTACKER_TYPES, UBI_TO_TACTIC_MAPPING
from core.models import CompanyData
from core.threat_mapper import mitre_techniques_for_tactic, normalize_fstec_tactic


def appendix6_rows(company: CompanyData) -> list[dict[str, Any]]:
    """Приложение 6: виды нарушителя, категории, цели."""
    rows: list[dict[str, Any]] = []
    for i, a in enumerate(company.attackers, start=1):
        meta_type = ATTACKER_TYPES.get(a.type, {})
        cat = meta_type.get("category", a.category)
        goals = ", ".join(a.goals) if a.goals else "—"
        rows.append(
            {
                "№ вида": i,
                "Виды нарушителя": a.type,
                "Категории нарушителя": cat,
                "Возможные цели": goals,
            }
        )
    return rows


def appendix7_rows(company: CompanyData) -> list[dict[str, Any]]:
    """Приложение 7: ущербы (заполняются из бизнес-процессов при наличии)."""
    rows: list[dict[str, Any]] = []
    for a in company.attackers:
        rows.append(
            {
                "Виды нарушителей": a.type,
                "Ущерб физ.лицу У1": "—",
                "Ущерб юр.лицу У2": "—",
                "Ущерб государству У3": "—",
                "Соответствие рискам": ", ".join(company.threats) if company.threats else "—",
            }
        )
    return rows


def appendix8_rows() -> list[dict[str, Any]]:
    """Приложение 8: уровни возможностей."""
    rows: list[dict[str, Any]] = []
    for i, (code, info) in enumerate(ATTACKER_LEVELS.items(), start=1):
        rows.append(
            {
                "№": i,
                "Уровень возможностей": code,
                "Возможности нарушителей": info.get("description", ""),
                "Виды нарушителей": ", ".join(
                    t for t, d in ATTACKER_TYPES.items() if code in d.get("levels", [])
                ),
            }
        )
    return rows


def appendix9_rows(company: CompanyData) -> list[dict[str, Any]]:
    """Приложение 9: риски, нарушитель, категория, уровень."""
    rows: list[dict[str, Any]] = []
    n = 1
    for ubi in company.threats:
        for a in company.attackers:
            rows.append(
                {
                    "№ п/п": n,
                    "Виды риска": ubi,
                    "Виды нарушителя": a.type,
                    "Категория": a.category,
                    "Уровень возможностей": a.level.value,
                }
            )
            n += 1
    return rows


def appendix10_rows(company: CompanyData) -> list[dict[str, Any]]:
    """Приложение 10: объект воздействия, интерфейсы, способы."""
    rows: list[dict[str, Any]] = []
    n = 1
    for a in company.attackers:
        for asset in company.assets:
            ifaces = ", ".join(asset.interfaces) if asset.interfaces else "—"
            rows.append(
                {
                    "№ п/п": n,
                    "Вид нарушителя": a.type,
                    "Категория": a.category,
                    "Объект воздействия": asset.name,
                    "Доступные интерфейсы": ifaces,
                    "Способы реализации": ", ".join(company.threats) if company.threats else "—",
                }
            )
            n += 1
    return rows


def appendix11_rows() -> list[dict[str, Any]]:
    """Приложение 11: тактика ФСТЭК и основные техники MITRE."""
    from config.mapping_config import FSTEC_TO_MITRE_MAPPING

    rows: list[dict[str, Any]] = []
    for i, (tactic, block) in enumerate(FSTEC_TO_MITRE_MAPPING.items(), start=1):
        techs = ", ".join(block.get("techniques", []))
        rows.append(
            {
                "№": i,
                "Тактика": tactic,
                "Основные техники": techs,
                "MITRE tactic": block.get("mitre_tactic", ""),
            }
        )
    sub_rows: list[dict[str, Any]] = []
    seen_sub: set[str] = set()
    for ubi, meta in UBI_TO_TACTIC_MAPPING.items():
        for t in meta.get("tactics", []):
            if t in seen_sub or t in FSTEC_TO_MITRE_MAPPING:
                continue
            if t.startswith("Т10."):
                seen_sub.add(t)
                parent = normalize_fstec_tactic(t)
                techs = ", ".join(mitre_techniques_for_tactic(t))
                sub_rows.append(
                    {
                        "№": len(rows) + len(sub_rows) + 1,
                        "Тактика": t,
                        "Основные техники": techs,
                        "MITRE tactic": FSTEC_TO_MITRE_MAPPING.get(parent, {}).get(
                            "mitre_tactic", ""
                        ),
                    }
                )
    return rows + sub_rows


def build_appendix(
    number: int,
    company: CompanyData | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Возвращает имя приложения и строки таблицы.

    Args:
        number: Номер 6–11.
        company: Данные организации (обязательны для 6,7,9,10).

    Returns:
        Кортеж (заголовок, строки).

    Raises:
        ValueError: Неверный номер или отсутствуют данные.
    """
    if company is None:
        raise ValueError("company data required for appendix generation")
    m = {
        6: ("Приложение 6", appendix6_rows(company)),
        7: ("Приложение 7", appendix7_rows(company)),
        8: ("Приложение 8", appendix8_rows()),
        9: ("Приложение 9", appendix9_rows(company)),
        10: ("Приложение 10", appendix10_rows(company)),
        11: ("Приложение 11", appendix11_rows()),
    }
    if number not in m:
        raise ValueError(f"appendix must be 6-11, got {number}")
    return m[number]
