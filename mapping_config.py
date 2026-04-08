# -*- coding: utf-8 -*-
"""ФСТЭК ↔ MITRE маппинги и справочники уровней нарушителей.

Все идентификаторы тактик/УБИ задаются здесь; организационные данные не хранятся.
"""

from __future__ import annotations

UBI_TO_TACTIC_MAPPING: dict[str, dict] = {
    "УБИ.1": {"tactics": ["Т9", "Т10.1"], "description": "Утечка информации"},
    "УБИ.2": {"tactics": ["Т10.1", "Т10.2"], "description": "НСД"},
    "УБИ.3": {"tactics": ["Т10.3", "Т10.4"], "description": "Модификация"},
    "УБИ.4": {"tactics": ["Т10.7"], "description": "Подмена"},
    "УБИ.5": {"tactics": ["Т10.8"], "description": "Удаление"},
    "УБИ.6": {"tactics": ["Т10.10"], "description": "Отказ в обслуживании"},
    "УБИ.7": {"tactics": ["Т10.11"], "description": "Нецелевое использование"},
    "УБИ.8": {"tactics": ["Т10.12", "Т10.13"], "description": "Нарушение функционирования"},
    "УБИ.9": {"tactics": ["Т10.4"], "description": "Недостоверный источник"},
    "УБИ.10": {"tactics": ["Т10.9"], "description": "Противоправная информация"},
    "УБИ.11": {"tactics": ["Т1", "Т9"], "description": "Массовый сбор"},
}

FSTEC_TO_MITRE_MAPPING: dict[str, dict] = {
    "Т1": {
        "mitre_tactic": "TA0043 (Reconnaissance)",
        "techniques": ["T1595", "T1592", "T1046"],
    },
    "Т2": {
        "mitre_tactic": "TA0001 (Initial Access)",
        "techniques": ["T1190", "T1566", "T1078"],
    },
    "Т3": {
        "mitre_tactic": "TA0002 (Execution)",
        "techniques": ["T1059", "T1053", "T1059.001"],
    },
    "Т4": {
        "mitre_tactic": "TA0003 (Persistence)",
        "techniques": ["T1136", "T1547", "T1543"],
    },
    "Т5": {
        "mitre_tactic": "TA0011 (Command and Control)",
        "techniques": ["T1071", "T1573", "T1572"],
    },
    "Т6": {
        "mitre_tactic": "TA0004 (Privilege Escalation)",
        "techniques": ["T1068", "T1548", "T1134"],
    },
    "Т7": {
        "mitre_tactic": "TA0005 (Defense Evasion)",
        "techniques": ["T1070", "T1027", "T1036"],
    },
    "Т8": {
        "mitre_tactic": "TA0008 (Lateral Movement)",
        "techniques": ["T1021", "T1563", "T1076"],
    },
    "Т9": {
        "mitre_tactic": "TA0010 (Exfiltration)",
        "techniques": ["T1041", "T1048", "T1567"],
    },
    "Т10": {
        "mitre_tactic": "TA0040 (Impact)",
        "techniques": ["T1489", "T1486", "T1565"],
    },
}

ATTACKER_LEVELS: dict[str, dict] = {
    "Н1": {
        "complexity": "low",
        "tools": "public_scripts",
        "knowledge": "basic_user",
        "description": "Базовые возможности",
    },
    "Н2": {
        "complexity": "medium",
        "tools": "frameworks",
        "knowledge": "practical",
        "description": "Базовые повышенные",
    },
    "Н3": {
        "complexity": "high",
        "tools": "custom",
        "knowledge": "advanced",
        "description": "Средние возможности",
    },
    "Н4": {
        "complexity": "very_high",
        "tools": "zero_day",
        "knowledge": "expert",
        "description": "Высокие возможности",
    },
}

ATTACKER_TYPES: dict[str, dict] = {
    "Преступные группы": {"category": "External/Internal", "levels": ["Н2", "Н3"]},
    "Отдельные физические лица (хакеры)": {
        "category": "External",
        "levels": ["Н1", "Н2"],
    },
    "Конкурирующие организации": {"category": "External", "levels": ["Н2", "Н3"]},
    "Разработчики ПО": {"category": "Internal", "levels": ["Н2", "Н3"]},
    "Поставщики услуг": {"category": "Internal", "levels": ["Н1", "Н2"]},
    "Авторизованные пользователи": {"category": "Internal", "levels": ["Н1", "Н2"]},
    "Системные администраторы": {"category": "Internal", "levels": ["Н2", "Н3"]},
    "Бывшие работники": {"category": "External", "levels": ["Н1", "Н2"]},
}

# Минимальный уровень нарушителя для тактики (для фильтра уровня).
TACTIC_MIN_ATTACKER_LEVEL: dict[str, str] = {
    "Т1": "Н1",
    "Т2": "Н1",
    "Т3": "Н1",
    "Т4": "Н2",
    "Т5": "Н2",
    "Т6": "Н2",
    "Т7": "Н2",
    "Т8": "Н3",
    "Т9": "Н2",
    "Т10": "Н1",
}

_LEVEL_ORDER = {"Н1": 1, "Н2": 2, "Н3": 3, "Н4": 4}


def normalize_fstec_tactic(tactic: str) -> str:
    """Сопоставляет подтактики Т10.x с родительской тактикой Т10 для MITRE.

    Args:
        tactic: Код тактики ФСТЭК (например, ``Т10.1`` или ``Т9``).

    Returns:
        Ключ из ``FSTEC_TO_MITRE_MAPPING`` (родитель для подтактик Т10.*).
    """
    if tactic.startswith("Т10."):
        return "Т10"
    return tactic


def tactic_min_level_rank(tactic: str) -> int:
    """Числовой ранг минимального уровня для тактики (после нормализации)."""
    parent = normalize_fstec_tactic(tactic)
    lvl = TACTIC_MIN_ATTACKER_LEVEL.get(parent, "Н1")
    return _LEVEL_ORDER.get(lvl, 1)


def attacker_level_rank(level: str) -> int:
    """Числовой ранг уровня нарушителя."""
    return _LEVEL_ORDER.get(level, 1)


def level_allows_tactic(attacker_level: str, tactic: str) -> bool:
    """True, если уровень нарушителя не ниже требуемого для тактики."""
    return attacker_level_rank(attacker_level) >= tactic_min_level_rank(tactic)
