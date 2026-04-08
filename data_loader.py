# -*- coding: utf-8 -*-
"""Загрузка JSON/YAML и вспомогательные пути (в т.ч. PyInstaller)."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from core.models import CompanyData

logger = logging.getLogger(__name__)


def get_resource_path(relative_path: str, base_dir: Path | None = None) -> Path:
    """Путь к ресурсу относительно каталога приложения или ``sys._MEIPASS``.

    Args:
        relative_path: Относительный путь (например, ``config/settings.yaml``).
        base_dir: Явная база (корень ``threat_modeling_engine``). Если None — авто.

    Returns:
        Абсолютный ``Path``.
    """
    if base_dir is not None:
        return (base_dir / relative_path).resolve()
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / relative_path  # type: ignore[attr-defined]
    # каталог пакета: родитель от core/
    engine_root = Path(__file__).resolve().parent.parent
    return (engine_root / relative_path).resolve()


def load_yaml_file(path: Path) -> dict[str, Any]:
    """Загружает YAML в словарь."""
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return data


def load_json_file(path: Path) -> Any:
    """Загружает JSON."""
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_company_json(text: str) -> CompanyData:
    """Парсит JSON из строки (для вставки в GUI).

    Args:
        text: Текст JSON.

    Returns:
        ``CompanyData``.

    Raises:
        json.JSONDecodeError: Невалидный JSON.
        ValidationError: Ошибка Pydantic.
    """
    raw = json.loads(text)
    try:
        return CompanyData.model_validate(raw)
    except ValidationError:
        logger.exception("Company data validation failed (pasted JSON)")
        raise


def load_company_data(path: Path) -> CompanyData:
    """Загружает и валидирует ``company_data.json``.

    Args:
        path: Путь к JSON.

    Returns:
        Экземпляр ``CompanyData``.

    Raises:
        ValidationError: Ошибка схемы Pydantic.
        OSError: Файл не найден.
    """
    raw = load_json_file(path)
    try:
        return CompanyData.model_validate(raw)
    except ValidationError:
        logger.exception("Company data validation failed for %s", path)
        raise


def load_settings(engine_root: Path | None = None) -> dict[str, Any]:
    """Настройки движка из ``config/settings.yaml``."""
    p = get_resource_path("config/settings.yaml", engine_root)
    return load_yaml_file(p)


def load_matrix_display(engine_root: Path | None = None) -> dict[str, Any]:
    """Подписи и шаблоны для HTML-матрицы сценария."""
    settings = load_settings(engine_root)
    rel = (settings.get("paths") or {}).get("matrix_display", "config/matrix_display.yaml")
    return load_yaml_file(get_resource_path(str(rel), engine_root))


def load_validation_config(
    path: str | Path | None = None, engine_root: Path | None = None
) -> dict[str, Any]:
    """Конфигурация валидации."""
    if path is not None:
        return load_yaml_file(Path(path))
    settings = load_settings(engine_root)
    rel = (
        settings.get("paths", {}) or {}
    ).get("validation_config", "config/validation_config.yaml")
    return load_yaml_file(get_resource_path(str(rel), engine_root))
