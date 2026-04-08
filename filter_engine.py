# -*- coding: utf-8 -*-
"""Движок фильтров: чтение validation_config и отчёт по сценариям."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from core.models import CompanyData
from validation.scenario_validator import FilterResult, ScenarioValidator


class FilterStrategy(ABC):
    """Расширяемая стратегия фильтрации (заготовка для плагинов)."""

    @abstractmethod
    def name(self) -> str:
        """Имя стратегии."""

    @abstractmethod
    def validate(self, scenario: dict[str, Any], context: dict[str, Any]) -> FilterResult:
        """Проверка сценария."""


@dataclass
class FilterEngineReport:
    """Итог применения фильтров к набору сценариев."""

    per_scenario: list[dict[str, Any]] = field(default_factory=list)
    summary_by_filter: dict[str, dict[str, int]] = field(default_factory=dict)
    messages: list[str] = field(default_factory=list)


class FilterEngine:
    """Применяет фильтры из ``validation_config.yaml`` к списку сценариев."""

    FILTER_KEYS = ("level", "topology", "ubi", "interface")

    def __init__(
        self,
        company: CompanyData,
        validation_config: dict[str, Any],
    ) -> None:
        self._company = company
        self._cfg = validation_config
        self._validator = ScenarioValidator(company, validation_config)

    def _enabled_filter_names(self) -> list[str]:
        out: list[str] = []
        if self._cfg.get("enable_level_check", True):
            out.append("level")
        if self._cfg.get("enable_topology_check", True):
            out.append("topology")
        if self._cfg.get("enable_ubi_consistency", True):
            out.append("ubi")
        if self._cfg.get("enable_interface_check", True):
            out.append("interface")
        return out

    def run(
        self,
        scenarios: list[dict[str, Any]],
        filter_subset: list[str] | None = None,
    ) -> FilterEngineReport:
        """Прогон всех сценариев.

        Args:
            scenarios: Список словарей сценариев.
            filter_subset: Если задан — только эти имена фильтров.

        Returns:
            ``FilterEngineReport`` с детализацией по каждому сценарию и фильтру.
        """
        enabled = filter_subset if filter_subset is not None else self._enabled_filter_names()
        report = FilterEngineReport()
        summary: dict[str, dict[str, int]] = {k: {"passed": 0, "failed": 0} for k in enabled}

        for sc in scenarios:
            rep = self._validator.validate_one(sc, enabled_filters=enabled)
            row: dict[str, Any] = {
                "scenario_id": rep.scenario_id,
                "all_passed": rep.all_passed,
                "filters": [],
            }
            for fr in rep.results:
                row["filters"].append(
                    {
                        "name": fr.filter_name,
                        "passed": fr.passed,
                        "reason": fr.reason,
                    }
                )
                bucket = summary.setdefault(fr.filter_name, {"passed": 0, "failed": 0})
                if fr.passed:
                    bucket["passed"] += 1
                else:
                    bucket["failed"] += 1
            report.per_scenario.append(row)

        report.summary_by_filter = summary
        return report
