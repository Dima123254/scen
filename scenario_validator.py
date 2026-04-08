# -*- coding: utf-8 -*-
"""Валидатор сценариев: фильтры уровня, топологии, УБИ, интерфейсов."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from config.attacker_level_mapping import level_allows_fstec_technique
from config.mapping_config import UBI_TO_TACTIC_MAPPING, level_allows_tactic
from core.models import Asset, Attacker, CompanyData, ZoneEnum


@dataclass
class FilterResult:
    """Результат применения одного фильтра к сценарию."""

    passed: bool
    filter_name: str
    reason: str


@dataclass
class ScenarioValidationReport:
    """Сводка по сценарию после всех фильтров."""

    scenario_id: str
    results: list[FilterResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results)


class ScenarioValidator:
    """Независимые проверки; состав задаётся ``filter_engine``."""

    def __init__(self, company: CompanyData, validation_config: dict[str, Any]) -> None:
        self._company = company
        self._cfg = validation_config
        self._ext_defaults: list[str] = list(
            (validation_config.get("default_external_interfaces") or [])
        )
        self._int_defaults: list[str] = list(
            (validation_config.get("default_internal_interfaces") or [])
        )

    def _asset_by_id(self, asset_id: str) -> Asset | None:
        for a in self._company.assets:
            if a.id == asset_id:
                return a
        return None

    def _check_attacker_level(self, scenario: dict[str, Any]) -> FilterResult:
        """Уровень нарушителя vs тактики цепочки и техники Приложения 11."""
        name = "level"
        level = str(scenario.get("attacker", {}).get("level", ""))
        fstec_block = scenario.get("fstec_techniques_by_tactic") or {}
        if fstec_block:
            for _tac, items in fstec_block.items():
                for item in items or []:
                    tid = item.get("id") if isinstance(item, dict) else str(item)
                    if not level_allows_fstec_technique(level, tid):
                        return FilterResult(
                            passed=False,
                            filter_name=name,
                            reason=(
                                f"Уровень {level} не допускает технику {tid} "
                                f"(Приложение 8 / маппинг уровней)."
                            ),
                        )
            return FilterResult(passed=True, filter_name=name, reason="OK (ФСТЭК-техники)")

        chain = list(scenario.get("tactic_chain") or [])
        for t in chain:
            if not level_allows_tactic(level, t):
                return FilterResult(
                    passed=False,
                    filter_name=name,
                    reason=(
                        f"Уровень {level} недостаточен для тактики {t} "
                        f"(требуется более высокий уровень по методике)."
                    ),
                )
        return FilterResult(passed=True, filter_name=name, reason="OK")

    def _check_topology(self, scenario: dict[str, Any]) -> FilterResult:
        """Внешний нарушитель не должен достигать Internal без участия DMZ на пути."""
        name = "topology"
        cat = scenario.get("attacker", {}).get("category", "")
        if cat == "Internal" or cat == "External/Internal":
            return FilterResult(passed=True, filter_name=name, reason="OK (internal category)")

        asset_id = scenario.get("asset", {}).get("id")
        target = self._asset_by_id(str(asset_id)) if asset_id else None
        if not target or target.zone != ZoneEnum.INTERNAL:
            return FilterResult(passed=True, filter_name=name, reason="OK (target not Internal)")

        ext_ids = {a.id for a in self._company.assets if a.zone == ZoneEnum.EXTERNAL}
        if not ext_ids:
            return FilterResult(
                passed=True,
                filter_name=name,
                reason="OK (no External assets in model — check skipped)",
            )

        graph: dict[str, list[str]] = {a.id: [] for a in self._company.assets}
        for link in self._company.topology:
            graph.setdefault(link.from_, []).append(link.to)
            graph.setdefault(link.to, []).append(link.from_)

        from collections import deque

        bad_path = False
        reachable_internal = False
        for start in ext_ids:
            queue: deque[tuple[str, bool]] = deque([(start, False)])
            visited_states: set[tuple[str, bool]] = set()
            while queue:
                node, saw_dmz = queue.popleft()
                key = (node, saw_dmz)
                if key in visited_states:
                    continue
                visited_states.add(key)
                node_asset = self._asset_by_id(node)
                if node_asset and node_asset.zone == ZoneEnum.DMZ:
                    saw_dmz = True
                if node == target.id:
                    reachable_internal = True
                    if not saw_dmz:
                        bad_path = True
                        break
                for nb in graph.get(node, []):
                    queue.append((nb, saw_dmz))
            if bad_path:
                break

        if bad_path:
            return FilterResult(
                passed=False,
                filter_name=name,
                reason=(
                    "Внешний нарушитель: существует путь к Internal-активу "
                    "без прохождения DMZ (нарушение периметра)."
                ),
            )
        if not reachable_internal:
            return FilterResult(
                passed=True,
                filter_name=name,
                reason="OK (нет пути External→Internal в топологии)",
            )
        return FilterResult(passed=True, filter_name=name, reason="OK")

    def _check_ubi_consistency(self, scenario: dict[str, Any]) -> FilterResult:
        """Финальная тактика цепочки должна соответствовать ожидаемым для УБИ."""
        name = "ubi"
        ubi = str(scenario.get("ubi", ""))
        chain = list(scenario.get("tactic_chain") or [])
        if not chain:
            return FilterResult(
                passed=False, filter_name=name, reason="Пустая цепочка тактик."
            )
        expected = [str(x) for x in (UBI_TO_TACTIC_MAPPING.get(ubi, {}).get("tactics") or [])]
        if not expected:
            return FilterResult(
                passed=False,
                filter_name=name,
                reason=f"Неизвестный или неподдерживаемый УБИ: {ubi}",
            )
        last = chain[-1]
        exp_set = set(expected)
        if last in exp_set:
            return FilterResult(passed=True, filter_name=name, reason="OK")
        if last.startswith("Т10.") and any(e.startswith("Т10.") for e in expected):
            return FilterResult(passed=True, filter_name=name, reason="OK")
        if last == "Т10" and any(e.startswith("Т10.") for e in expected):
            return FilterResult(passed=True, filter_name=name, reason="OK")
        if "Т9" in exp_set and last == "Т10" and "Т9" in chain:
            return FilterResult(passed=True, filter_name=name, reason="OK (эксфильтрация перед Т10)")
        return FilterResult(
            passed=False,
            filter_name=name,
            reason=(
                f"Финальная тактика {last} не согласована с УБИ {ubi}; "
                f"ожидаются тактики из карты УБИ: {expected}."
            ),
        )

    def _effective_attacker_interfaces(self, scenario: dict[str, Any]) -> set[str]:
        raw = scenario.get("attacker", {}).get("interfaces") or []
        cat = scenario.get("attacker", {}).get("category", "")
        if raw:
            return {str(x).lower() for x in raw}
        if cat == "Internal" or cat == "External/Internal":
            return {str(x).lower() for x in self._int_defaults}
        return {str(x).lower() for x in self._ext_defaults}

    def _check_interface_access(self, scenario: dict[str, Any]) -> FilterResult:
        """Интерфейсы актива должны пересекаться с доступными нарушителю."""
        name = "interface"
        asset_if = scenario.get("asset", {}).get("interfaces") or []
        if not asset_if:
            return FilterResult(
                passed=True,
                filter_name=name,
                reason="OK (у актива не заданы интерфейсы — проверка пропущена)",
            )
        eff = self._effective_attacker_interfaces(scenario)
        asset_set = {str(x).lower() for x in asset_if}
        if eff & asset_set:
            return FilterResult(passed=True, filter_name=name, reason="OK")
        return FilterResult(
            passed=False,
            filter_name=name,
            reason=(
                f"Нет пересечения интерфейсов нарушителя {sorted(eff)} "
                f"с интерфейсами актива {sorted(asset_set)}."
            ),
        )

    def validate_one(
        self,
        scenario: dict[str, Any],
        enabled_filters: list[str] | None = None,
    ) -> ScenarioValidationReport:
        """Запускает все включённые фильтры.

        Args:
            scenario: Словарь сценария.
            enabled_filters: Имена: level, topology, ubi, interface.

        Returns:
            ``ScenarioValidationReport``.
        """
        sid = str(scenario.get("scenario_id", "unknown"))
        report = ScenarioValidationReport(scenario_id=sid)
        all_filters = {
            "level": self._check_attacker_level,
            "topology": self._check_topology,
            "ubi": self._check_ubi_consistency,
            "interface": self._check_interface_access,
        }
        keys = enabled_filters or list(all_filters.keys())
        for k in keys:
            fn = all_filters.get(k)
            if fn:
                report.results.append(fn(scenario))
        return report
