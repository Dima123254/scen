# -*- coding: utf-8 -*-
"""Интерактивные графы атак на базе pyvis."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    from pyvis.network import Network
except ImportError:  # pragma: no cover
    Network = None  # type: ignore[misc, assignment]


class GraphVisualizer:
    """Узлы: нарушитель, тактики, техники, активы, УБИ; рёбра с подписями."""

    def __init__(self, height: str = "600px", width: str = "100%") -> None:
        self._height = height
        self._width = width

    def create_attack_graph(self, scenario: dict[str, Any]) -> Any:
        """Строит ``pyvis.network.Network`` для одного сценария.

        Args:
            scenario: Словарь с ``attacker``, ``asset``, ``tactic_chain``,
                ``techniques_by_tactic``, ``ubi``.

        Returns:
            Объект Network или None при отсутствии pyvis.

        Raises:
            RuntimeError: pyvis не установлен.
        """
        if Network is None:
            raise RuntimeError("Пакет pyvis не установлен; выполните pip install pyvis")
        net = Network(height=self._height, width=self._width, directed=True, bgcolor="#ffffff")
        att = scenario.get("attacker", {})
        asset = scenario.get("asset", {})
        ubi = str(scenario.get("ubi", ""))
        sid = str(scenario.get("scenario_id", "scenario"))

        net.add_node(
            f"{sid}_att",
            label=f"Нарушитель\n{att.get('type', '')}",
            color="#e74c3c",
            size=30,
            title="Attacker",
        )
        net.add_node(
            f"{sid}_ubi",
            label=f"{ubi}",
            color="#3498db",
            size=20,
            title="УБИ",
        )
        net.add_edge(f"{sid}_att", f"{sid}_ubi", label="цель/риск")

        prev = f"{sid}_ubi"
        for t in scenario.get("tactic_chain") or []:
            tid = f"{sid}_tac_{t}"
            net.add_node(tid, label=str(t), color="#e67e22", size=20, title="Тактика ФСТЭК")
            net.add_edge(prev, tid, label=str(t))
            for tech in (scenario.get("techniques_by_tactic") or {}).get(t, []):
                nid = f"{sid}_tech_{t}_{tech}"
                net.add_node(nid, label=str(tech), color="#f1c40f", size=15, title="MITRE")
                net.add_edge(tid, nid, label=f"{t}→техника")
            prev = tid

        aid = f"{sid}_asset"
        net.add_node(
            aid,
            label=f"Актив\n{asset.get('name', '')}",
            color="#27ae60",
            size=25,
            title="Asset",
        )
        net.add_edge(prev, aid, label="воздействие")
        return net

    def export_graph(
        self,
        scenario: dict[str, Any],
        path: Path,
        format: str = "html",
    ) -> Path | None:
        """Сохраняет граф (HTML поддерживается полностью; PNG/SVG — при наличии зависимостей).

        Args:
            scenario: Сценарий.
            path: Путь к файлу.
            format: ``html``, ``png``, ``svg``.

        Returns:
            Путь к файлу или None если формат недоступен.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        net = self.create_attack_graph(scenario)
        fmt = format.lower()
        if fmt == "html":
            out = path if path.suffix else path.with_suffix(".html")
            net.write_html(str(out))
            return out
        if fmt in ("png", "svg"):
            logger.warning(
                "Экспорт %s через pyvis не реализован; сохранён только HTML. "
                "Откройте HTML и экспортируйте из браузера либо установите graphviz.",
                fmt,
            )
            out = path.with_suffix(".html")
            net.write_html(str(out))
            return out
        logger.error("Неизвестный формат графа: %s", format)
        return None
