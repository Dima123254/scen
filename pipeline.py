# -*- coding: utf-8 -*-
"""Один вызов: сценарии + опционально валидация и графы (для GUI и скриптов)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.data_loader import load_matrix_display, load_settings, load_validation_config
from core.models import CompanyData
from core.scenario_builder import ThreatScenarioBuilder, build_all_scenarios
from reporting.report_generator import ReportGenerator
from validation.filter_engine import FilterEngine

logger = logging.getLogger(__name__)


@dataclass
class GenerateBundleResult:
    """Результат пакетной генерации."""

    scenarios_count: int
    scenarios_path: Path
    validation_paths: list[Path] = field(default_factory=list)
    graph_paths: list[Path] = field(default_factory=list)
    matrix_paths: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def run_generate_bundle(
    company: CompanyData,
    output_dir: Path,
    *,
    engine_root: Path,
    validation_config_path: Path | None = None,
    validate: bool = True,
    visualize: bool = True,
    max_scenarios_per_ubi: int | None = None,
    visualization_mode: str | None = None,
    max_visualized_scenarios: int | None = None,
) -> GenerateBundleResult:
    """Строит сценарии и сохраняет артефакты в ``output_dir``.

    Args:
        company: Валидированные данные организации.
        output_dir: Рабочий каталог (создаётся при необходимости).
        engine_root: Корень движка (где лежат ``config/``).
        validation_config_path: Явный YAML или None.
        validate: Записать отчёты валидации.
        visualize: Сохранить визуализации (матрица и/или граф).
        max_scenarios_per_ubi: Переопределение лимита; None — из YAML.
        visualization_mode: ``matrix`` / ``graph`` / ``both``; None — из ``settings.yaml``.
        max_visualized_scenarios: Лимит HTML на диск; ``None`` — из settings; ``<=0`` — все сценарии.

    Returns:
        ``GenerateBundleResult`` с путями к файлам.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    settings = load_settings(engine_root)
    vcfg = load_validation_config(validation_config_path, engine_root)
    thresholds = vcfg.get("thresholds") or {}
    max_per = (
        max_scenarios_per_ubi
        if max_scenarios_per_ubi is not None
        else int(thresholds.get("max_scenarios_per_ubi", 10))
    )

    builder = ThreatScenarioBuilder(settings)
    scenarios = build_all_scenarios(company, builder, max_per_ubi=max_per)

    scenarios_path = output_dir / "scenarios.json"
    scenarios_path.write_text(
        json.dumps(scenarios, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    val_paths: list[Path] = []
    graph_paths: list[Path] = []
    matrix_paths: list[Path] = []
    errs: list[str] = []

    viz_cfg = settings.get("visualization") or {}
    vmode = (visualization_mode or str(viz_cfg.get("mode", "matrix"))).lower()
    if max_visualized_scenarios is not None:
        max_vis = int(max_visualized_scenarios)
    else:
        try:
            max_vis = int(viz_cfg.get("max_visualized_scenarios", 0))
        except (TypeError, ValueError):
            max_vis = 0
    slice_sc = scenarios if max_vis <= 0 else scenarios[:max_vis]
    if max_vis <= 0:
        logger.info("Визуализация: все сценарии (%s шт.)", len(scenarios))
    else:
        logger.info("Визуализация: первые %s из %s сценариев", max_vis, len(scenarios))

    if validate:
        try:
            fe = FilterEngine(company, vcfg)
            rep = fe.run(scenarios)
            rg = ReportGenerator()
            rep_cfg = vcfg.get("reporting") or {}
            fmts = list(rep_cfg.get("format") or ["json", "txt"])
            val_paths = rg.generate_validation_report(
                rep, output_dir / "reports" / "validation_report", fmts
            )
        except Exception as e:  # pragma: no cover
            logger.exception("validation report")
            errs.append(f"Валидация/отчёт: {e}")

    if visualize:
        if vmode in ("matrix", "both"):
            try:
                from visualization.matrix_visualizer import export_matrix_html

                mcfg = load_matrix_display(engine_root)
                mdir = output_dir / "matrices"
                mdir.mkdir(parents=True, exist_ok=True)
                for sc in slice_sc:
                    safe = str(sc.get("scenario_id", "x")).replace("/", "_").replace("\\", "_")
                    p = mdir / f"{safe}.html"
                    try:
                        matrix_paths.append(export_matrix_html(sc, p, mcfg))
                    except Exception as e:  # pragma: no cover
                        errs.append(f"Матрица {safe}: {e}")
            except Exception as e:  # pragma: no cover
                logger.exception("matrix visualize")
                errs.append(f"Матрица: {e}")

        if vmode in ("graph", "both"):
            try:
                from visualization.graph_visualizer import GraphVisualizer

                gv = GraphVisualizer()
                gdir = output_dir / "graphs"
                gdir.mkdir(parents=True, exist_ok=True)
                for sc in slice_sc:
                    safe = str(sc.get("scenario_id", "x")).replace("/", "_").replace("\\", "_")
                    p = gdir / f"{safe}.html"
                    try:
                        out = gv.export_graph(sc, p, format="html")
                        if out:
                            graph_paths.append(out)
                    except Exception as e:  # pragma: no cover
                        errs.append(f"Граф {safe}: {e}")
            except Exception as e:  # pragma: no cover
                logger.exception("graph visualize")
                errs.append(f"Граф: {e}")

    return GenerateBundleResult(
        scenarios_count=len(scenarios),
        scenarios_path=scenarios_path,
        validation_paths=val_paths,
        graph_paths=graph_paths,
        matrix_paths=matrix_paths,
        errors=errs,
    )
