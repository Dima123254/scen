# -*- coding: utf-8 -*-
"""CLI движка моделирования угроз (Методика ФСТЭК 2021, приложения 6–11)."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import typer

from core.data_loader import load_company_data, load_validation_config
from core.pipeline import run_generate_bundle
from reporting.report_generator import ReportGenerator
from validation.filter_engine import FilterEngine

app = typer.Typer(help="Универсальный движок сценариев угроз (ФСТЭК / MITRE)")


def _engine_root() -> Path:
    return Path(__file__).resolve().parent


def _setup_logging(output_dir: Path) -> None:
    log_dir = output_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "threat_engine.log"
    fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.INFO)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(logging.Formatter(fmt))
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter(fmt))
    root.addHandler(fh)
    root.addHandler(sh)


@app.command()
def generate(
    input_file: Path = typer.Argument(..., help="Путь к company_data.json"),
    output_dir: Path = typer.Option(
        Path("output"),
        "--output",
        "-o",
        help="Каталог для сценариев, отчётов, графов",
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="validation_config.yaml (по умолчанию из settings)",
    ),
    validate: bool = typer.Option(False, "--validate", help="Запустить валидацию"),
    visualize: bool = typer.Option(False, "--visualize", help="Создать HTML-визуализации"),
    viz_mode: Optional[str] = typer.Option(
        None,
        "--viz-mode",
        help="matrix | graph | both (по умолчанию из settings.yaml)",
    ),
    max_visualized: Optional[int] = typer.Option(
        None,
        "--max-visualized",
        help="Сколько HTML матриц/графов (0 или не задано с max=0 в settings = все сценарии)",
    ),
) -> None:
    """Сгенерировать сценарии из входного JSON."""
    output_dir = Path(output_dir)
    if not output_dir.is_absolute():
        output_dir = Path.cwd() / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    _setup_logging(output_dir)
    log = logging.getLogger("main")
    engine_root = _engine_root()
    try:
        in_path = Path(input_file)
        if not in_path.is_absolute():
            in_path = Path.cwd() / in_path
            if not in_path.exists():
                in_path = engine_root / Path(input_file)
        company = load_company_data(in_path)
        vcfg_path = Path(config) if config else None
        bundle = run_generate_bundle(
            company,
            output_dir,
            engine_root=engine_root,
            validation_config_path=vcfg_path,
            validate=validate,
            visualize=visualize,
            max_scenarios_per_ubi=None,
            visualization_mode=viz_mode,
            max_visualized_scenarios=max_visualized,
        )
        log.info(
            "Сохранено сценариев: %s → %s",
            bundle.scenarios_count,
            bundle.scenarios_path,
        )
        if validate:
            log.info("Отчёт валидации: %s", output_dir / "reports")
        if visualize:
            log.info("Матрицы (HTML): %s файлов", len(bundle.matrix_paths))
            log.info("Графы (HTML): %s файлов", len(bundle.graph_paths))
        for err in bundle.errors:
            log.warning("%s", err)
    except Exception as e:
        log.exception("Ошибка generate: %s", e)
        typer.echo(f"Ошибка: {e}", err=True)
        raise typer.Exit(code=1) from e


@app.command("validate")
def validate_cmd(
    scenarios_file: Path = typer.Argument(..., help="JSON со списком сценариев"),
    company_file: Path = typer.Option(
        Path("input/company_data.json"),
        "--company",
        help="Исходный company_data.json для контекста топологии",
    ),
    filters: str = typer.Option(
        "level,topology,ubi,interface",
        "--filters",
        "-f",
        help="Список фильтров через запятую",
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    output_dir: Path = typer.Option(Path("output"), "--output", "-o"),
) -> None:
    """Валидация готового файла сценариев."""
    output_dir = Path(output_dir)
    if not output_dir.is_absolute():
        output_dir = Path.cwd() / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    _setup_logging(output_dir)
    log = logging.getLogger("main")
    engine_root = _engine_root()
    try:
        cf = Path(company_file)
        if not cf.is_absolute():
            cf = Path.cwd() / cf
            if not cf.exists():
                cf = engine_root / Path(company_file)
        company = load_company_data(cf)
        vcfg = load_validation_config(config, engine_root)
        sf = Path(scenarios_file)
        if not sf.is_absolute():
            sf = Path.cwd() / sf
            if not sf.exists():
                sf = engine_root / Path(scenarios_file)
        raw = json.loads(sf.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError("scenarios_file должен содержать JSON-массив сценариев")
        subset = [x.strip() for x in filters.split(",") if x.strip()]
        fe = FilterEngine(company, vcfg)
        rep = fe.run(raw, filter_subset=subset)
        rg = ReportGenerator()
        rg.generate_validation_report(rep, output_dir / "reports" / "validation_report", ["json", "txt", "xlsx"])
        log.info("Валидация завершена")
    except Exception as e:
        log.exception("Ошибка validate: %s", e)
        typer.echo(f"Ошибка: {e}", err=True)
        raise typer.Exit(code=1) from e


@app.command("report")
def report_cmd(
    appendix: int = typer.Option(..., "--appendix", "-a", min=6, max=11),
    format: str = typer.Option("xlsx", "--format", "-F"),
    company_file: Path = typer.Option(
        Path("input/company_data.json"),
        "--company",
        help="Данные организации",
    ),
    output: Path = typer.Option(Path("output/reports"), "--output", "-o"),
) -> None:
    """Сгенерировать таблицу приложения 6–11."""
    engine_root = _engine_root()
    log_base = engine_root / "output"
    _setup_logging(log_base)
    log = logging.getLogger("main")
    try:
        cpath = Path(company_file)
        if not cpath.is_absolute():
            cpath = engine_root / cpath
        company = load_company_data(cpath)
        rg = ReportGenerator()
        out_path = Path(output)
        if not out_path.is_absolute():
            out_path = engine_root / out_path
        out = rg.generate_fstec_appendix(appendix, company, out_path, fmt=format)
        log.info("Приложение %s → %s", appendix, out)
        typer.echo(str(out))
    except Exception as e:
        logging.getLogger("main").exception("Ошибка report: %s", e)
        typer.echo(f"Ошибка: {e}", err=True)
        raise typer.Exit(code=1) from e


def main() -> None:
    app()


if __name__ == "__main__":
    main()
