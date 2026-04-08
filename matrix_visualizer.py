# -*- coding: utf-8 -*-
"""Матрица сценария: способы реализации | тактики Т1–Т10 | техники (как в методичке)."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from config.bdu_realization_methods import format_bdu_method_line
from config.mapping_config import normalize_fstec_tactic

ORDERED_BASE_TACTICS = [f"Т{i}" for i in range(1, 11)]


def _realization_methods(scenario: dict[str, Any], cfg: dict[str, Any]) -> list[str]:
    """Слева в матрице: перечень БДУ ФСТЭК (из сценария) или запасной текст из YAML."""
    use_bdu = cfg.get("use_bdu_realization_methods", True)
    bdu_block = scenario.get("bdu_realization_methods") or []
    if use_bdu and bdu_block:
        lines = [format_bdu_method_line(x) for x in bdu_block if isinstance(x, dict)]
        src = scenario.get("bdu_realization_source_url")
        if src and lines:
            lines.append(f"(классификатор: {src})")
        return lines if lines else _realization_methods_yaml_fallback(scenario, cfg)

    return _realization_methods_yaml_fallback(scenario, cfg)


def _realization_methods_yaml_fallback(scenario: dict[str, Any], cfg: dict[str, Any]) -> list[str]:
    by_ubi = cfg.get("realization_methods_by_ubi") or {}
    ubi = str(scenario.get("ubi", ""))
    methods = by_ubi.get(ubi) or by_ubi.get("default") or [
        "Реализация угрозы по сценарию (настройте realization_methods_by_ubi в matrix_display.yaml "
        "или включите use_bdu_realization_methods и пересоберите сценарии)."
    ]
    return list(methods) if isinstance(methods, list) else [str(methods)]


def _techniques_by_base_tactic(
    scenario: dict[str, Any],
) -> dict[str, list[tuple[str, str]]]:
    """Техники по колонкам Т1–Т10: пары (id, название). Приоритет — ``fstec_techniques_by_tactic``."""
    out: dict[str, list[tuple[str, str]]] = {t: [] for t in ORDERED_BASE_TACTICS}
    seen: dict[str, set[str]] = {t: set() for t in ORDERED_BASE_TACTICS}

    fstec = scenario.get("fstec_techniques_by_tactic") or {}
    if fstec:
        for tac_key, items in fstec.items():
            base = normalize_fstec_tactic(str(tac_key))
            if base not in out:
                continue
            for item in items or []:
                if isinstance(item, dict):
                    tid = str(item.get("id", ""))
                    nm = str(item.get("name", ""))
                else:
                    tid = str(item)
                    nm = ""
                if tid and tid not in seen[base]:
                    seen[base].add(tid)
                    out[base].append((tid, nm))
        return out

    raw = scenario.get("techniques_by_tactic") or {}
    for tac_key, tech_list in raw.items():
        base = normalize_fstec_tactic(str(tac_key))
        if base not in out:
            continue
        for tid in tech_list or []:
            s = str(tid)
            if s not in seen[base]:
                seen[base].add(s)
                out[base].append((s, ""))
    return out


def _scenario_title(scenario: dict[str, Any], cfg: dict[str, Any]) -> str:
    tpl = str(
        cfg.get("scenario_title_template")
        or "Сценарий: {ubi} — «{asset_name}»"
    )
    asset = scenario.get("asset") or {}
    return tpl.format(
        ubi_description=html.escape(str(scenario.get("ubi_description", scenario.get("ubi", "")))),
        ubi=html.escape(str(scenario.get("ubi", ""))),
        asset_name=html.escape(str(asset.get("name", asset.get("id", "")))),
        company_name=html.escape(str(scenario.get("company_name", ""))),
        system_name=html.escape(str(scenario.get("system_name", ""))),
    )


def build_matrix_html(scenario: dict[str, Any], display_cfg: dict[str, Any]) -> str:
    """Собирает один HTML-документ с матрицей.

    Args:
        scenario: Словарь сценария.
        display_cfg: Содержимое ``matrix_display.yaml``.

    Returns:
        Полный HTML5-документ.
    """
    methods = _realization_methods(scenario, display_cfg)
    by_col = _techniques_by_base_tactic(scenario)
    tactic_titles: dict[str, str] = display_cfg.get("tactic_titles_ru") or {}
    tech_labels: dict[str, str] = display_cfg.get("mitre_technique_labels_ru") or {}
    legend = display_cfg.get("legend") or {}
    leg_t = html.escape(str(legend.get("tactics", "Тактика")))
    leg_e = html.escape(str(legend.get("techniques", "Техника")))
    leg_m = html.escape(str(legend.get("methods", "Способ реализации угрозы")))

    title = _scenario_title(scenario, display_cfg)
    meta_line = html.escape(
        f"{scenario.get('company_name', '')} · {scenario.get('system_name', '')} · "
        f"Нарушитель: {(scenario.get('attacker') or {}).get('type', '')} "
        f"({(scenario.get('attacker') or {}).get('level', '')})"
    )
    sid = html.escape(str(scenario.get("scenario_id", "")))

    # Шапка тактик
    header_cells = []
    for t in ORDERED_BASE_TACTICS:
        label = html.escape(tactic_titles.get(t, t))
        header_cells.append(f'<div class="tactic-head" title="{html.escape(t)}">{label}</div>')

    # Колонки техник
    col_cells = []
    for t in ORDERED_BASE_TACTICS:
        techs = by_col.get(t, [])
        inner = []
        for tid, fstec_name in techs:
            ru = fstec_name or tech_labels.get(tid, "")
            tid_e = html.escape(tid)
            if ru:
                inner.append(
                    f'<div class="technique"><span class="tech-id">{tid_e}</span>'
                    f'<span class="tech-desc">{html.escape(ru)}</span></div>'
                )
            else:
                inner.append(
                    f'<div class="technique tech-only-id"><span class="tech-id">{tid_e}</span></div>'
                )
        if not inner:
            inner.append('<div class="technique empty">—</div>')
        col_cells.append(f'<div class="tactic-col">{"".join(inner)}</div>')

    methods_html = "".join(
        f'<div class="method-card">{html.escape(str(m))}</div>' for m in methods
    )

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{title}</title>
  <style>
    :root {{
      --bg: #f4f6fb;
      --card: #ffffff;
      --tactic: #1d4ed8;
      --tactic-soft: #dbeafe;
      --technique: #ea580c;
      --technique-soft: #ffedd5;
      --method: #db2777;
      --method-soft: #fce7f3;
      --text: #1e293b;
      --muted: #64748b;
      --radius: 12px;
      --shadow: 0 4px 14px rgba(15, 23, 42, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
      background: linear-gradient(160deg, #eef2ff 0%, var(--bg) 40%, #f8fafc 100%);
      color: var(--text);
      min-height: 100vh;
      padding: 1.5rem;
    }}
    .sheet {{
      max-width: 1600px;
      margin: 0 auto;
      background: var(--card);
      border-radius: 20px;
      box-shadow: var(--shadow);
      padding: 1.75rem 1.5rem 2rem;
    }}
    h1 {{
      font-size: 1.25rem;
      font-weight: 700;
      margin: 0 0 0.35rem 0;
      line-height: 1.35;
      color: #0f172a;
    }}
    .sub {{
      font-size: 0.85rem;
      color: var(--muted);
      margin-bottom: 1.25rem;
    }}
    .matrix {{
      display: flex;
      flex-direction: column;
      gap: 0.65rem;
    }}
    .top-row {{
      display: flex;
      gap: 0.65rem;
      align-items: stretch;
    }}
    .corner {{
      width: 260px;
      min-width: 220px;
      flex-shrink: 0;
      background: linear-gradient(135deg, var(--method-soft), #fff);
      border-radius: var(--radius);
      border: 1px solid #f9a8d4;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.72rem;
      font-weight: 600;
      color: var(--method);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      padding: 0.5rem;
      text-align: center;
    }}
    .tactic-row {{
      flex: 1;
      display: grid;
      grid-template-columns: repeat(10, minmax(0, 1fr));
      gap: 0.45rem;
    }}
    .tactic-head {{
      background: linear-gradient(180deg, var(--tactic), #1e40af);
      color: #fff;
      border-radius: var(--radius);
      padding: 0.55rem 0.35rem;
      font-size: 0.68rem;
      font-weight: 600;
      text-align: center;
      line-height: 1.25;
      min-height: 3.4rem;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 2px 8px rgba(29, 78, 216, 0.25);
    }}
    .main-row {{
      display: flex;
      gap: 0.65rem;
      align-items: stretch;
    }}
    .methods {{
      width: 260px;
      min-width: 220px;
      flex-shrink: 0;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }}
    .method-card {{
      background: linear-gradient(135deg, #fff, var(--method-soft));
      border: 1px solid #f9a8d4;
      border-radius: var(--radius);
      padding: 0.65rem 0.75rem;
      font-size: 0.78rem;
      line-height: 1.4;
      color: #831843;
      flex: 1;
      box-shadow: 0 1px 4px rgba(219, 39, 119, 0.12);
    }}
    .technique-grid {{
      flex: 1;
      display: grid;
      grid-template-columns: repeat(10, minmax(0, 1fr));
      gap: 0.45rem;
      align-items: start;
    }}
    .tactic-col {{
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
      min-height: 120px;
    }}
    .technique {{
      background: linear-gradient(135deg, #fff, var(--technique-soft));
      border: 1px solid #fdba74;
      border-radius: 10px;
      padding: 0.45rem 0.5rem;
      font-size: 0.72rem;
      line-height: 1.35;
      box-shadow: 0 1px 3px rgba(234, 88, 12, 0.1);
    }}
    .technique.empty {{
      color: var(--muted);
      background: #f8fafc;
      border-style: dashed;
      text-align: center;
    }}
    .tech-id {{
      display: block;
      font-weight: 700;
      color: #9a3412;
      font-size: 0.7rem;
      margin-bottom: 0.2rem;
    }}
    .tech-desc {{ color: #431407; }}
    .tech-only-id .tech-id {{ margin-bottom: 0; }}
    .legend {{
      margin-top: 1.25rem;
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      font-size: 0.75rem;
      color: var(--muted);
      justify-content: flex-end;
    }}
    .legend span {{
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
    }}
    .swatch {{
      width: 14px;
      height: 14px;
      border-radius: 4px;
    }}
    @media print {{
      body {{ background: #fff; padding: 0; }}
      .sheet {{ box-shadow: none; max-width: none; }}
    }}
    @media (max-width: 1200px) {{
      .top-row, .main-row {{ flex-direction: column; }}
      .corner, .methods {{ width: 100%; }}
      .tactic-row, .technique-grid {{
        display: flex;
        flex-wrap: wrap;
        justify-content: flex-start;
      }}
      .tactic-head, .tactic-col {{ min-width: 140px; flex: 1 1 140px; }}
    }}
  </style>
</head>
<body>
  <div class="sheet">
    <h1>{title}</h1>
    <div class="sub">{meta_line}<br/><code style="font-size:0.8em">{sid}</code></div>
    <div class="matrix">
      <div class="top-row">
        <div class="corner">{leg_m}</div>
        <div class="tactic-row">
          {"".join(header_cells)}
        </div>
      </div>
      <div class="main-row">
        <div class="methods">{methods_html}</div>
        <div class="technique-grid">
          {"".join(col_cells)}
        </div>
      </div>
    </div>
    <div class="legend">
      <span><span class="swatch" style="background:linear-gradient(180deg,var(--tactic),#1e40af)"></span> {leg_t}</span>
      <span><span class="swatch" style="background:linear-gradient(135deg,#fff,var(--technique-soft));border:1px solid #fdba74"></span> {leg_e}</span>
      <span><span class="swatch" style="background:linear-gradient(135deg,#fff,var(--method-soft));border:1px solid #f9a8d4"></span> {leg_m}</span>
    </div>
  </div>
</body>
</html>
"""


def export_matrix_html(
    scenario: dict[str, Any],
    output_path: Path,
    display_cfg: dict[str, Any],
) -> Path:
    """Записывает матрицу в HTML-файл."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc = build_matrix_html(scenario, display_cfg)
    output_path.write_text(doc, encoding="utf-8")
    return output_path
