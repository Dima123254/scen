# -*- coding: utf-8 -*-
"""
Простой режим: вставить или загрузить JSON → получить сценарии и отчёты.

Запуск из каталога threat_modeling_engine:
    streamlit run gui/streamlit_app.py
"""

from __future__ import annotations

import json
import logging
import sys
import zipfile
from io import BytesIO
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st
from json import JSONDecodeError
from pydantic import ValidationError

from core.data_loader import parse_company_json
from core.pipeline import run_generate_bundle

st.set_page_config(
    page_title="Моделирование угроз — простой режим",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Моделирование угроз (ФСТЭК)")
st.markdown(
    "**Три шага:** (1) подготовьте JSON по шаблону `input/company_data.template.json` → "
    "(2) загрузите файл или вставьте текст → (3) нажмите **«Сформировать результат»** и скачайте файлы."
)

with st.sidebar:
    st.header("Настройки")
    do_validate = st.checkbox("Проверка сценариев (валидация)", value=True)
    do_visualize = st.checkbox("Визуализация: матрица сценария (как в методичке)", value=True)
    max_sc = st.number_input(
        "Макс. сценариев на один УБИ",
        min_value=1,
        max_value=500,
        value=10,
    )
    max_vis_html = st.number_input(
        "Сколько HTML (матриц/графов) сохранять",
        min_value=0,
        max_value=500000,
        value=0,
        help="0 = все сценарии (столько файлов, сколько строк в scenarios.json). Число > 0 — только первые N (быстрее при очень больших объёмах).",
    )

    st.divider()
    st.subheader("Помощник Qwen (по желанию)")
    st.caption(
        "**Не отправляйте** конфиденциальные данные. Подходит для общих вопросов по полям JSON."
    )
    qwen_key = st.text_input(
        "API-ключ",
        type="password",
        help="DashScope или переменная окружения DASHSCOPE_API_KEY",
    )
    qwen_url = st.text_input(
        "URL API (OpenAI-совместимый)",
        value="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )
    qwen_model = st.text_input("Модель", value="qwen-turbo")
    qwen_question = st.text_area(
        "Вопрос",
        placeholder="Как описать topology между DMZ и Internal?",
        height=80,
    )
    if st.button("Спросить Qwen"):
        import os

        key = (qwen_key or os.environ.get("DASHSCOPE_API_KEY", "")).strip()
        if not key:
            st.error("Нужен API-ключ или DASHSCOPE_API_KEY в системе.")
        elif not (qwen_question or "").strip():
            st.warning("Введите вопрос.")
        else:
            try:
                from gui.qwen_client import chat_completion

                ans = chat_completion(
                    [
                        {
                            "role": "system",
                            "content": (
                                "Помоги заполнить JSON для модели угроз ФСТЭК: meta, assets, "
                                "topology, attackers, threats (УБИ.1–11), business_processes. Кратко по-русски."
                            ),
                        },
                        {"role": "user", "content": qwen_question.strip()},
                    ],
                    api_key=key,
                    base_url=qwen_url.strip(),
                    model=(qwen_model or "qwen-turbo").strip(),
                )
                st.success("Ответ:")
                st.write(ans)
            except Exception as e:
                st.error(str(e))

st.subheader("Данные организации (JSON)")

source = st.radio(
    "Как передать файл?",
    ("Загрузить JSON-файл", "Вставить текст вручную"),
    horizontal=True,
)

json_text = ""
if source == "Загрузить JSON-файл":
    uploaded = st.file_uploader("Файл company_data.json", type=["json"])
    if uploaded is not None:
        json_text = uploaded.read().decode("utf-8", errors="replace")
else:
    if "ta_json" not in st.session_state:
        st.session_state["ta_json"] = ""
    c1, c2 = st.columns([1, 1])
    with c1:
        if st.button("Вставить шаблон из папки input"):
            tpl = _ROOT / "input" / "company_data.template.json"
            if tpl.exists():
                st.session_state["ta_json"] = tpl.read_text(encoding="utf-8")
                st.rerun()
            else:
                st.warning("Шаблон не найден.")
    with c2:
        if st.button("Очистить поле"):
            st.session_state["ta_json"] = ""
            st.rerun()
    st.text_area(
        "Вставьте сюда весь JSON",
        height=360,
        key="ta_json",
    )
    json_text = st.session_state.get("ta_json", "")

with st.expander("Краткая памятка по полям"):
    st.markdown(
        """
- **meta** — `company_name` (обязательно), остальное по желанию.
- **assets** — каждый актив: `id`, `name`, `zone` (Internal / External / DMZ / Filial), `interfaces`.
- **topology** — связи `from` и `to` (id активов), `protocol`.
- **attackers** — `type`, `level` (Н1–Н4), `category` (External / Internal / External/Internal).
- **threats** — список строк `УБИ.1` … `УБИ.11`.
- Подробнее: файл `input/README.md`.
        """
    )

if st.button("Сформировать результат", type="primary", use_container_width=True):
    if not (json_text or "").strip():
        st.error("Сначала загрузите файл или вставьте JSON.")
    else:
        import tempfile

        work_dir = Path(tempfile.mkdtemp(prefix="threat_gui_"))
        logging.basicConfig(level=logging.WARNING)

        try:
            company = parse_company_json(json_text)
        except JSONDecodeError as e:
            st.error(f"Ошибка разбора JSON: {e}")
            st.stop()
        except ValidationError as e:
            st.error("Данные не прошли проверку. Исправьте поля и попробуйте снова:")
            st.code(str(e), language="text")
            st.stop()

        with st.spinner("Считаем сценарии, отчёты и HTML-матрицы…"):
            result = run_generate_bundle(
                company,
                work_dir,
                engine_root=_ROOT,
                validate=do_validate,
                visualize=do_visualize,
                max_scenarios_per_ubi=int(max_sc),
                max_visualized_scenarios=int(max_vis_html),
            )

        st.success(f"Готово. Сгенерировано сценариев: **{result.scenarios_count}**")
        if do_visualize and result.matrix_paths:
            st.caption(
                f"В архив матриц попало **{len(result.matrix_paths)}** HTML (при лимите 0 в боковой панели — по одному на каждый сценарий)."
            )
        for msg in result.errors:
            st.warning(msg)

        dl1, dl2, dl3, dl4 = st.columns(4)
        with dl1:
            st.download_button(
                "Скачать scenarios.json",
                data=result.scenarios_path.read_bytes(),
                file_name="scenarios.json",
                mime="application/json",
            )
        with dl2:
            if result.validation_paths:
                for p in result.validation_paths:
                    label = f"Скачать {p.name}"
                    mime = (
                        "text/plain"
                        if p.suffix == ".txt"
                        else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        if p.suffix == ".xlsx"
                        else "application/json"
                    )
                    st.download_button(
                        label,
                        data=p.read_bytes(),
                        file_name=p.name,
                        mime=mime,
                        key=f"v_{p.name}",
                    )
            else:
                st.caption("Валидация выключена или отчёт не создан.")
        with dl3:
            if result.matrix_paths:
                buf_m = BytesIO()
                with zipfile.ZipFile(buf_m, "w", zipfile.ZIP_DEFLATED) as zf:
                    for p in result.matrix_paths:
                        zf.writestr(p.name, p.read_bytes())
                buf_m.seek(0)
                st.download_button(
                    "Матрицы сценариев (ZIP)",
                    data=buf_m.getvalue(),
                    file_name="matrices.zip",
                    mime="application/zip",
                )
            else:
                st.caption("Матрицы не строились.")
        with dl4:
            if result.graph_paths:
                buf = BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    for p in result.graph_paths:
                        zf.writestr(p.name, p.read_bytes())
                buf.seek(0)
                st.download_button(
                    "Графы pyvis (ZIP)",
                    data=buf.getvalue(),
                    file_name="graphs.zip",
                    mime="application/zip",
                )
            else:
                st.caption("Режим «только матрица» — графы не создаются.")

        st.subheader("Фрагмент результата")
        scenarios_data = json.loads(result.scenarios_path.read_text(encoding="utf-8"))
        st.json(scenarios_data[: min(3, len(scenarios_data))])
        st.caption(f"Временные файлы: `{work_dir}` (можно удалить после скачивания).")
