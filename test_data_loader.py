# -*- coding: utf-8 -*-
"""Тесты загрузки данных."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from core.data_loader import get_resource_path, load_company_data, load_settings, parse_company_json


def test_get_resource_path():
    base = Path(__file__).resolve().parent.parent
    p = get_resource_path("config/settings.yaml", base)
    assert p.exists()


def test_load_settings():
    root = Path(__file__).resolve().parent.parent
    s = load_settings(root)
    assert "engine" in s


def test_load_company_data_org_alpha():
    p = Path(__file__).parent / "test_data" / "org_alpha.json"
    c = load_company_data(p)
    assert c.meta.company_name


def test_parse_company_json_string():
    p = Path(__file__).parent / "test_data" / "org_alpha.json"
    text = p.read_text(encoding="utf-8")
    c = parse_company_json(text)
    assert c.meta.company_name == "Тестовая организация Alpha"


def test_invalid_zone_rejected(tmp_path):
    import json

    raw = {
        "meta": {"company_name": "X", "system_name": "", "author": "", "date": ""},
        "assets": [
            {
                "id": "a",
                "name": "n",
                "zone": "Wrong",
                "interfaces": [],
                "data_types": [],
            }
        ],
        "topology": [],
        "attackers": [],
        "threats": [],
        "business_processes": [],
    }
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_company_data(path)
