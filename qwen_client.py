# -*- coding: utf-8 -*-
"""Вызов Qwen через OpenAI-совместимый HTTP API (stdlib, без лишних зависимостей)."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any


def chat_completion(
    messages: list[dict[str, str]],
    *,
    api_key: str,
    base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1",
    model: str = "qwen-turbo",
    timeout: int = 90,
) -> str:
    """Отправляет чат-запрос и возвращает текст ответа ассистента.

    Args:
        messages: Список ``{"role": "user"|"system", "content": "..."}``.
        api_key: Ключ (например, DashScope).
        base_url: База без завершающего ``/``.
        model: Идентификатор модели на стороне провайдера.
        timeout: Таймаут секунд.

    Returns:
        Текст ответа.

    Raises:
        RuntimeError: HTTP или формат ответа.
        urllib.error.URLError: Сеть.
    """
    url = base_url.rstrip("/") + "/chat/completions"
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")

    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {detail}") from e

    try:
        choice = body["choices"][0]
        msg = choice.get("message") or {}
        content = msg.get("content")
        if content:
            return str(content)
    except (KeyError, IndexError, TypeError):
        pass
    raise RuntimeError(f"Неожиданный ответ API: {body!r}")
