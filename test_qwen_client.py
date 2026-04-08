# -*- coding: utf-8 -*-
"""Тест HTTP-клиента Qwen (мок ответа)."""

from __future__ import annotations

from unittest.mock import patch

from gui.qwen_client import chat_completion


def test_chat_completion_parses_choice():
    fake_body = (
        b'{"choices":[{"message":{"content":"hello"}}]}'
    )

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_body

    with patch("gui.qwen_client.urllib.request.urlopen", return_value=FakeResp()):
        out = chat_completion(
            [{"role": "user", "content": "hi"}],
            api_key="test",
            base_url="https://example.com/v1",
        )
    assert out == "hello"
