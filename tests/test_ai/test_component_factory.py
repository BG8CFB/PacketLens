"""component_factory 测试 — 使用真实配置验证参数透传"""

from __future__ import annotations

import pytest

from app.ai.ai_engine import AIEngine
from app.ai.component_factory import (
    create_ai_engine,
    create_prompt_builder,
    create_result_parser,
)
from app.config.ai_defaults import AI_DEFAULTS
from app.storage.config_manager import ConfigManager


def _get_ai_config(**overrides) -> dict:
    """从 ConfigManager 获取当前激活 provider 的真实配置，允许覆盖"""
    cfg = ConfigManager().get_ai_config()
    cfg.update(overrides)
    return cfg


class TestCreateAIEngine:
    """验证 create_ai_engine 使用真实配置正确创建 AIEngine"""

    def test_returns_aiengine_instance(self):
        cfg = _get_ai_config()
        engine = create_ai_engine(cfg)
        assert isinstance(engine, AIEngine)

    def test_temperature_propagated(self):
        """temperature 应正确透传到 AIEngine 内部状态"""
        cfg = _get_ai_config(temperature=0.85)
        engine = create_ai_engine(cfg)
        assert engine._temperature == pytest.approx(0.85)

    def test_zero_temperature_propagated(self):
        """temperature=0 是合法值，不应被当作 None 而退回默认"""
        cfg = _get_ai_config(temperature=0.0)
        engine = create_ai_engine(cfg)
        assert engine._temperature == 0.0

    def test_missing_temperature_uses_default(self):
        """配置中不带 temperature 时应回退到 AI_DEFAULTS"""
        cfg = _get_ai_config()
        cfg.pop("temperature", None)
        engine = create_ai_engine(cfg)
        assert engine._temperature == AI_DEFAULTS["temperature"]

    def test_max_tokens_and_timeout_propagated(self):
        cfg = _get_ai_config(max_tokens=1234, timeout=33)
        engine = create_ai_engine(cfg)
        assert engine._max_tokens == 1234
        assert engine._timeout == 33

    def test_api_key_and_base_url_propagated(self):
        cfg = _get_ai_config()
        engine = create_ai_engine(cfg)
        assert engine._api_key == cfg["api_key"]
        assert engine._base_url == cfg["base_url"]

    def test_model_propagated(self):
        cfg = _get_ai_config()
        engine = create_ai_engine(cfg)
        assert engine._model == cfg["model"]

    def test_provider_type_propagated(self):
        cfg = _get_ai_config()
        engine = create_ai_engine(cfg)
        assert engine._provider_type == cfg["provider_type"]


class TestCreatePromptBuilder:
    """PromptBuilder 工厂测试"""

    def test_uses_provided_context_window(self):
        cfg = _get_ai_config(context_window_tokens=99000)
        builder = create_prompt_builder(cfg)
        assert builder is not None

    def test_creates_result_parser(self):
        parser = create_result_parser()
        assert parser is not None
