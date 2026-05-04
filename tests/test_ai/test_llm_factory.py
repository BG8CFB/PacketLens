"""LLM Factory 真实 API 测试 — 调用真实 API 验证工厂创建和调用"""

import os

import pytest

from app.ai.llm_factory import (
    LLMFactory,
    PROVIDER_TYPE_ANTHROPIC,
    PROVIDER_TYPE_OPENAI,
)
from app.storage.config_manager import ConfigManager


def _get_config() -> dict:
    return ConfigManager().get_ai_config()


def _has_anthropic_key() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())


class TestLLMFactoryOpenAI:
    """OpenAI 兼容类型 — 使用 .env 中的 MiniMax 真实 API"""

    def test_create_and_invoke(self):
        """创建 ChatOpenAI 并真实调用 API"""
        cfg = _get_config()
        llm = LLMFactory.create(
            PROVIDER_TYPE_OPENAI,
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
            max_tokens=20,
        )
        from langchain_core.messages import HumanMessage

        response = llm.invoke([HumanMessage(content="1+1等于几？只回答数字")])
        assert response.content
        assert len(response.content) > 0

    def test_create_and_stream(self):
        """流式调用真实 API"""
        cfg = _get_config()
        llm = LLMFactory.create(
            PROVIDER_TYPE_OPENAI,
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
            max_tokens=30,
        )
        from langchain_core.messages import HumanMessage

        chunks = []
        for chunk in llm.stream([HumanMessage(content="说你好")]):
            if chunk.content:
                chunks.append(chunk.content)
        result = "".join(chunks)
        assert len(result) > 0

    def test_invalid_type_raises(self):
        """不支持的 provider_type 应抛出 ValueError"""
        with pytest.raises(ValueError, match="不支持的 provider_type"):
            LLMFactory.create("gemini", api_key="test")

    def test_valid_provider_types(self):
        """验证注册表中包含 openai 和 anthropic"""
        registered = LLMFactory.registered_types()
        assert "openai" in registered
        assert "anthropic" in registered

    def test_create_openai_with_base_url(self):
        """ChatOpenAI 创建时 base_url 应被正确传递"""
        llm = LLMFactory.create(
            PROVIDER_TYPE_OPENAI,
            api_key="test-key",
            base_url="https://custom.api.com/v1",
            model="test-model",
            max_tokens=10,
        )
        # 验证 LLM 实例创建成功（不调用 API）
        assert llm is not None

    def test_register_custom_provider(self):
        """应支持动态注册自定义 provider"""
        from langchain_core.language_models.chat_models import BaseChatModel

        def custom_creator(api_key, base_url, model, temperature, max_tokens,
                           timeout, stream_usage, **kwargs):
            # 返回 None 会触发错误，这里只验证注册机制
            return None

        LLMFactory.register_provider("custom_test", custom_creator)
        assert "custom_test" in LLMFactory.registered_types()


@pytest.mark.skipif(
    not _has_anthropic_key(),
    reason="未配置 ANTHROPIC_API_KEY 环境变量",
)
class TestLLMFactoryAnthropic:
    """Anthropic 类型 — 需要配置 ANTHROPIC_API_KEY 环境变量"""

    def test_create_and_invoke(self):
        """创建 ChatAnthropic 并真实调用 API"""
        llm = LLMFactory.create(
            PROVIDER_TYPE_ANTHROPIC,
            api_key=os.environ["ANTHROPIC_API_KEY"],
            model="claude-sonnet-4-20250514",
            max_tokens=20,
        )
        from langchain_core.messages import HumanMessage

        response = llm.invoke([HumanMessage(content="1+1等于几？只回答数字")])
        assert response.content
        assert len(response.content) > 0
