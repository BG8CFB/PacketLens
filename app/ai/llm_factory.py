"""LLM 工厂 — 根据 provider_type 创建对应的 LangChain ChatModel

支持动态注册新的 provider 类型，无需修改工厂代码。
"""

from __future__ import annotations

import logging
from typing import Callable

from langchain_core.language_models.chat_models import BaseChatModel

logger = logging.getLogger(__name__)

PROVIDER_TYPE_OPENAI = "openai"
PROVIDER_TYPE_ANTHROPIC = "anthropic"

# provider_type → 创建函数的注册表
_PROVIDER_REGISTRY: dict[str, Callable[..., BaseChatModel]] = {}


class LLMFactory:
    """LangChain ChatModel 工厂

    内置支持 openai 和 anthropic 两种 provider 类型。
    可通过 register_provider() 动态注册新类型。
    """

    @staticmethod
    def create(
        provider_type: str,
        *,
        api_key: str,
        base_url: str = "",
        model: str = "",
        temperature: float = 0.3,
        max_tokens: int = 4096,
        timeout: int = 120,
        stream_usage: bool = True,
    ) -> BaseChatModel:
        creator = _PROVIDER_REGISTRY.get(provider_type)
        if creator is None:
            valid = ", ".join(sorted(_PROVIDER_REGISTRY.keys()))
            raise ValueError(
                f"不支持的 provider_type: '{provider_type}'，"
                f"已注册类型: [{valid}]"
            )
        return creator(
            api_key=api_key, base_url=base_url, model=model,
            temperature=temperature, max_tokens=max_tokens,
            timeout=timeout, stream_usage=stream_usage,
        )

    @staticmethod
    def register_provider(
        provider_type: str,
        creator: Callable[..., BaseChatModel],
    ) -> None:
        """注册新的 provider 类型

        Args:
            provider_type: 类型标识（如 "gemini"）
            creator: 创建函数，签名为 (api_key, base_url, model, temperature,
                     max_tokens, timeout, stream_usage) -> BaseChatModel
        """
        if provider_type in _PROVIDER_REGISTRY:
            logger.warning(f"覆盖已注册的 provider_type: '{provider_type}'")
        _PROVIDER_REGISTRY[provider_type] = creator

    @staticmethod
    def registered_types() -> tuple[str, ...]:
        """返回所有已注册的 provider 类型"""
        return tuple(sorted(_PROVIDER_REGISTRY.keys()))


def _create_openai(
    api_key: str, base_url: str, model: str,
    temperature: float, max_tokens: int, timeout: int, stream_usage: bool,
    **kwargs,
) -> BaseChatModel:
    from langchain_openai import ChatOpenAI

    kw = dict(
        api_key=api_key, model=model, temperature=temperature,
        max_tokens=max_tokens, timeout=timeout, stream_usage=stream_usage,
    )
    if base_url:
        kw["base_url"] = base_url
    return ChatOpenAI(**kw)


def _create_anthropic(
    api_key: str, base_url: str, model: str,
    temperature: float, max_tokens: int, timeout: int, stream_usage: bool,
    **kwargs,
) -> BaseChatModel:
    from langchain_anthropic import ChatAnthropic

    kw = dict(
        api_key=api_key, model=model, temperature=temperature,
        max_tokens=max_tokens, timeout=timeout, streaming=stream_usage,
    )
    if base_url:
        kw["anthropic_api_url"] = base_url
    return ChatAnthropic(**kw)


# 注册内置 provider 类型
_PROVIDER_REGISTRY[PROVIDER_TYPE_OPENAI] = _create_openai
_PROVIDER_REGISTRY[PROVIDER_TYPE_ANTHROPIC] = _create_anthropic
