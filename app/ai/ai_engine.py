"""AI Engine — 通过 OpenAI SDK 调用兼容 API"""

from __future__ import annotations

import logging
import time
from typing import Callable

from openai import OpenAI

from app.config.ai_defaults import AI_DEFAULTS

logger = logging.getLogger(__name__)


class AIEngine:
    """AI API 接口

    使用 OpenAI SDK + base_url 指向任意兼容 API。
    不做输入截断——由 PromptBuilder 在构建阶段通过智能采样控制数据量。
    如果 API 返回 token 超限错误，由调用方处理重试逻辑。
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
        context_window_tokens: int | None = None,
        max_tokens: int | None = None,
    ):
        self._api_key = api_key or ""
        self._base_url = base_url or ""
        self._model = model or ""
        self._max_tokens = max_tokens if max_tokens is not None else AI_DEFAULTS["max_tokens"]
        self._context_window_tokens = (
            context_window_tokens if context_window_tokens is not None
            else AI_DEFAULTS["context_window_tokens"]
        )
        self._last_usage: dict = {}

        self._client = OpenAI(
            api_key=self._api_key,
            base_url=self._base_url,
            timeout=timeout or AI_DEFAULTS["timeout"],
        )

    def analyze(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = AI_DEFAULTS["temperature"],
        max_tokens: int | None = None,
    ) -> str:
        """同步分析调用"""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        prompt_chars = sum(len(m["content"]) for m in messages)
        logger.info(f"发送 AI 请求: {len(messages)} 条消息, {prompt_chars} 字符")

        start = time.time()
        response = self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens if max_tokens is not None else self._max_tokens,
        )
        elapsed = time.time() - start

        result = response.choices[0].message.content or ""
        usage = response.usage
        self._last_usage = {}
        if usage:
            self._last_usage = {
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens,
            }
        logger.info(
            f"AI 响应: {len(result)} 字符, {elapsed:.1f}s, "
            f"tokens={usage.total_tokens if usage else 'N/A'}"
        )

        return result

    def analyze_stream(
        self,
        prompt: str,
        system_prompt: str = "",
        on_chunk: Callable[[str], None] | None = None,
        temperature: float = AI_DEFAULTS["temperature"],
        max_tokens: int | None = None,
    ) -> str:
        """流式分析调用"""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        prompt_chars = sum(len(m["content"]) for m in messages)
        logger.info(f"发送流式 AI 请求: {prompt_chars} 字符")

        start = time.time()
        stream = self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens if max_tokens is not None else self._max_tokens,
            stream=True,
        )

        collected: list[str] = []
        for chunk in stream:
            delta = chunk.choices[0].delta
            if delta.content:
                collected.append(delta.content)
                if on_chunk:
                    on_chunk(delta.content)

        elapsed = time.time() - start
        result = "".join(collected)
        self._last_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "estimated": True,
            "prompt_chars": prompt_chars,
            "response_chars": len(result),
        }
        logger.info(f"流式 AI 响应完成: {len(result)} 字符, {elapsed:.1f}s")

        return result

    @property
    def last_usage(self) -> dict:
        return self._last_usage.copy()

    def test_connection(self) -> tuple[bool, str]:
        """测试 API 连接"""
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": "Hi"}],
                max_tokens=10,
                temperature=0,
            )
            return True, f"连接成功，模型: {self._model}"
        except Exception as e:
            error_msg = str(e)[:200]
            logger.error(f"API 连接测试失败: {error_msg}")
            return False, f"连接失败: {error_msg}"
