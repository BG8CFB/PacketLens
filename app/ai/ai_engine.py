"""AI Engine — 通过 LangChain 调用 OpenAI/Anthropic API"""

from __future__ import annotations

import logging
import time
from typing import Callable

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from app.ai.llm_factory import LLMFactory, PROVIDER_TYPE_OPENAI
from app.config.ai_defaults import AI_DEFAULTS

logger = logging.getLogger(__name__)


class AIEngine:
    """AI API 接口 (LangChain 版)

    使用 LangChain BaseChatModel 统一调用 OpenAI 兼容协议和 Anthropic 协议。
    不做输入截断——由 PromptBuilder 在构建阶段通过智能采样控制数据量。
    """

    def __init__(
        self,
        provider_type: str = PROVIDER_TYPE_OPENAI,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
        context_window_tokens: int | None = None,
        max_tokens: int | None = None,
        max_input_chars: int | None = None,
        temperature: float | None = None,
    ):
        self._provider_type = provider_type
        self._api_key = api_key or ""
        if not self._api_key:
            logger.warning("AI Engine 初始化时 api_key 为空，后续分析调用将失败")
        self._base_url = base_url or ""
        self._model = model or ""
        self._temperature = temperature if temperature is not None else AI_DEFAULTS["temperature"]
        self._max_tokens = max_tokens if max_tokens is not None else AI_DEFAULTS["max_tokens"]
        self._timeout = timeout or AI_DEFAULTS["timeout"]
        self._context_window_tokens = (
            context_window_tokens if context_window_tokens is not None
            else AI_DEFAULTS["context_window_tokens"]
        )
        self._max_input_chars = (
            max_input_chars if max_input_chars is not None
            else AI_DEFAULTS["max_input_chars"]
        )
        self._last_usage: dict = {}

        self._llm: BaseChatModel = LLMFactory.create(
            provider_type=self._provider_type,
            api_key=self._api_key,
            base_url=self._base_url,
            model=self._model,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
            timeout=self._timeout,
        )

    @property
    def provider_type(self) -> str:
        return self._provider_type

    def analyze(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """同步分析调用"""
        if not self._api_key:
            raise ValueError("API Key 未配置，请在设置中配置 AI 模型的 API Key")

        messages = self._build_messages(prompt, system_prompt)
        prompt_chars = sum(len(m.content) for m in messages)
        self._check_input_length(prompt_chars)
        logger.info(f"发送 AI 请求: {len(messages)} 条消息, {prompt_chars} 字符")

        start = time.time()
        llm = self._llm_with_overrides(temperature, max_tokens)
        response = llm.invoke(messages)
        elapsed = time.time() - start

        result = response.content or ""
        self._extract_usage(response)
        logger.info(
            f"AI 响应: {len(result)} 字符, {elapsed:.1f}s, "
            f"tokens={self._last_usage.get('total_tokens', 'N/A')}"
        )

        return result

    def analyze_stream(
        self,
        prompt: str,
        system_prompt: str = "",
        on_chunk: Callable[[str], None] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """流式分析调用"""
        if not self._api_key:
            raise ValueError("API Key 未配置，请在设置中配置 AI 模型的 API Key")

        messages = self._build_messages(prompt, system_prompt)
        prompt_chars = sum(len(m.content) for m in messages)
        self._check_input_length(prompt_chars)
        logger.info(f"发送流式 AI 请求: {prompt_chars} 字符")

        start = time.time()
        llm = self._llm_with_overrides(temperature, max_tokens)
        collected: list[str] = []
        last_chunk = None

        for chunk in llm.stream(messages):
            if chunk.content:
                collected.append(chunk.content)
                if on_chunk:
                    on_chunk(chunk.content)
            last_chunk = chunk

        elapsed = time.time() - start
        result = "".join(collected)

        # 尝试从最后一个 chunk 提取 usage
        if last_chunk is not None:
            self._extract_usage(last_chunk)
        if not self._last_usage:
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

    def test_connection(self) -> tuple[bool, str]:
        """测试 API 连接"""
        if not self._api_key:
            return False, "API Key 未配置，请在设置中配置 AI 模型的 API Key"
        try:
            messages = [HumanMessage(content="Hi")]
            # 使用绑定了小 max_tokens 的 LLM 避免浪费
            test_llm = self._llm.bind(max_tokens=10)
            test_llm.invoke(messages)
            return True, f"连接成功，模型: {self._model}"
        except Exception as e:
            error_msg = str(e)[:200]
            logger.error(f"API 连接测试失败: {error_msg}")
            return False, f"连接失败: {error_msg}"

    @property
    def last_usage(self) -> dict:
        return self._last_usage.copy()

    def clone_for_worker(self, max_tokens: int | None = None) -> AIEngine:
        """为 Layer 2 工作线程创建独立实例（线程安全）

        复用当前 engine 的所有配置参数，创建新的 LLM 实例。
        """
        return AIEngine(
            provider_type=self._provider_type,
            api_key=self._api_key,
            base_url=self._base_url,
            model=self._model,
            timeout=self._timeout,
            context_window_tokens=self._context_window_tokens,
            max_tokens=max_tokens or self._max_tokens,
            max_input_chars=self._max_input_chars,
            temperature=self._temperature,
        )

    # ── 内部方法 ──

    def _check_input_length(self, prompt_chars: int) -> None:
        """检查输入长度是否超过安全上限，超出时记录警告

        不截断——由 PromptBuilder 在构建阶段通过智能采样控制数据量。
        但仍需在此处发出警告，以便排查 API 调用失败的原因。
        """
        if prompt_chars > self._max_input_chars:
            logger.warning(
                f"输入长度 {prompt_chars} 字符超过安全上限 "
                f"{self._max_input_chars}，API 调用可能因超出上下文窗口而失败"
            )

    @staticmethod
    def _build_messages(prompt: str, system_prompt: str) -> list:
        """构建 LangChain Message 列表"""
        messages = []
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        messages.append(HumanMessage(content=prompt))
        return messages

    def _llm_with_overrides(
        self,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> BaseChatModel:
        """返回带 per-call 参数覆盖的 LLM 实例"""
        if temperature is None and max_tokens is None:
            return self._llm

        kwargs = {}
        if temperature is not None:
            kwargs["temperature"] = temperature
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens
        return self._llm.bind(**kwargs)

    def _extract_usage(self, response) -> None:
        """从 LangChain response 中提取 token usage"""
        # 优先从 usage_metadata 提取（LangChain 统一字段）
        if hasattr(response, 'usage_metadata') and response.usage_metadata:
            um = response.usage_metadata
            self._last_usage = {
                "prompt_tokens": um.get("input_tokens", 0),
                "completion_tokens": um.get("output_tokens", 0),
                "total_tokens": um.get("total_tokens", 0),
            }
            return

        # 备用：从 response_metadata 中提取
        if hasattr(response, 'response_metadata') and response.response_metadata:
            meta = response.response_metadata
            usage = meta.get("token_usage", meta.get("usage", {}))
            if usage:
                self._last_usage = {
                    "prompt_tokens": usage.get("prompt_tokens", usage.get("input_tokens", 0)),
                    "completion_tokens": usage.get("completion_tokens", usage.get("output_tokens", 0)),
                    "total_tokens": usage.get("total_tokens", 0),
                }
                return

        self._last_usage = {}
