"""AI 组件工厂 — 统一创建 AIEngine、PromptBuilder、ResultParser

UI 层（main_window、settings_dialog）通过此工厂创建 AI 组件，
不直接依赖 AIEngine 的构造参数细节。
"""

from __future__ import annotations

from app.ai.ai_engine import AIEngine
from app.ai.prompt_builder import PromptBuilder
from app.ai.result_parser import ResultParser


def create_ai_engine(ai_config: dict) -> AIEngine:
    """根据 AI 配置创建 AIEngine 实例

    Args:
        ai_config: 来自 ConfigManager.get_ai_config() 的配置 dict
    """
    return AIEngine(
        provider_type=ai_config["provider_type"],
        api_key=ai_config["api_key"],
        base_url=ai_config["base_url"],
        model=ai_config["model"],
        timeout=ai_config["timeout"],
        context_window_tokens=ai_config["context_window_tokens"],
        max_tokens=ai_config["max_tokens"],
        max_input_chars=ai_config.get("max_input_chars"),
    )


def create_prompt_builder(ai_config: dict) -> PromptBuilder:
    """根据 AI 配置创建 PromptBuilder 实例"""
    return PromptBuilder(
        context_window_tokens=ai_config["context_window_tokens"],
        max_input_chars=ai_config.get("max_input_chars"),
    )


def create_result_parser() -> ResultParser:
    """创建 ResultParser 实例"""
    return ResultParser()


def test_connection(ai_config: dict) -> tuple[bool, str]:
    """测试 AI API 连接

    Args:
        ai_config: Provider 配置（可包含额外字段如 context_window_tokens 等）

    Returns:
        (ok, message)
    """
    engine = create_ai_engine(ai_config)
    return engine.test_connection()
