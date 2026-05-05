"""内置 AI Provider 环境变量加载器

从 .env 中的 AI_* 环境变量加载内置默认 Provider 配置。
此模块仅负责读取环境变量并组装 dict，不涉及持久化。
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from app.config.ai_defaults import AI_DEFAULTS

logger = logging.getLogger(__name__)


def _safe_int(val, default: int) -> int:
    """安全转换为 int，非法值返回 default"""
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _safe_float(val, default: float) -> float:
    """安全转换为 float，非法值返回 default"""
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


# 缓存哨兵：区分"未加载"与"已确认无 provider"
_NOT_LOADED = object()
# 内置 provider 缓存（首次调用后缓存，避免重复扫描环境变量）
_builtin_provider_cache: dict | None = _NOT_LOADED  # type: ignore[assignment]
_dotenv_loaded = False


def _ensure_dotenv_loaded() -> None:
    """确保 .env 已加载到当前进程环境

    GUI 启动时会在 main.py 提前加载 .env，但测试、脚本或直接导入
    ConfigManager/ProviderLoader 时不会经过 main.py，因此这里需要兜底。
    """
    global _dotenv_loaded
    if _dotenv_loaded:
        return

    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.exists():
        _dotenv_loaded = True
        return

    try:
        from dotenv import load_dotenv
        load_dotenv(env_path, override=False)
    except ImportError:
        logger.debug("python-dotenv 未安装，跳过 .env 自动加载")

    _dotenv_loaded = True


def load_builtin_provider() -> dict | None:
    """从环境变量加载内置 AI Provider 配置

    环境变量格式：AI_NAME, AI_API_BASE, AI_API_KEY, AI_MODEL, 以及可选的
    AI_PROVIDER_TYPE, AI_CONTEXT_WINDOW, AI_MAX_TOKENS, AI_TEMPERATURE, AI_TIMEOUT。

    Returns:
        provider dict（含 is_default=True）或 None（AI_NAME 为空时）
    """
    global _builtin_provider_cache
    _ensure_dotenv_loaded()

    if _builtin_provider_cache is not _NOT_LOADED:
        return _builtin_provider_cache

    name = os.environ.get("AI_NAME", "").strip()
    api_key = os.environ.get("AI_API_KEY", "").strip()
    model = os.environ.get("AI_MODEL", "").strip()
    if not name or not api_key or not model:
        # 三项必填：名称、密钥、模型，缺少任意一项均视为未配置
        logger.debug("内置 Provider 环境变量不完整（需要 AI_NAME, AI_API_KEY, AI_MODEL）")
        _builtin_provider_cache = None
        return None

    provider = {
        "name": name,
        "provider_type": os.environ.get("AI_PROVIDER_TYPE", "openai").strip(),
        "api_base": os.environ.get("AI_API_BASE", "").strip(),
        "api_key": api_key,
        "model": model,
        "context_window_tokens": _safe_int(
            os.environ.get("AI_CONTEXT_WINDOW") or AI_DEFAULTS["context_window_tokens"],
            AI_DEFAULTS["context_window_tokens"],
        ),
        "max_tokens": _safe_int(
            os.environ.get("AI_MAX_TOKENS") or AI_DEFAULTS["max_tokens"],
            AI_DEFAULTS["max_tokens"],
        ),
        "temperature": _safe_float(
            os.environ.get("AI_TEMPERATURE") or AI_DEFAULTS["temperature"],
            AI_DEFAULTS["temperature"],
        ),
        "max_input_chars": _safe_int(
            os.environ.get("AI_MAX_INPUT_CHARS") or AI_DEFAULTS["max_input_chars"],
            AI_DEFAULTS["max_input_chars"],
        ),
        "timeout": _safe_int(
            os.environ.get("AI_TIMEOUT") or AI_DEFAULTS["timeout"],
            AI_DEFAULTS["timeout"],
        ),
        "max_concurrency": _safe_int(
            os.environ.get("AI_MAX_CONCURRENCY") or AI_DEFAULTS["max_concurrency"],
            AI_DEFAULTS["max_concurrency"],
        ),
        "max_layer2_flows": _safe_int(
            os.environ.get("AI_MAX_LAYER2_FLOWS") or AI_DEFAULTS["max_layer2_flows"],
            AI_DEFAULTS["max_layer2_flows"],
        ),
        "is_default": True,
    }

    _builtin_provider_cache = provider
    return provider


def reset_builtin_provider_cache() -> None:
    """重置内置 provider 缓存，强制下次调用重新读取环境变量

    用途：
    - 测试隔离（不再依赖私有变量直接赋值）
    - AI_* 环境变量在运行期发生变化时主动失效

    注意：本函数仅重置内存缓存，不会重新加载 .env 文件。
    若需要刷新 .env，请使用 ``dotenv.load_dotenv(override=True)``。
    """
    global _builtin_provider_cache
    _builtin_provider_cache = _NOT_LOADED  # type: ignore[assignment]
