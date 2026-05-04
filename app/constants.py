"""全局常量 — 非配置类常量（颜色、协议、阈值等）

AI 可配置参数的默认值定义在 app/config/ai_defaults.py。
内置 provider 的具体值从 .env 的 AI_* 环境变量加载。
"""

import os

from app.config.ai_defaults import AI_DEFAULTS

# 应用信息
APP_NAME = "PacketLens"
APP_VERSION = "1.0.0"

# 内置 provider 缓存（首次调用后缓存，避免重复扫描环境变量）
_builtin_provider_cache: dict | None = None


def load_builtin_provider() -> dict | None:
    """从环境变量加载内置 AI Provider 配置

    环境变量格式：AI_NAME, AI_API_BASE, AI_API_KEY, AI_MODEL, 以及可选的
    AI_CONTEXT_WINDOW, AI_MAX_TOKENS, AI_TEMPERATURE, AI_TIMEOUT。

    Returns:
        provider dict（含 is_default=True）或 None（AI_NAME 为空时）
    """
    global _builtin_provider_cache
    if _builtin_provider_cache is not None:
        return _builtin_provider_cache

    name = os.environ.get("AI_NAME", "").strip()
    if not name:
        _builtin_provider_cache = None
        return None

    provider = {
        "name": name,
        "api_base": os.environ.get("AI_API_BASE", "").strip(),
        "api_key": os.environ.get("AI_API_KEY", "").strip(),
        "model": os.environ.get("AI_MODEL", "").strip(),
        "context_window_tokens": int(os.environ.get("AI_CONTEXT_WINDOW") or AI_DEFAULTS["context_window_tokens"]),
        "max_tokens": int(os.environ.get("AI_MAX_TOKENS") or AI_DEFAULTS["max_tokens"]),
        "temperature": float(os.environ.get("AI_TEMPERATURE") or AI_DEFAULTS["temperature"]),
        "timeout": int(os.environ.get("AI_TIMEOUT") or AI_DEFAULTS["timeout"]),
        "is_default": True,
    }

    _builtin_provider_cache = provider
    return provider

# 抓包配置
DEFAULT_CAPTURE_DURATION = 60  # 秒
MIN_CAPTURE_DURATION = 10
MAX_CAPTURE_DURATION = 300
SNAPLEN = 65535
CAPTURE_POLL_INTERVAL_MS = 100  # QTimer 轮询间隔

# PCAP 写入
PCAP_QUEUE_SIZE = 50000  # PCAP 写入队列容量

# 严重级别
SEVERITY_CRITICAL = "Critical"
SEVERITY_WARNING = "Warning"
SEVERITY_INFO = "Info"
SEVERITY_NORMAL = "Normal"

SEVERITY_COLORS = {
    SEVERITY_CRITICAL: "#FF4444",
    SEVERITY_WARNING: "#FFB020",
    SEVERITY_INFO: "#4488FF",
    SEVERITY_NORMAL: "#44BB44",
}

# 协议颜色
PROTOCOL_COLORS = {
    "TCP": "#4488CC",
    "UDP": "#44AA44",
    "ICMP": "#CC4444",
    "ARP": "#CC8844",
    "DNS": "#8844CC",
    "TLS": "#CC44AA",
    "HTTP": "#44CCAA",
}

# 存储配置
DEFAULT_HISTORY_RETENTION_DAYS = 30
MAX_PCAP_FILE_SIZE_MB = 500

# 流聚合超时（秒）
TCP_FLOW_TIMEOUT = 60
UDP_FLOW_TIMEOUT = 30
ICMP_FLOW_TIMEOUT = 30
DEFAULT_FLOW_TIMEOUT = 120
