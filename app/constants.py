"""全局常量 — 非配置类常量（颜色、协议、阈值等）

AI 配置加载逻辑已迁移至 app/config/provider_loader.py。
AI 可配置参数的默认值定义在 app/config/ai_defaults.py。
"""

# 向后兼容重导出（其他模块可能仍从此处 import）
from app.config.provider_loader import load_builtin_provider  # noqa: F401

# 应用信息
APP_NAME = "PacketLens"
APP_VERSION = "1.0.0"
REPO_URL = "https://github.com/BG8CFB/PacketLens"

# 抓包配置
DEFAULT_CAPTURE_DURATION = 20  # 秒
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
    "QUIC": "#CC44CC",
}

# 存储配置
DEFAULT_HISTORY_RETENTION_DAYS = 30
MAX_PCAP_FILE_SIZE_MB = 500

# 流聚合超时（秒）
TCP_FLOW_TIMEOUT = 60
UDP_FLOW_TIMEOUT = 30
ICMP_FLOW_TIMEOUT = 30
DEFAULT_FLOW_TIMEOUT = 120
