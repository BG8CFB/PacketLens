"""故障检测子模块

提供网络故障检测能力（与 storm/ 模块的安全风暴检测互补）：
- ARP 欺骗检测
- TCP 健康度（重传/零窗口/RST 风暴）
- ICMP 错误模式（不可达/超时/重定向）
- TTL 异常（路由环路/不对称路由）
- DNS 解析失败
- IP 分片异常
- 突发流量峰值
"""

from __future__ import annotations

from app.preprocessing.fault.fault_detector import FaultDetector
from app.preprocessing.fault.counter import FaultCounter

__all__ = ["FaultDetector", "FaultCounter"]
