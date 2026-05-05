"""ICMP 泛洪检测器"""

from __future__ import annotations

from app.preprocessing.storm.base import StormAlert
from app.preprocessing.storm.counter import StormCounter
from app.preprocessing.storm.thresholds import (
    ICMP_FLOOD_CRITICAL_THRESHOLD,
    ICMP_FLOOD_PACKET_THRESHOLD,
    ICMP_FLOOD_RATE_THRESHOLD,
)


class ICMPFloodDetector:
    """检测 ICMP 泛洪（ping flood）：大量 ICMP Echo Request"""

    def detect_from_counter(self, counter: StormCounter, duration: float) -> list[StormAlert]:
        if duration <= 0:
            return []

        # 只统计 Echo Request，不统计 Reply 或其他 ICMP 类型
        echo_requests = counter.icmp_echo_request

        if echo_requests < ICMP_FLOOD_PACKET_THRESHOLD:
            return []

        rate = echo_requests / duration
        if rate < ICMP_FLOOD_RATE_THRESHOLD:
            return []

        severity = "Critical" if echo_requests >= ICMP_FLOOD_CRITICAL_THRESHOLD else "Warning"

        return [StormAlert(
            type="icmp_flood",
            severity=severity,
            description=f"检测到 ICMP 泛洪: {echo_requests} 个 Echo Request, "
                       f"速率 {rate:.1f} pkt/s (Reply: {counter.icmp_echo_reply})",
            detail={
                "packet_count": echo_requests,
                "rate_pps": round(rate, 1),
                "echo_request_count": counter.icmp_echo_request,
                "echo_reply_count": counter.icmp_echo_reply,
            },
        )]
