"""ARP 泛洪检测器"""

from __future__ import annotations

from app.preprocessing.storm.base import StormAlert
from app.preprocessing.storm.counter import StormCounter
from app.preprocessing.storm.thresholds import (
    ARP_FLOOD_CRITICAL_THRESHOLD,
    ARP_FLOOD_PACKET_THRESHOLD,
    ARP_FLOOD_RATE_THRESHOLD,
)


class ARPFloodDetector:
    """检测 ARP 泛洪：大量 ARP 请求/响应包"""

    def detect_from_counter(self, counter: StormCounter, duration: float) -> list[StormAlert]:
        if duration <= 0:
            return []

        if counter.arp_count < ARP_FLOOD_PACKET_THRESHOLD:
            return []

        rate = counter.arp_count / duration
        if rate < ARP_FLOOD_RATE_THRESHOLD:
            return []

        severity = "Critical" if counter.arp_count >= ARP_FLOOD_CRITICAL_THRESHOLD else "Warning"

        return [StormAlert(
            type="arp_flood",
            severity=severity,
            description=f"检测到 ARP 泛洪: {counter.arp_count} 个 ARP 包, "
                       f"速率 {rate:.1f} pkt/s (Request: {counter.arp_request}, Reply: {counter.arp_reply})",
            detail={
                "packet_count": counter.arp_count,
                "rate_pps": round(rate, 1),
                "request_count": counter.arp_request,
                "reply_count": counter.arp_reply,
            },
        )]
