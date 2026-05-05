"""组播泛洪检测器"""

from __future__ import annotations

from app.preprocessing.storm.base import StormAlert
from app.preprocessing.storm.counter import StormCounter
from app.preprocessing.storm.thresholds import (
    MULTICAST_FLOOD_CRITICAL_THRESHOLD,
    MULTICAST_FLOOD_PACKET_THRESHOLD,
    MULTICAST_FLOOD_RATE_THRESHOLD,
)


class MulticastDetector:
    """检测组播泛洪：大量组播流量冲击网络"""

    def detect_from_counter(self, counter: StormCounter, duration: float) -> list[StormAlert]:
        if duration <= 0:
            return []

        if counter.multicast_count < MULTICAST_FLOOD_PACKET_THRESHOLD:
            return []

        rate = counter.multicast_count / duration
        if rate < MULTICAST_FLOOD_RATE_THRESHOLD:
            return []

        bandwidth_bps = (counter.multicast_bytes * 8) / duration
        severity = "Critical" if counter.multicast_count >= MULTICAST_FLOOD_CRITICAL_THRESHOLD else "Warning"

        return [StormAlert(
            type="multicast_flood",
            severity=severity,
            description=f"检测到组播泛洪: {counter.multicast_count} 个组播包, "
                       f"速率 {rate:.1f} pkt/s, 带宽 {bandwidth_bps:.0f} bps",
            detail={
                "packet_count": counter.multicast_count,
                "rate_pps": round(rate, 1),
                "total_bytes": counter.multicast_bytes,
                "bandwidth_bps": round(bandwidth_bps, 0),
            },
        )]
