"""广播风暴检测器"""

from __future__ import annotations

from app.preprocessing.storm.base import StormAlert
from app.preprocessing.storm.counter import StormCounter
from app.preprocessing.storm.thresholds import (
    BROADCAST_STORM_CRITICAL_THRESHOLD,
    BROADCAST_STORM_PACKET_THRESHOLD,
    BROADCAST_STORM_RATE_THRESHOLD,
)


class BroadcastDetector:
    """检测广播风暴：大量广播包冲击网络"""

    def detect_from_counter(self, counter: StormCounter, duration: float) -> list[StormAlert]:
        if duration <= 0:
            return []

        if counter.broadcast_count < BROADCAST_STORM_PACKET_THRESHOLD:
            return []

        rate = counter.broadcast_count / duration
        if rate < BROADCAST_STORM_RATE_THRESHOLD:
            return []

        bandwidth_bps = (counter.broadcast_bytes * 8) / duration
        severity = "Critical" if counter.broadcast_count >= BROADCAST_STORM_CRITICAL_THRESHOLD else "Warning"

        return [StormAlert(
            type="broadcast_storm",
            severity=severity,
            description=f"检测到广播风暴: {counter.broadcast_count} 个广播包, "
                       f"速率 {rate:.1f} pkt/s, 带宽 {bandwidth_bps:.0f} bps",
            detail={
                "packet_count": counter.broadcast_count,
                "rate_pps": round(rate, 1),
                "total_bytes": counter.broadcast_bytes,
                "bandwidth_bps": round(bandwidth_bps, 0),
            },
        )]
