"""广播风暴检测器单元测试"""

from __future__ import annotations

import pytest

from app.preprocessing.storm.broadcast_detector import BroadcastDetector
from app.preprocessing.storm.counter import StormCounter
from app.preprocessing.storm.thresholds import (
    BROADCAST_STORM_CRITICAL_THRESHOLD,
    BROADCAST_STORM_PACKET_THRESHOLD,
    BROADCAST_STORM_RATE_THRESHOLD,
)


class TestBroadcastDetector:
    def test_detect_at_threshold(self):
        detector = BroadcastDetector()
        counter = StormCounter()
        counter.broadcast_count = BROADCAST_STORM_PACKET_THRESHOLD
        counter.broadcast_bytes = BROADCAST_STORM_PACKET_THRESHOLD * 60
        duration = BROADCAST_STORM_PACKET_THRESHOLD / BROADCAST_STORM_RATE_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.type == "broadcast_storm"
        assert alert.severity == "Warning"
        assert "广播风暴" in alert.description
        assert alert.detail["packet_count"] == BROADCAST_STORM_PACKET_THRESHOLD
        assert alert.detail["rate_pps"] == BROADCAST_STORM_RATE_THRESHOLD

    def test_no_alert_below_packet_threshold(self):
        detector = BroadcastDetector()
        counter = StormCounter()
        counter.broadcast_count = BROADCAST_STORM_PACKET_THRESHOLD - 1
        counter.broadcast_bytes = counter.broadcast_count * 60
        duration = 10.0
        alerts = detector.detect_from_counter(counter, duration)
        assert len(alerts) == 0

    def test_no_alert_below_rate_threshold(self):
        detector = BroadcastDetector()
        counter = StormCounter()
        counter.broadcast_count = BROADCAST_STORM_PACKET_THRESHOLD
        counter.broadcast_bytes = counter.broadcast_count * 60
        # 速率低于阈值: 100包 / 20秒 = 5 pkt/s < 10
        duration = 20.0
        alerts = detector.detect_from_counter(counter, duration)
        assert len(alerts) == 0

    def test_no_alert_zero_duration(self):
        detector = BroadcastDetector()
        counter = StormCounter()
        counter.broadcast_count = BROADCAST_STORM_PACKET_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration=0.0)
        assert len(alerts) == 0

    def test_no_alert_negative_duration(self):
        detector = BroadcastDetector()
        counter = StormCounter()
        counter.broadcast_count = BROADCAST_STORM_PACKET_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration=-1.0)
        assert len(alerts) == 0

    def test_description_contains_bandwidth(self):
        detector = BroadcastDetector()
        counter = StormCounter()
        counter.broadcast_count = 200
        counter.broadcast_bytes = 200 * 100  # 每包 100 字节
        duration = 10.0  # 20 pkt/s
        alerts = detector.detect_from_counter(counter, duration)
        assert len(alerts) == 1
        assert "bps" in alerts[0].description
        # 带宽 = 200 * 100 * 8 / 10 = 16000 bps
        assert alerts[0].detail["bandwidth_bps"] == 16000.0

    def test_critical_at_500_packets(self):
        detector = BroadcastDetector()
        counter = StormCounter()
        counter.broadcast_count = BROADCAST_STORM_CRITICAL_THRESHOLD
        counter.broadcast_bytes = counter.broadcast_count * 60
        duration = BROADCAST_STORM_CRITICAL_THRESHOLD / BROADCAST_STORM_RATE_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration)

        assert len(alerts) == 1
        assert alerts[0].severity == "Critical"

    def test_affected_flows_is_empty(self):
        detector = BroadcastDetector()
        counter = StormCounter()
        counter.broadcast_count = BROADCAST_STORM_PACKET_THRESHOLD
        counter.broadcast_bytes = counter.broadcast_count * 60
        duration = BROADCAST_STORM_PACKET_THRESHOLD / BROADCAST_STORM_RATE_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration)
        assert alerts[0].affected_flows == []
