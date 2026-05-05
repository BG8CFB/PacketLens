"""组播泛洪检测器单元测试"""

from __future__ import annotations

import pytest

from app.preprocessing.storm.multicast_detector import MulticastDetector
from app.preprocessing.storm.counter import StormCounter
from app.preprocessing.storm.thresholds import (
    MULTICAST_FLOOD_CRITICAL_THRESHOLD,
    MULTICAST_FLOOD_PACKET_THRESHOLD,
    MULTICAST_FLOOD_RATE_THRESHOLD,
)


class TestMulticastDetector:
    def test_detect_at_threshold(self):
        detector = MulticastDetector()
        counter = StormCounter()
        counter.multicast_count = MULTICAST_FLOOD_PACKET_THRESHOLD
        counter.multicast_bytes = MULTICAST_FLOOD_PACKET_THRESHOLD * 60
        duration = MULTICAST_FLOOD_PACKET_THRESHOLD / MULTICAST_FLOOD_RATE_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.type == "multicast_flood"
        assert alert.severity == "Warning"
        assert "组播泛洪" in alert.description
        assert alert.detail["packet_count"] == MULTICAST_FLOOD_PACKET_THRESHOLD
        assert alert.detail["rate_pps"] == MULTICAST_FLOOD_RATE_THRESHOLD

    def test_no_alert_below_packet_threshold(self):
        detector = MulticastDetector()
        counter = StormCounter()
        counter.multicast_count = MULTICAST_FLOOD_PACKET_THRESHOLD - 1
        duration = 10.0
        alerts = detector.detect_from_counter(counter, duration)
        assert len(alerts) == 0

    def test_no_alert_below_rate_threshold(self):
        detector = MulticastDetector()
        counter = StormCounter()
        counter.multicast_count = MULTICAST_FLOOD_PACKET_THRESHOLD
        duration = 20.0  # 5 pkt/s < 10
        alerts = detector.detect_from_counter(counter, duration)
        assert len(alerts) == 0

    def test_no_alert_zero_duration(self):
        detector = MulticastDetector()
        counter = StormCounter()
        counter.multicast_count = MULTICAST_FLOOD_PACKET_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration=0.0)
        assert len(alerts) == 0

    def test_critical_at_500_packets(self):
        detector = MulticastDetector()
        counter = StormCounter()
        counter.multicast_count = MULTICAST_FLOOD_CRITICAL_THRESHOLD
        counter.multicast_bytes = counter.multicast_count * 60
        duration = MULTICAST_FLOOD_CRITICAL_THRESHOLD / MULTICAST_FLOOD_RATE_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration)

        assert len(alerts) == 1
        assert alerts[0].severity == "Critical"
