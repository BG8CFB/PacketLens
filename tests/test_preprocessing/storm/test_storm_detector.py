"""StormDetector 集成测试"""

from __future__ import annotations

import pytest

from app.preprocessing.storm.storm_detector import StormDetector
from app.preprocessing.storm.counter import StormCounter
from app.preprocessing.storm.thresholds import (
    BROADCAST_STORM_PACKET_THRESHOLD,
    BROADCAST_STORM_RATE_THRESHOLD,
    MULTICAST_FLOOD_PACKET_THRESHOLD,
    MULTICAST_FLOOD_RATE_THRESHOLD,
    ARP_FLOOD_PACKET_THRESHOLD,
    ARP_FLOOD_RATE_THRESHOLD,
    ICMP_FLOOD_PACKET_THRESHOLD,
    ICMP_FLOOD_RATE_THRESHOLD,
)


class TestStormDetectorIntegration:
    def test_empty_counter_returns_empty(self):
        detector = StormDetector()
        counter = StormCounter()
        alerts = detector.detect_from_counter(counter, duration=10.0)
        assert alerts == []

    def test_single_detector_triggered(self):
        detector = StormDetector()
        counter = StormCounter()
        counter.broadcast_count = BROADCAST_STORM_PACKET_THRESHOLD
        counter.broadcast_bytes = counter.broadcast_count * 60
        duration = BROADCAST_STORM_PACKET_THRESHOLD / BROADCAST_STORM_RATE_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration)

        assert len(alerts) == 1
        assert alerts[0]["type"] == "broadcast_storm"
        assert alerts[0]["severity"] == "Warning"
        assert "affected_flows" in alerts[0]
        assert "detail" in alerts[0]

    def test_multiple_detectors_triggered(self):
        detector = StormDetector()
        counter = StormCounter()
        counter.broadcast_count = BROADCAST_STORM_PACKET_THRESHOLD
        counter.broadcast_bytes = counter.broadcast_count * 60
        counter.multicast_count = MULTICAST_FLOOD_PACKET_THRESHOLD
        counter.multicast_bytes = counter.multicast_count * 60
        counter.arp_count = ARP_FLOOD_PACKET_THRESHOLD
        counter.arp_request = 80
        counter.arp_reply = 20
        counter.icmp_echo_request = ICMP_FLOOD_PACKET_THRESHOLD
        counter.icmp_echo_reply = 50

        # 使用一个所有检测器都能触发的时长
        # 广播/组播/ICMP: 100包 / 10 pkt/s = 10s
        # ARP: 100包 / 5 pkt/s = 20s, 但在 10s 时速率=10 >= 5 也触发
        duration = 10.0

        alerts = detector.detect_from_counter(counter, duration)

        assert len(alerts) == 4
        types = {a["type"] for a in alerts}
        assert "broadcast_storm" in types
        assert "multicast_flood" in types
        assert "arp_flood" in types
        assert "icmp_flood" in types

    def test_dict_output_format(self):
        detector = StormDetector()
        counter = StormCounter()
        counter.broadcast_count = BROADCAST_STORM_PACKET_THRESHOLD
        counter.broadcast_bytes = counter.broadcast_count * 60
        duration = BROADCAST_STORM_PACKET_THRESHOLD / BROADCAST_STORM_RATE_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration)

        alert = alerts[0]
        assert isinstance(alert, dict)
        assert set(alert.keys()) == {"type", "severity", "description", "affected_flows", "detail"}

    def test_duration_zero_returns_empty(self):
        detector = StormDetector()
        counter = StormCounter()
        counter.broadcast_count = 9999
        counter.arp_count = 9999
        counter.icmp_echo_request = 9999
        alerts = detector.detect_from_counter(counter, duration=0.0)
        assert alerts == []

    def test_partial_trigger(self):
        """只有部分检测器触发"""
        detector = StormDetector()
        counter = StormCounter()
        counter.broadcast_count = BROADCAST_STORM_PACKET_THRESHOLD
        counter.broadcast_bytes = counter.broadcast_count * 60
        counter.arp_count = ARP_FLOOD_PACKET_THRESHOLD - 1  # 不触发
        duration = BROADCAST_STORM_PACKET_THRESHOLD / BROADCAST_STORM_RATE_THRESHOLD

        alerts = detector.detect_from_counter(counter, duration)

        assert len(alerts) == 1
        assert alerts[0]["type"] == "broadcast_storm"
