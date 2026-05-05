"""ICMP 泛洪检测器单元测试"""

from __future__ import annotations

import pytest

from app.preprocessing.storm.icmp_detector import ICMPFloodDetector
from app.preprocessing.storm.counter import StormCounter
from app.preprocessing.storm.thresholds import (
    ICMP_FLOOD_CRITICAL_THRESHOLD,
    ICMP_FLOOD_PACKET_THRESHOLD,
    ICMP_FLOOD_RATE_THRESHOLD,
)


class TestICMPFloodDetector:
    def test_detect_at_threshold(self):
        detector = ICMPFloodDetector()
        counter = StormCounter()
        counter.icmp_echo_request = ICMP_FLOOD_PACKET_THRESHOLD
        counter.icmp_echo_reply = 50
        duration = ICMP_FLOOD_PACKET_THRESHOLD / ICMP_FLOOD_RATE_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.type == "icmp_flood"
        assert alert.severity == "Warning"
        assert "ICMP 泛洪" in alert.description
        assert alert.detail["packet_count"] == ICMP_FLOOD_PACKET_THRESHOLD
        assert alert.detail["echo_request_count"] == ICMP_FLOOD_PACKET_THRESHOLD
        assert alert.detail["echo_reply_count"] == 50

    def test_no_alert_below_threshold(self):
        detector = ICMPFloodDetector()
        counter = StormCounter()
        counter.icmp_echo_request = ICMP_FLOOD_PACKET_THRESHOLD - 1
        duration = 10.0
        alerts = detector.detect_from_counter(counter, duration)
        assert len(alerts) == 0

    def test_no_alert_below_rate_threshold(self):
        detector = ICMPFloodDetector()
        counter = StormCounter()
        counter.icmp_echo_request = ICMP_FLOOD_PACKET_THRESHOLD
        duration = 20.0  # 5 pkt/s < 10
        alerts = detector.detect_from_counter(counter, duration)
        assert len(alerts) == 0

    def test_echo_reply_not_counted(self):
        """只统计 Echo Request，Reply 多不应触发"""
        detector = ICMPFloodDetector()
        counter = StormCounter()
        counter.icmp_echo_reply = 200
        counter.icmp_echo_request = 10
        duration = 10.0
        alerts = detector.detect_from_counter(counter, duration)
        assert len(alerts) == 0

    def test_other_icmp_types_not_counted(self):
        """Destination Unreachable 等不应计入"""
        detector = ICMPFloodDetector()
        counter = StormCounter()
        counter.icmp_count = 200  # 总 ICMP 多
        counter.icmp_echo_request = 10  # 但 Echo Request 少
        duration = 10.0
        alerts = detector.detect_from_counter(counter, duration)
        assert len(alerts) == 0

    def test_critical_at_500_packets(self):
        detector = ICMPFloodDetector()
        counter = StormCounter()
        counter.icmp_echo_request = ICMP_FLOOD_CRITICAL_THRESHOLD
        counter.icmp_echo_reply = 50
        duration = ICMP_FLOOD_CRITICAL_THRESHOLD / ICMP_FLOOD_RATE_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration)

        assert len(alerts) == 1
        assert alerts[0].severity == "Critical"

    def test_no_alert_zero_duration(self):
        detector = ICMPFloodDetector()
        counter = StormCounter()
        counter.icmp_echo_request = ICMP_FLOOD_PACKET_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration=0.0)
        assert len(alerts) == 0
