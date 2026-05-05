"""ARP 泛洪检测器单元测试"""

from __future__ import annotations

import pytest

from app.preprocessing.storm.arp_detector import ARPFloodDetector
from app.preprocessing.storm.counter import StormCounter
from app.preprocessing.storm.thresholds import (
    ARP_FLOOD_PACKET_THRESHOLD,
    ARP_FLOOD_RATE_THRESHOLD,
)


class TestARPFloodDetector:
    def test_detect_at_threshold(self):
        detector = ARPFloodDetector()
        counter = StormCounter()
        counter.arp_count = ARP_FLOOD_PACKET_THRESHOLD
        counter.arp_request = 80
        counter.arp_reply = 20
        duration = ARP_FLOOD_PACKET_THRESHOLD / ARP_FLOOD_RATE_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.type == "arp_flood"
        assert alert.severity == "Warning"
        assert "ARP 泛洪" in alert.description
        assert alert.detail["packet_count"] == ARP_FLOOD_PACKET_THRESHOLD
        assert alert.detail["request_count"] == 80
        assert alert.detail["reply_count"] == 20

    def test_critical_at_500_packets(self):
        detector = ARPFloodDetector()
        counter = StormCounter()
        counter.arp_count = 500
        counter.arp_request = 400
        counter.arp_reply = 100
        duration = 500 / ARP_FLOOD_RATE_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration)

        assert len(alerts) == 1
        assert alerts[0].severity == "Critical"

    def test_no_alert_below_packet_threshold(self):
        detector = ARPFloodDetector()
        counter = StormCounter()
        counter.arp_count = ARP_FLOOD_PACKET_THRESHOLD - 1
        duration = 10.0
        alerts = detector.detect_from_counter(counter, duration)
        assert len(alerts) == 0

    def test_no_alert_below_rate_threshold(self):
        detector = ARPFloodDetector()
        counter = StormCounter()
        counter.arp_count = ARP_FLOOD_PACKET_THRESHOLD
        duration = 30.0  # ~3.3 pkt/s < 5
        alerts = detector.detect_from_counter(counter, duration)
        assert len(alerts) == 0

    def test_no_alert_zero_duration(self):
        detector = ARPFloodDetector()
        counter = StormCounter()
        counter.arp_count = ARP_FLOOD_PACKET_THRESHOLD
        alerts = detector.detect_from_counter(counter, duration=0.0)
        assert len(alerts) == 0

    def test_only_arp_packets_counted(self):
        detector = ARPFloodDetector()
        counter = StormCounter()
        counter.broadcast_count = 200  # 广播包多，但 ARP 少
        counter.arp_count = ARP_FLOOD_PACKET_THRESHOLD - 1
        duration = 10.0
        alerts = detector.detect_from_counter(counter, duration)
        assert len(alerts) == 0
