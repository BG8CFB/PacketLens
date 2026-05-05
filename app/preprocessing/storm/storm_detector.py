"""风暴检测编排入口

聚合四种检测器，统一输出 anomalies 格式。
"""

from __future__ import annotations

from app.preprocessing.storm.base import StormAlert
from app.preprocessing.storm.broadcast_detector import BroadcastDetector
from app.preprocessing.storm.counter import StormCounter
from app.preprocessing.storm.multicast_detector import MulticastDetector
from app.preprocessing.storm.arp_detector import ARPFloodDetector
from app.preprocessing.storm.icmp_detector import ICMPFloodDetector


class StormDetector:
    """风暴检测编排器 — 聚合广播风暴、组播泛洪、ARP 泛洪、ICMP 泛洪检测"""

    def __init__(self) -> None:
        self._detectors = [
            BroadcastDetector(),
            MulticastDetector(),
            ARPFloodDetector(),
            ICMPFloodDetector(),
        ]

    def detect_from_counter(self, counter: StormCounter, duration: float) -> list[dict]:
        """基于计数器执行所有风暴检测

        Args:
            counter: 抓包过程中累积的 StormCounter
            duration: 抓包时长（秒），用于计算速率

        Returns:
            与 AnomalyMarker 输出格式统一的 anomalies 列表
        """
        alerts: list[StormAlert] = []
        for detector in self._detectors:
            alerts.extend(detector.detect_from_counter(counter, duration))
        return [a.to_dict() for a in alerts]
