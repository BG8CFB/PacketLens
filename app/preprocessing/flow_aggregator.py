"""实时五元组流聚合器"""

from __future__ import annotations

import hashlib
import logging
from typing import Iterator

from app.constants import (
    TCP_FLOW_TIMEOUT, UDP_FLOW_TIMEOUT,
    ICMP_FLOW_TIMEOUT, DEFAULT_FLOW_TIMEOUT,
)
from app.models.flow_record import FlowRecord
from app.models.packet_record import PacketRecord
from app.preprocessing.protocol_classifier import classify_service

logger = logging.getLogger(__name__)

MAX_EXPIRED_FLOWS = 10000


class FlowAggregator:
    """五元组流聚合器

    方向无关：A→B 和 B→A 归入同一条流。
    每包 O(1) 哈希表查找更新。
    支持流超时：超过超时时间的新包会创建新流而非续接旧流。
    """

    def __init__(self):
        self._flows: dict[str, FlowRecord] = {}
        self._expired_flows: list[FlowRecord] = []

    def update(self, packet: PacketRecord) -> None:
        """根据数据包更新流表"""
        if not packet.src_ip or not packet.dst_ip:
            return

        flow_key = self._compute_key(
            packet.src_ip, packet.dst_ip,
            packet.src_port or 0, packet.dst_port or 0,
            packet.protocol,
        )

        if flow_key in self._flows:
            flow = self._flows[flow_key]
            # 检查流超时：如果距离 last_seen 超过阈值，归档旧流并创建新流
            timeout = self._get_timeout(packet.protocol)
            if timeout and (packet.timestamp - flow.last_seen) > timeout:
                flow.flow_id = f"{flow.flow_id}_{int(flow.last_seen)}"
                if len(self._expired_flows) < MAX_EXPIRED_FLOWS:
                    self._expired_flows.append(flow)
                self._flows[flow_key] = self._create_flow(flow_key, packet)
                return

            flow.packet_count += 1
            flow.byte_count += packet.length
            flow.last_seen = packet.timestamp
            if packet.flags:
                flow.flags_set.add(packet.flags)
            if packet.length > self._get_min_frame_size(packet.protocol):
                flow.has_payload = True
        else:
            self._flows[flow_key] = self._create_flow(flow_key, packet)

    def _create_flow(self, flow_key: str, packet: PacketRecord) -> FlowRecord:
        """创建新流记录"""
        return FlowRecord(
            flow_id=flow_key,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port or 0,
            dst_port=packet.dst_port or 0,
            protocol=packet.protocol,
            packet_count=1,
            byte_count=packet.length,
            first_seen=packet.timestamp,
            last_seen=packet.timestamp,
            flags_set={packet.flags} if packet.flags else set(),
            has_payload=packet.length > self._get_min_frame_size(packet.protocol),
            service=classify_service(packet.src_port, packet.dst_port, packet.protocol),
        )

    def update_batch(self, packets: list[PacketRecord]) -> None:
        """批量更新"""
        for pkt in packets:
            self.update(pkt)

    def get_flows(self) -> list[FlowRecord]:
        """返回所有流（含超时归档流），按包数降序"""
        all_flows = list(self._flows.values()) + self._expired_flows
        return sorted(all_flows, key=lambda f: f.packet_count, reverse=True)

    def get_flow_count(self) -> int:
        return len(self._flows) + len(self._expired_flows)

    def get_total_packets(self) -> int:
        active = sum(f.packet_count for f in self._flows.values())
        expired = sum(f.packet_count for f in self._expired_flows)
        return active + expired

    def get_total_bytes(self) -> int:
        active = sum(f.byte_count for f in self._flows.values())
        expired = sum(f.byte_count for f in self._expired_flows)
        return active + expired

    def reset(self) -> None:
        self._flows.clear()
        self._expired_flows.clear()

    @staticmethod
    def _get_timeout(protocol: str) -> float | None:
        """获取协议对应的流超时时间"""
        if protocol == "TCP":
            return TCP_FLOW_TIMEOUT
        elif protocol == "UDP":
            return UDP_FLOW_TIMEOUT
        elif protocol == "ICMP":
            return ICMP_FLOW_TIMEOUT
        return DEFAULT_FLOW_TIMEOUT

    @staticmethod
    def _get_min_frame_size(protocol: str) -> int:
        """获取协议对应的最小帧长度（Ethernet + IP + L4 header）"""
        if protocol == "TCP":
            return 54  # Ethernet(14) + IP(20) + TCP(20)
        elif protocol in ("UDP", "ICMP"):
            return 42  # Ethernet(14) + IP(20) + UDP/ICMP(8)
        return 54  # 默认使用 TCP 阈值

    @staticmethod
    def _compute_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
        """计算方向无关的五元组哈希"""
        ep_a = (src_ip, src_port)
        ep_b = (dst_ip, dst_port)

        if ep_a > ep_b:
            ep_a, ep_b = ep_b, ep_a

        raw = f"{ep_a[0]}:{ep_a[1]}-{ep_b[0]}:{ep_b[1]}-{protocol}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]
