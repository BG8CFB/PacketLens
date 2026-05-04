"""实时五元组流聚合器"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import threading

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
    所有公共方法线程安全，通过 _lock 保护内部状态。
    """

    def __init__(self):
        self._flows: dict[str, FlowRecord] = {}
        self._expired_flows: list[FlowRecord] = []
        self._lock = threading.Lock()
        self._drop_warned = False
        self._dropped_count = 0

    def update(self, packet: PacketRecord) -> None:
        """根据数据包更新流表（线程安全）"""
        if not packet.src_ip or not packet.dst_ip:
            return

        flow_key = self._compute_key(
            packet.src_ip, packet.dst_ip,
            packet.src_port or 0, packet.dst_port or 0,
            packet.protocol,
        )

        with self._lock:
            if flow_key in self._flows:
                flow = self._flows[flow_key]
                # 检查流超时：如果距离 last_seen 超过阈值，归档旧流并创建新流
                timeout = self._get_timeout(packet.protocol)
                if timeout > 0 and (packet.timestamp - flow.last_seen) > timeout:
                    # 修改归档流的 flow_id 以区分新流（归档前修改）
                    flow.flow_id = f"{flow.flow_id}_{int(flow.last_seen)}"
                    if len(self._expired_flows) < MAX_EXPIRED_FLOWS:
                        self._expired_flows.append(flow)
                    else:
                        self._dropped_count += 1
                        if not self._drop_warned:
                            logger.warning(
                                f"过期流缓冲区已满 ({MAX_EXPIRED_FLOWS})，"
                                f"丢弃过期流 {flow.flow_id}。后续丢弃将静默进行。"
                            )
                            self._drop_warned = True
                    self._flows[flow_key] = self._create_flow(flow_key, packet)
                    return

                flow.packet_count += 1
                flow.byte_count += packet.length
                flow.last_seen = packet.timestamp
                if packet.flags:
                    # 将 TCP flags 字符串（如 "SA"）拆分为单个 flag 字符（"S", "A"）
                    flow.flags_set.update(packet.flags)
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
            # 将 TCP flags 字符串拆分为单个 flag 字符的集合（如 "SA" → {"S", "A"}）
            flags_set=set(packet.flags) if packet.flags else set(),
            has_payload=packet.length > self._get_min_frame_size(packet.protocol),
            service=classify_service(packet.src_port, packet.dst_port, packet.protocol),
        )

    def update_batch(self, packets: list[PacketRecord]) -> None:
        """批量更新"""
        for pkt in packets:
            self.update(pkt)

    def get_flows(self) -> list[FlowRecord]:
        """返回所有流（含超时归档流），按包数降序（线程安全）"""
        with self._lock:
            all_flows = list(self._flows.values()) + list(self._expired_flows)
        return sorted(all_flows, key=lambda f: f.packet_count, reverse=True)

    def get_flow_count(self) -> int:
        """当前流总数（线程安全）"""
        with self._lock:
            return len(self._flows) + len(self._expired_flows)

    def get_total_packets(self) -> int:
        """所有流的总包数（线程安全）"""
        with self._lock:
            active = sum(f.packet_count for f in self._flows.values())
            expired = sum(f.packet_count for f in self._expired_flows)
            return active + expired

    def get_total_bytes(self) -> int:
        """所有流的总字节数（线程安全）"""
        with self._lock:
            active = sum(f.byte_count for f in self._flows.values())
            expired = sum(f.byte_count for f in self._expired_flows)
            return active + expired

    def reset(self) -> None:
        """清空所有流和归档流（线程安全）"""
        with self._lock:
            self._flows.clear()
            self._expired_flows.clear()
            self._drop_warned = False
            self._dropped_count = 0

    def get_stats(self) -> dict:
        """返回聚合器内部统计（线程安全）"""
        with self._lock:
            return {
                "active_flows": len(self._flows),
                "expired_flows": len(self._expired_flows),
                "dropped_expired": self._dropped_count,
            }

    @staticmethod
    def _get_timeout(protocol: str) -> float:
        """获取协议对应的流超时时间（秒），始终返回正数"""
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
        """计算方向无关的五元组哈希

        使用数值 IP 比较确保方向归一化的正确性，
        避免字符串比较在 "9.x.x.x" vs "10.x.x.x" 等场景下出错。
        """
        try:
            ip_a = int(ipaddress.ip_address(src_ip))
            ip_b = int(ipaddress.ip_address(dst_ip))
        except ValueError:
            # 非法 IP 地址时降级为哈希数值比较，避免字符串字典序错误
            ip_a = int(hashlib.md5(src_ip.encode()).hexdigest(), 16)
            ip_b = int(hashlib.md5(dst_ip.encode()).hexdigest(), 16)

        if (ip_a, src_port) > (ip_b, dst_port):
            src_ip, dst_ip = dst_ip, src_ip
            src_port, dst_port = dst_port, src_port

        raw = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]
