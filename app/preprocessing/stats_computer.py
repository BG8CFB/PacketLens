"""批量统计计算（阶段2 — 抓包结束后执行）"""

from __future__ import annotations

import logging
from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.flow_record import FlowRecord
    from app.models.packet_record import PacketRecord

logger = logging.getLogger(__name__)


class StatsComputer:
    """抓包结束后的批量统计计算"""

    def compute(
        self,
        flows: list[FlowRecord],
        packets: list[PacketRecord],
    ) -> dict:
        """从原始包列表计算统计（仅用于测试或兼容场景）"""
        if not packets and not flows:
            return self._empty_stats()

        if not packets:
            # 有流但无原始包列表时，仍需计算流级别统计
            return self._build_result(
                flows=flows,
                protocol_dist=Counter(),
                src_counter=Counter(),
                dst_counter=Counter(),
                total_packets=0,
                total_bytes=0,
                first_ts=0.0,
                last_ts=0.0,
            )

        protocol_dist = Counter(p.protocol for p in packets)
        src_counter = Counter(p.src_ip for p in packets if p.src_ip)
        dst_counter = Counter(p.dst_ip for p in packets if p.dst_ip)
        total_packets = len(packets)
        total_bytes = sum(p.length for p in packets)
        timestamps = [p.timestamp for p in packets]
        first_ts = min(timestamps)
        last_ts = max(timestamps)

        return self._build_result(
            flows=flows,
            protocol_dist=protocol_dist,
            src_counter=src_counter,
            dst_counter=dst_counter,
            total_packets=total_packets,
            total_bytes=total_bytes,
            first_ts=first_ts,
            last_ts=last_ts,
        )

    def compute_from_counters(
        self,
        flows: list[FlowRecord],
        protocol_dist: Counter,
        src_counter: Counter,
        dst_counter: Counter,
        total_packets: int,
        total_bytes: int,
        first_ts: float | None,
        last_ts: float | None,
    ) -> dict:
        """从预计算的增量计数器生成统计（推荐，不受环形缓冲区限制）"""
        if total_packets == 0 and not flows:
            return self._empty_stats()

        return self._build_result(
            flows=flows,
            protocol_dist=protocol_dist,
            src_counter=src_counter,
            dst_counter=dst_counter,
            total_packets=total_packets,
            total_bytes=total_bytes,
            first_ts=first_ts if first_ts is not None else 0.0,
            last_ts=last_ts if last_ts is not None else 0.0,
        )

    def _build_result(
        self,
        flows: list[FlowRecord],
        protocol_dist: Counter,
        src_counter: Counter,
        dst_counter: Counter,
        total_packets: int,
        total_bytes: int,
        first_ts: float,
        last_ts: float,
    ) -> dict:
        """构建统计结果字典"""
        # 使用 is not None 判断避免 first_ts=0.0 被误判为 falsy
        duration = (last_ts - first_ts) if first_ts is not None and last_ts is not None else 0.0
        avg_pkt_size = total_bytes / total_packets if total_packets > 0 else 0.0
        bandwidth_bps = (total_bytes * 8) / duration if duration > 0 else 0.0

        # 流级别统计（空列表时不填充虚假数据）
        flow_sizes = [f.byte_count for f in flows] if flows else []
        avg_flow_size = sum(flow_sizes) / len(flow_sizes) if flow_sizes else 0.0
        flow_size_median = self._median(flow_sizes)

        top_flows_by_bytes = sorted(flows, key=lambda f: f.byte_count, reverse=True)[:5]
        top_flows = [
            {
                "flow_id": f.flow_id,
                "src": f"{f.src_ip}:{f.src_port}",
                "dst": f"{f.dst_ip}:{f.dst_port}",
                "protocol": f.protocol,
                "bytes": f.byte_count,
                "packets": f.packet_count,
            }
            for f in top_flows_by_bytes
        ]

        return {
            "protocol_distribution": dict(protocol_dist.most_common()),
            "top_talkers_src": src_counter.most_common(10),
            "top_talkers_dst": dst_counter.most_common(10),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_flows": len(flows),
            "avg_packet_size": round(avg_pkt_size, 1),
            "duration": round(duration, 2),
            "bandwidth_bps": round(bandwidth_bps, 0),
            "avg_flow_size": round(avg_flow_size, 1),
            "top_flows": top_flows,
            "flow_size_median": flow_size_median,
        }

    @staticmethod
    def _median(values: list[int]) -> float:
        """计算中位数（偶数个元素取中间两个的平均值）"""
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        mid = n // 2
        if n % 2 == 1:
            return float(sorted_vals[mid])
        # 偶数个：取中间两个的平均值
        return (sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0

    @staticmethod
    def _empty_stats() -> dict:
        return {
            "protocol_distribution": {},
            "top_talkers_src": [],
            "top_talkers_dst": [],
            "total_packets": 0,
            "total_bytes": 0,
            "total_flows": 0,
            "avg_packet_size": 0.0,
            "duration": 0.0,
            "bandwidth_bps": 0.0,
            "avg_flow_size": 0.0,
            "top_flows": [],
            "flow_size_median": 0.0,
        }
