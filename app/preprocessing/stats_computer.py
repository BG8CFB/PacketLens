"""批量统计计算（阶段2 — 抓包结束后执行）"""

from __future__ import annotations

import logging
from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.flow_record import FlowRecord
    from app.models.packet_record import PacketRecord
    from app.preprocessing.fault.counter import FaultCounter

from app.preprocessing.fault.thresholds import TTL_ANOMALY_MIN_SAMPLES, TTL_ANOMALY_RANGE

logger = logging.getLogger(__name__)


class StatsComputer:
    """抓包结束后的批量统计计算"""

    def compute(
        self,
        flows: list[FlowRecord],
        packets: list[PacketRecord],
        fault_counter: FaultCounter | None = None,
    ) -> dict:
        """从原始包列表计算统计（仅用于测试或兼容场景）"""
        if not packets and not flows:
            return self._empty_stats()

        if not packets:
            return self._build_result(
                flows=flows,
                protocol_dist=Counter(),
                src_counter=Counter(),
                dst_counter=Counter(),
                total_packets=0,
                total_bytes=0,
                first_ts=0.0,
                last_ts=0.0,
                fault_counter=fault_counter,
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
            fault_counter=fault_counter,
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
        fault_counter: FaultCounter | None = None,
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
            fault_counter=fault_counter,
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
        fault_counter: FaultCounter | None = None,
    ) -> dict:
        """构建统计结果字典"""
        duration = (last_ts - first_ts) if first_ts is not None and last_ts is not None else 0.0
        avg_pkt_size = total_bytes / total_packets if total_packets > 0 else 0.0
        bandwidth_bps = (total_bytes * 8) / duration if duration > 0 else 0.0

        # 流级别统计
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

        # TCP 健康度统计
        tcp_total = fault_counter.tcp_total if fault_counter else 0
        tcp_retransmits = sum(f.retransmit_count for f in flows if f.protocol == "TCP")
        tcp_retransmit_rate = tcp_retransmits / tcp_total if tcp_total > 0 else 0.0

        # DNS 健康度统计
        dns_resp = fault_counter.dns_response_count if fault_counter else 0
        dns_fail = fault_counter.dns_failure_count if fault_counter else 0
        dns_failure_rate = dns_fail / dns_resp if dns_resp > 0 else 0.0

        # PPS 突发统计
        pps_stats = fault_counter.get_pps_stats() if fault_counter else {}

        # TTL 异常源
        ttl_anomalies = []
        if fault_counter:
            for ip, ttl_vals in fault_counter.ttl_by_src.items():
                if len(ttl_vals) >= TTL_ANOMALY_MIN_SAMPLES:
                    ttl_range = max(ttl_vals) - min(ttl_vals)
                    if ttl_range > TTL_ANOMALY_RANGE:
                        ttl_anomalies.append({
                            "ip": ip,
                            "ttl_range": ttl_range,
                            "samples": len(ttl_vals),
                        })

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
            # 故障类指标
            "tcp_health": {
                "total_tcp_packets": tcp_total,
                "retransmit_rate": round(tcp_retransmit_rate, 4),
                "zero_window_count": fault_counter.tcp_zero_windows if fault_counter else 0,
                "rst_count": fault_counter.tcp_rst_count if fault_counter else 0,
            },
            "icmp_error_summary": {
                "total_errors": fault_counter.icmp_error_count if fault_counter else 0,
                "by_type": {str(k): v for k, v in (fault_counter.icmp_error_by_type if fault_counter else {}).items()},
            },
            "dns_health": {
                "response_count": dns_resp,
                "failure_count": dns_fail,
                "failure_rate": round(dns_failure_rate, 4),
            },
            "ttl_distribution": {
                "anomalous_sources": ttl_anomalies,
            },
            "fragment_stats": {
                "frag_packets": fault_counter.frag_packets if fault_counter else 0,
                "overlaps": fault_counter.frag_overlaps if fault_counter else 0,
                "incomplete": fault_counter.frag_incomplete if fault_counter else 0,
            },
            "pps_timeline": {
                "max_pps": pps_stats.get("max_pps", 0),
                "median_pps": pps_stats.get("median_pps", 0.0),
                "spike_ratio": pps_stats.get("spike_ratio", 0.0),
            },
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
            "tcp_health": {"total_tcp_packets": 0, "retransmit_rate": 0.0, "zero_window_count": 0, "rst_count": 0},
            "icmp_error_summary": {"total_errors": 0, "by_type": {}},
            "dns_health": {"response_count": 0, "failure_count": 0, "failure_rate": 0.0},
            "ttl_distribution": {"anomalous_sources": []},
            "fragment_stats": {"frag_packets": 0, "overlaps": 0, "incomplete": 0},
            "pps_timeline": {"max_pps": 0, "median_pps": 0.0, "spike_ratio": 0.0},
        }
