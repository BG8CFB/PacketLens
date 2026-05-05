"""故障检测编排器 — 8 种网络故障检测

与 StormDetector（广播/组播/ARP 泛洪/ICMP 泛洪）互补，
本模块覆盖 ARP 欺骗、TCP 健康度、ICMP 错误、TTL 异常、DNS 故障、分片异常、突发流量。
"""

from __future__ import annotations

import logging
from collections import defaultdict

from app.models.flow_record import FlowRecord
from app.models.packet_record import PacketRecord
from app.preprocessing.fault.base import FaultAlert
from app.preprocessing.fault.counter import FaultCounter
from app.preprocessing.fault.thresholds import (
    ARP_SPOOF_CONFLICT_THRESHOLD,
    ARP_SPOOF_CRITICAL_THRESHOLD,
    ARP_SPOOF_MIN_PACKETS,
    TCP_RETRANSMIT_RATE_WARNING,
    TCP_RETRANSMIT_RATE_CRITICAL,
    TCP_RETRANSMIT_MIN_PACKETS,
    TCP_ZERO_WINDOW_WARNING,
    TCP_ZERO_WINDOW_CRITICAL,
    RST_STORM_PACKET_THRESHOLD,
    RST_STORM_RATE_THRESHOLD,
    RST_STORM_CRITICAL_THRESHOLD,
    ICMP_ERROR_PACKET_THRESHOLD,
    ICMP_ERROR_RATE_THRESHOLD,
    ICMP_ERROR_CRITICAL_THRESHOLD,
    TTL_ANOMALY_RANGE,
    TTL_ANOMALY_MIN_SAMPLES,
    DNS_FAILURE_RATE_WARNING,
    DNS_FAILURE_MIN_RESPONSES,
    DNS_SERVFAIL_THRESHOLD,
    FRAG_OVERLAP_THRESHOLD,
    FRAG_INCOMPLETE_THRESHOLD,
    BURST_SPIKE_MULTIPLIER,
    BURST_MIN_PPS,
)
from app.preprocessing.storm.counter import StormCounter

logger = logging.getLogger(__name__)

_ICMP_TYPE_NAMES = {3: "Destination Unreachable", 5: "Redirect", 11: "Time Exceeded"}


class FaultDetector:
    """网络故障检测器 — 与 AnomalyMarker（安全检测）平行运行"""

    def detect(
        self,
        fault_counter: FaultCounter,
        storm_counter: StormCounter,
        flows: list[FlowRecord],
        packets: list[PacketRecord],
        duration: float,
    ) -> list[dict]:
        """运行所有故障检测，返回 anomaly 格式字典列表"""
        alerts: list[FaultAlert] = []
        alerts.extend(self._detect_arp_spoof(packets))
        alerts.extend(self._detect_tcp_retransmit(fault_counter, flows))
        alerts.extend(self._detect_tcp_zero_window(fault_counter, flows))
        alerts.extend(self._detect_rst_storm(fault_counter, duration))
        alerts.extend(self._detect_icmp_errors(fault_counter, duration))
        alerts.extend(self._detect_ttl_anomaly(fault_counter))
        alerts.extend(self._detect_dns_failure(fault_counter))
        alerts.extend(self._detect_ip_fragment_anomaly(fault_counter))
        alerts.extend(self._detect_traffic_burst(fault_counter, duration))

        if alerts:
            types = [a.type for a in alerts]
            logger.info(f"故障检测完成: {len(alerts)} 个告警 ({', '.join(types)})")
        return [a.to_dict() for a in alerts]

    # ── 1. ARP 欺骗检测 ──────────────────────────────────

    def _detect_arp_spoof(self, packets: list[PacketRecord]) -> list[FaultAlert]:
        """检测 ARP 欺骗：同 IP 出现多个不同 MAC（使用 FaultCounter 增量追踪数据）"""
        alerts: list[FaultAlert] = []

        # 使用 packets 参数兼容无 FaultCounter 的调用路径
        ip_mac_map: dict[str, set[str]] = defaultdict(set)
        ip_packet_count: dict[str, int] = defaultdict(int)
        for pkt in packets:
            if pkt.protocol != "ARP" or pkt.arp_op != 2:
                continue
            if not pkt.src_mac or not pkt.src_ip:
                continue
            ip_mac_map[pkt.src_ip].add(pkt.src_mac.lower())
            ip_packet_count[pkt.src_ip] += 1

        for ip, macs in ip_mac_map.items():
            if ip_packet_count[ip] < ARP_SPOOF_MIN_PACKETS:
                continue
            if len(macs) < ARP_SPOOF_CONFLICT_THRESHOLD:
                continue

            is_critical = len(macs) >= ARP_SPOOF_CRITICAL_THRESHOLD
            severity = "Critical" if is_critical else "Warning"
            alerts.append(FaultAlert(
                type="arp_spoof",
                severity=severity,
                description=(
                    f"检测到 ARP 欺骗: IP {ip} 映射到 {len(macs)} 个不同 MAC "
                    f"({', '.join(sorted(macs)[:5])})"
                ),
                affected_ips=[ip],
                detail={
                    "ip": ip,
                    "mac_count": len(macs),
                    "macs": sorted(macs),
                    "arp_reply_count": ip_packet_count[ip],
                },
            ))
        return alerts

    # ── 2. TCP 重传检测 ──────────────────────────────────

    def _detect_tcp_retransmit(
        self, counter: FaultCounter, flows: list[FlowRecord]
    ) -> list[FaultAlert]:
        """检测高 TCP 重传率"""
        if counter.tcp_total < TCP_RETRANSMIT_MIN_PACKETS:
            return []

        # 全局重传统计
        total_retransmits = sum(f.retransmit_count for f in flows if f.protocol == "TCP")
        global_rate = total_retransmits / counter.tcp_total if counter.tcp_total else 0.0

        if global_rate < TCP_RETRANSMIT_RATE_WARNING:
            # 检查单流高重传
            return self._check_single_flow_retransmit(flows, counter.tcp_total)

        is_critical = global_rate >= TCP_RETRANSMIT_RATE_CRITICAL
        severity = "Critical" if is_critical else "Warning"

        # 找出重传最高的 Top 3 流
        tcp_flows = [f for f in flows if f.protocol == "TCP" and f.retransmit_count > 0]
        tcp_flows.sort(key=lambda f: f.retransmit_count, reverse=True)
        top_flows = tcp_flows[:3]
        affected_flows = [f.flow_id for f in top_flows]
        affected_ips = []
        for f in top_flows:
            if f.src_ip not in affected_ips:
                affected_ips.append(f.src_ip)
            if f.dst_ip not in affected_ips:
                affected_ips.append(f.dst_ip)

        return [FaultAlert(
            type="tcp_retransmit",
            severity=severity,
            description=(
                f"检测到高 TCP 重传率: 全局 {global_rate:.1%} "
                f"({total_retransmits}/{counter.tcp_total} 包), "
                f"Top 流重传: {', '.join(f'{f.flow_id}={f.retransmit_count}' for f in top_flows)}"
            ),
            affected_flows=affected_flows,
            affected_ips=affected_ips[:10],
            detail={
                "global_retransmit_rate": round(global_rate, 4),
                "total_retransmits": total_retransmits,
                "total_tcp_packets": counter.tcp_total,
            },
        )]

    def _check_single_flow_retransmit(
        self, flows: list[FlowRecord], total_tcp: int
    ) -> list[FaultAlert]:
        """检查单流高重传（即使全局率正常）"""
        alerts: list[FaultAlert] = []
        for f in flows:
            if f.protocol != "TCP" or f.packet_count < 20:
                continue
            flow_rate = f.retransmit_count / f.packet_count
            if flow_rate >= TCP_RETRANSMIT_RATE_CRITICAL:
                alerts.append(FaultAlert(
                    type="tcp_retransmit",
                    severity="Critical",
                    description=(
                        f"单流高重传: 流 {f.flow_id} ({f.src_ip}:{f.src_port} → "
                        f"{f.dst_ip}:{f.dst_port}) 重传率 {flow_rate:.1%} "
                        f"({f.retransmit_count}/{f.packet_count} 包)"
                    ),
                    affected_flows=[f.flow_id],
                    affected_ips=[f.src_ip, f.dst_ip],
                    detail={
                        "flow_id": f.flow_id,
                        "flow_retransmit_rate": round(flow_rate, 4),
                        "retransmit_count": f.retransmit_count,
                    },
                ))
        return alerts

    # ── 3. TCP 零窗口检测 ────────────────────────────────

    def _detect_tcp_zero_window(
        self, counter: FaultCounter, flows: list[FlowRecord]
    ) -> list[FaultAlert]:
        """检测 TCP 零窗口条件"""
        if counter.tcp_zero_windows < TCP_ZERO_WINDOW_WARNING:
            return []

        is_critical = counter.tcp_zero_windows >= TCP_ZERO_WINDOW_CRITICAL
        severity = "Critical" if is_critical else "Warning"

        # 找出零窗口最多的流
        tcp_flows = [f for f in flows if f.protocol == "TCP" and f.zero_window_count > 0]
        tcp_flows.sort(key=lambda f: f.zero_window_count, reverse=True)
        top_flows = tcp_flows[:3]
        affected_flows = [f.flow_id for f in top_flows]

        return [FaultAlert(
            type="tcp_zero_window",
            severity=severity,
            description=(
                f"检测到 TCP 零窗口: {counter.tcp_zero_windows} 个零窗口包, "
                f"可能导致数据传输暂停"
            ),
            affected_flows=affected_flows,
            detail={
                "zero_window_count": counter.tcp_zero_windows,
                "affected_flow_count": len(tcp_flows),
            },
        )]

    # ── 4. RST 风暴检测 ──────────────────────────────────

    def _detect_rst_storm(self, counter: FaultCounter, duration: float) -> list[FaultAlert]:
        """检测 RST 包风暴"""
        if duration <= 0 or counter.tcp_rst_count < RST_STORM_PACKET_THRESHOLD:
            return []

        rate = counter.tcp_rst_count / duration
        if rate < RST_STORM_RATE_THRESHOLD:
            return []

        is_critical = counter.tcp_rst_count >= RST_STORM_CRITICAL_THRESHOLD
        severity = "Critical" if is_critical else "Warning"

        return [FaultAlert(
            type="rst_storm",
            severity=severity,
            description=(
                f"检测到 RST 风暴: {counter.tcp_rst_count} 个 RST 包, "
                f"速率 {rate:.1f} RST/s"
            ),
            detail={
                "rst_count": counter.tcp_rst_count,
                "rate_per_sec": round(rate, 1),
            },
        )]

    # ── 5. ICMP 错误风暴检测 ────────────────────────────

    def _detect_icmp_errors(
        self, counter: FaultCounter, duration: float
    ) -> list[FaultAlert]:
        """检测 ICMP 错误风暴（DestUnreachable/Redirect/TimeExceeded）"""
        if duration <= 0 or counter.icmp_error_count < ICMP_ERROR_PACKET_THRESHOLD:
            return []

        rate = counter.icmp_error_count / duration
        if rate < ICMP_ERROR_RATE_THRESHOLD:
            return []

        is_critical = counter.icmp_error_count >= ICMP_ERROR_CRITICAL_THRESHOLD
        severity = "Critical" if is_critical else "Warning"

        type_breakdown = {
            _ICMP_TYPE_NAMES.get(t, f"Type {t}"): c
            for t, c in counter.icmp_error_by_type.items()
        }

        return [FaultAlert(
            type="icmp_error_storm",
            severity=severity,
            description=(
                f"检测到 ICMP 错误风暴: {counter.icmp_error_count} 个错误包, "
                f"速率 {rate:.1f}/s ({', '.join(f'{k}={v}' for k, v in type_breakdown.items())})"
            ),
            detail={
                "error_count": counter.icmp_error_count,
                "rate_per_sec": round(rate, 1),
                "by_type": type_breakdown,
            },
        )]

    # ── 6. TTL 异常/路由环路检测 ─────────────────────────

    def _detect_ttl_anomaly(self, counter: FaultCounter) -> list[FaultAlert]:
        """检测 TTL 异常（路由环路/不对称路由）"""
        alerts: list[FaultAlert] = []
        for ip, ttl_values in counter.ttl_by_src.items():
            if len(ttl_values) < TTL_ANOMALY_MIN_SAMPLES:
                continue

            ttl_min, ttl_max = min(ttl_values), max(ttl_values)
            ttl_range = ttl_max - ttl_min
            if ttl_range <= TTL_ANOMALY_RANGE:
                continue

            alerts.append(FaultAlert(
                type="ttl_anomaly",
                severity="Warning",
                description=(
                    f"检测到 TTL 异常: 源 IP {ip} 的 TTL 跨度={ttl_range} "
                    f"(min={ttl_min}, max={ttl_max}), "
                    f"可能存在路由环路或不对称路由"
                ),
                affected_ips=[ip],
                detail={
                    "src_ip": ip,
                    "ttl_min": ttl_min,
                    "ttl_max": ttl_max,
                    "ttl_range": ttl_range,
                    "sample_count": len(ttl_values),
                },
            ))
        return alerts

    # ── 7. DNS 解析失败检测 ──────────────────────────────

    def _detect_dns_failure(self, counter: FaultCounter) -> list[FaultAlert]:
        """检测 DNS 解析失败模式"""
        alerts: list[FaultAlert] = []

        if counter.dns_response_count >= DNS_FAILURE_MIN_RESPONSES:
            failure_rate = counter.dns_failure_count / counter.dns_response_count
            if failure_rate > DNS_FAILURE_RATE_WARNING:
                alerts.append(FaultAlert(
                    type="dns_failure",
                    severity="Warning",
                    description=(
                        f"检测到 DNS 解析失败率过高: {failure_rate:.1%} "
                        f"({counter.dns_failure_count}/{counter.dns_response_count} 响应)"
                    ),
                    detail={
                        "failure_rate": round(failure_rate, 4),
                        "failure_count": counter.dns_failure_count,
                        "response_count": counter.dns_response_count,
                        "rcode_breakdown": counter.dns_rcode_breakdown,
                    },
                ))

        # 独立 SERVFAIL 检测（rcode=2）
        servfail_count = counter.dns_rcode_breakdown.get(2, 0)
        if servfail_count >= DNS_SERVFAIL_THRESHOLD:
            alerts.append(FaultAlert(
                type="dns_servfail",
                severity="Warning",
                description=(
                    f"检测到大量 DNS SERVFAIL: {servfail_count} 次, "
                    f"可能存在 DNS 服务器配置错误"
                ),
                detail={
                    "servfail_count": servfail_count,
                },
            ))

        return alerts

    # ── 8. IP 分片异常检测 ───────────────────────────────

    def _detect_ip_fragment_anomaly(self, counter: FaultCounter) -> list[FaultAlert]:
        """检测 IP 分片异常（重叠/不完整）"""
        alerts: list[FaultAlert] = []

        if counter.frag_overlaps >= FRAG_OVERLAP_THRESHOLD:
            alerts.append(FaultAlert(
                type="fragment_overlap",
                severity="Warning",
                description=(
                    f"检测到 IP 分片重叠: {counter.frag_overlaps} 次, "
                    f"可能存在 MTU 错配或分片攻击"
                ),
                detail={
                    "overlap_count": counter.frag_overlaps,
                    "total_frag_packets": counter.frag_packets,
                },
            ))

        if counter.frag_incomplete >= FRAG_INCOMPLETE_THRESHOLD:
            alerts.append(FaultAlert(
                type="fragment_incomplete",
                severity="Warning",
                description=(
                    f"检测到不完整 IP 分片: {counter.frag_incomplete} 个分片集缺少最后一个分片"
                ),
                detail={
                    "incomplete_count": counter.frag_incomplete,
                    "total_frag_packets": counter.frag_packets,
                },
            ))

        return alerts

    # ── 9. 突发流量峰值检测 ──────────────────────────────

    def _detect_traffic_burst(
        self, counter: FaultCounter, duration: float
    ) -> list[FaultAlert]:
        """检测突发流量（PPS 突刺）"""
        if duration <= 0:
            return []

        stats = counter.get_pps_stats()
        max_pps = stats["max_pps"]
        median_pps = stats["median_pps"]
        spike_ratio = stats["spike_ratio"]

        if max_pps < BURST_MIN_PPS or spike_ratio < BURST_SPIKE_MULTIPLIER:
            return []

        return [FaultAlert(
            type="traffic_burst",
            severity="Warning",
            description=(
                f"检测到突发流量峰值: 最高 {max_pps} pps, "
                f"中位数 {median_pps:.0f} pps, "
                f"峰值/中位数比={spike_ratio:.1f}x"
            ),
            detail={
                "max_pps": max_pps,
                "median_pps": round(median_pps, 1),
                "spike_ratio": spike_ratio,
                "duration": round(duration, 1),
            },
        )]
