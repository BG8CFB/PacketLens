"""异常启发式检测"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict

from app.models.flow_record import FlowRecord

logger = logging.getLogger(__name__)

# 异常阈值
PORT_SCAN_THRESHOLD = 20  # 同一目标的流数超过此值视为端口扫描
HIGH_PORT_THRESHOLD = 49152  # 高端口范围起点


class AnomalyMarker:
    """异常检测启发式

    检测常见网络异常模式，结果用于丰富 AI 分析提示词。
    """

    def mark(self, flows: list[FlowRecord]) -> list[dict]:
        """对流列表执行异常检测

        Returns:
            异常描述列表，每项包含:
            - type: 异常类型
            - severity: 建议严重级别
            - description: 描述
            - affected_flows: 受影响的 flow_id 列表
            - detail: 详细信息
        """
        anomalies: list[dict] = []

        anomalies.extend(self._detect_port_scans(flows))
        anomalies.extend(self._detect_unusual_ports(flows))
        anomalies.extend(self._detect_large_transfers(flows))
        anomalies.extend(self._detect_syn_flood(flows))
        anomalies.extend(self._detect_dns_tunnel(flows))

        return anomalies

    def _detect_port_scans(self, flows: list[FlowRecord]) -> list[dict]:
        """检测端口扫描模式：同一源 IP 对同一目标 IP 的多端口访问"""
        target_flows: dict[tuple[str, str], list[FlowRecord]] = defaultdict(list)

        for flow in flows:
            if flow.protocol in ("TCP", "UDP") and flow.packet_count <= 3:
                target_flows[(flow.src_ip, flow.dst_ip)].append(flow)

        anomalies = []
        for (src_ip, dst_ip), flow_list in target_flows.items():
            unique_ports = set(f.dst_port for f in flow_list)
            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                anomalies.append({
                    "type": "port_scan",
                    "severity": "Warning",
                    "description": f"疑似端口扫描: {src_ip} → {dst_ip}, "
                                   f"{len(unique_ports)} 个不同端口, {len(flow_list)} 条流",
                    "affected_flows": [f.flow_id for f in flow_list],
                    "detail": {
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "port_count": len(unique_ports),
                        "flow_count": len(flow_list),
                        "ports_sample": sorted(unique_ports)[:20],
                    },
                })

        return anomalies

    def _detect_unusual_ports(self, flows: list[FlowRecord]) -> list[dict]:
        """检测非标准端口的大流量（排除已知服务）"""
        anomalies = []

        for flow in flows:
            if flow.dst_port < HIGH_PORT_THRESHOLD:
                continue
            if flow.byte_count <= 500_000:  # 500KB 阈值
                continue
            if flow.protocol not in ("TCP", "UDP"):
                continue
            # 排除已识别的服务（如 QUIC/DNS 等）
            if flow.service is not None:
                continue

            anomalies.append({
                "type": "unusual_port",
                "severity": "Info",
                "description": f"非标准端口流量: {flow.src_ip}:{flow.src_port} -> "
                               f"{flow.dst_ip}:{flow.dst_port} ({flow.byte_count} bytes)",
                "affected_flows": [flow.flow_id],
                "detail": {
                    "src": f"{flow.src_ip}:{flow.src_port}",
                    "dst": f"{flow.dst_ip}:{flow.dst_port}",
                    "bytes": flow.byte_count,
                    "packets": flow.packet_count,
                },
            })

        return anomalies

    def _detect_large_transfers(self, flows: list[FlowRecord]) -> list[dict]:
        """检测大流量传输（可能的数据泄露）"""
        anomalies = []

        for flow in flows:
            if flow.byte_count > 10_000_000:  # > 10MB
                anomalies.append({
                    "type": "large_transfer",
                    "severity": "Info",
                    "description": f"大流量传输: {flow.src_ip} -> {flow.dst_ip} "
                                   f"{flow.byte_count / 1024 / 1024:.1f} MB, "
                                   f"{flow.packet_count} 包",
                    "affected_flows": [flow.flow_id],
                    "detail": {
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "bytes": flow.byte_count,
                        "packets": flow.packet_count,
                        "duration": round(flow.duration, 2),
                    },
                })

        return anomalies

    def _detect_syn_flood(self, flows: list[FlowRecord]) -> list[dict]:
        """检测 SYN Flood：同一目标 IP 收到大量 SYN-only 流"""
        SYN_FLOOD_THRESHOLD = 50

        target_syn: dict[str, list[FlowRecord]] = defaultdict(list)
        for flow in flows:
            if flow.protocol == "TCP" and "S" in flow.flags_set and "A" not in flow.flags_set:
                if flow.packet_count <= 3:
                    key = flow.dst_ip
                    target_syn[key].append(flow)

        anomalies = []
        for dst_ip, syn_flows in target_syn.items():
            if len(syn_flows) >= SYN_FLOOD_THRESHOLD:
                sources = set(f.src_ip for f in syn_flows)
                anomalies.append({
                    "type": "syn_flood",
                    "severity": "Critical",
                    "description": f"疑似 SYN Flood: 目标 {dst_ip}, "
                                   f"{len(syn_flows)} 条 SYN 流, 来自 {len(sources)} 个源 IP",
                    "affected_flows": [f.flow_id for f in syn_flows[:50]],
                    "detail": {
                        "target_ip": dst_ip,
                        "syn_flow_count": len(syn_flows),
                        "unique_sources": len(sources),
                        "sources_sample": sorted(sources)[:10],
                    },
                })
        return anomalies

    def _detect_dns_tunnel(self, flows: list[FlowRecord]) -> list[dict]:
        """检测 DNS 隧道：高频 DNS 查询"""
        DNS_TUNNEL_FLOW_THRESHOLD = 100

        dns_flows_by_src: dict[str, list[FlowRecord]] = defaultdict(list)
        for flow in flows:
            if flow.service == "DNS" or (flow.dst_port == 53 and flow.protocol in ("TCP", "UDP")):
                key = flow.src_ip
                dns_flows_by_src[key].append(flow)

        anomalies = []
        for src_ip, dns_list in dns_flows_by_src.items():
            if len(dns_list) >= DNS_TUNNEL_FLOW_THRESHOLD:
                anomalies.append({
                    "type": "dns_tunnel",
                    "severity": "Warning",
                    "description": f"疑似 DNS 隧道: {src_ip} 发起 {len(dns_list)} 条 DNS 流",
                    "affected_flows": [f.flow_id for f in dns_list[:50]],
                    "detail": {
                        "source_ip": src_ip,
                        "dns_flow_count": len(dns_list),
                        "total_bytes": sum(f.byte_count for f in dns_list),
                    },
                })
        return anomalies
