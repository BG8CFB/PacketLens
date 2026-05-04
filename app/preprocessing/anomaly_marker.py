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
            if flow.byte_count <= 100_000:  # 100KB 阈值
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
            if flow.byte_count > 1_000_000:  # > 1MB
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
