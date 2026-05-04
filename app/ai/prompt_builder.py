"""提示词构建器"""

from __future__ import annotations

import json
import logging
from collections import Counter

from app.ai.prompts.system_prompt import get_system_prompt
from app.ai.prompts.quick_analysis import get_quick_template
from app.ai.prompts.deep_analysis import get_deep_layer1_template, get_deep_layer2_template
from app.config.ai_defaults import AI_DEFAULTS, MAX_FLOWS_IN_PROMPT
from app.models.flow_record import FlowRecord
from app.models.packet_record import PacketRecord
from app.preprocessing.protocol_classifier import classify_service

logger = logging.getLogger(__name__)


class PromptBuilder:
    """构建 AI 分析提示词

    通过智能采样控制数据量，基于 token 预算动态调整采样数量。
    """

    def __init__(self, context_window_tokens: int | None = None):
        self._context_window_tokens = (
            context_window_tokens if context_window_tokens is not None
            else AI_DEFAULTS["context_window_tokens"]
        )

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """粗略估算 token 数（保守估算约 2 字符/token）"""
        return max(len(text) // 2, 1)

    def _available_tokens_for_flows(self, system_prompt: str, stats_text: str) -> int:
        """计算可用于流数据的 token 预算"""
        used = self._estimate_tokens(system_prompt + stats_text)
        return int(self._context_window_tokens * 0.6) - used

    def build_quick_prompt(
        self,
        flows: list[FlowRecord],
        stats: dict,
        anomalies: list[dict],
    ) -> tuple[str, str]:
        """构建快速分析提示词

        Returns:
            (user_prompt, system_prompt)
        """
        system = get_system_prompt()

        proto_dist = stats.get("protocol_distribution", {})
        proto_lines = [f"  {k}: {v} 包" for k, v in proto_dist.items()]

        top_src = stats.get("top_talkers_src", [])[:10]
        top_dst = stats.get("top_talkers_dst", [])[:10]
        src_lines = [f"  {ip}: {cnt} 包" for ip, cnt in top_src]
        dst_lines = [f"  {ip}: {cnt} 包" for ip, cnt in top_dst]

        # Top 20 流（快速分析只看概要）
        flow_lines = _format_flow_lines(flows[:20])

        anomaly_lines = []
        if anomalies:
            for a in anomalies:
                anomaly_lines.append(f"  [{a['severity']}] {a['description']}")
        else:
            anomaly_lines.append("  未检测到明显异常")

        user_prompt = get_quick_template().format(
            total_packets=stats.get("total_packets", 0),
            total_bytes=stats.get("total_bytes", 0),
            total_flows=stats.get("total_flows", 0),
            duration=stats.get("duration", 0),
            bandwidth_bps=stats.get("bandwidth_bps", 0),
            protocol_distribution="\n".join(proto_lines) or "无数据",
            top_src="\n".join(src_lines) or "无数据",
            top_dst="\n".join(dst_lines) or "无数据",
            flow_summary="\n".join(flow_lines) or "无数据",
            anomaly_summary="\n".join(anomaly_lines),
        )

        return user_prompt, system

    def build_deep_layer1_prompt(
        self,
        flows: list[FlowRecord],
        stats: dict,
        anomalies: list[dict],
        user_focus: str = "",
    ) -> tuple[str, str]:
        """构建深度分析 Layer 1 提示词

        智能采样：优先按 token 预算动态调整，回退到数量限制。
        """
        system = get_system_prompt()
        stats_text = json.dumps(stats, ensure_ascii=False, indent=2)
        budget = self._available_tokens_for_flows(system, stats_text)

        if budget <= 0:
            budget = 1000  # 最小预算兜底

        # 按 token 预算动态采样流数据
        all_flow_lines = []
        used_tokens = 0
        max_flows = min(len(flows), MAX_FLOWS_IN_PROMPT)

        for flow in flows[:max_flows]:
            line = _format_flow_line(flow, detailed=True)
            line_tokens = self._estimate_tokens(line)
            if used_tokens + line_tokens > budget:
                break
            all_flow_lines.append(line)
            used_tokens += line_tokens

        # 生成剩余流摘要
        sampled_count = len(all_flow_lines)
        summary_suffix = ""
        if len(flows) > sampled_count:
            remaining = flows[sampled_count:]
            rem_proto = Counter(f.protocol for f in remaining)
            rem_bytes = sum(f.byte_count for f in remaining)
            rem_pkts = sum(f.packet_count for f in remaining)
            summary_suffix = (
                f"\n\n### 剩余 {len(remaining)} 条流摘要（已省略详情）\n"
                f"- 总包数: {rem_pkts}, 总字节: {rem_bytes}\n"
                f"- 协议分布: {', '.join(f'{k}: {v}' for k, v in rem_proto.most_common())}"
            )

        anomaly_lines = [f"  [{a['severity']}] {a['type']}: {a['description']}" for a in anomalies]

        user_prompt = get_deep_layer1_template().format(
            full_stats=json.dumps(stats, ensure_ascii=False, indent=2),
            all_flows="\n".join(all_flow_lines),
            anomalies="\n".join(anomaly_lines) or "无",
            user_focus=user_focus or "全面分析",
        ) + summary_suffix

        logger.info(
            f"Deep Layer1 prompt: {len(flows)} 条流, "
            f"已采样 {min(len(flows), MAX_FLOWS_IN_PROMPT)} 条, "
            f"prompt 长度 {len(user_prompt)} 字符"
        )

        return user_prompt, system

    def build_deep_layer2_prompt(
        self,
        flow: FlowRecord,
        packets: list[PacketRecord],
        context: str = "",
    ) -> tuple[str, str]:
        """构建深度分析 Layer 2 提示词（单流）"""
        system = get_system_prompt()

        relevant_packets = _select_relevant_packets(packets, flow, max_packets=50)

        pkt_lines = []
        for p in relevant_packets:
            pkt_lines.append(
                f"  #{p.index} {p.src_ip}:{p.src_port} -> {p.dst_ip}:{p.dst_port} "
                f"[{p.protocol}] len={p.length} {p.info}"
            )

        user_prompt = get_deep_layer2_template().format(
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            packet_count=flow.packet_count,
            byte_count=flow.byte_count,
            duration=f"{flow.duration:.2f}",
            flags=",".join(flow.flags_set) or "无",
            packets_detail="\n".join(pkt_lines),
            context=context or "无额外上下文",
        )

        return user_prompt, system


def _format_flow_line(
    flow: FlowRecord,
    detailed: bool = False,
) -> str:
    """格式化单条流记录为文本行"""
    svc = flow.service or classify_service(flow.src_port, flow.dst_port, flow.protocol)
    svc_tag = f" [{svc}]" if svc else ""
    if detailed:
        return (
            f"  [{flow.flow_id}] {flow.src_ip}:{flow.src_port} -> "
            f"{flow.dst_ip}:{flow.dst_port} ({flow.protocol}) "
            f"{flow.packet_count}包 {flow.byte_count}B dur={flow.duration:.2f}s "
            f"flags={','.join(flow.flags_set) or '-'}"
            f"{svc_tag}"
        )
    return (
        f"  [{flow.flow_id}] {flow.src_ip}:{flow.src_port} -> "
        f"{flow.dst_ip}:{flow.dst_port} ({flow.protocol}) "
        f"{flow.packet_count}包 {flow.byte_count}B "
        f"flags={','.join(flow.flags_set) or '-'}"
        f"{svc_tag}"
    )


def _format_flow_lines(
    flows: list[FlowRecord],
    detailed: bool = False,
) -> list[str]:
    """格式化流记录为文本行"""
    return [_format_flow_line(f, detailed) for f in flows]


def _select_relevant_packets(
    packets: list[PacketRecord],
    flow: FlowRecord,
    max_packets: int = 50,
) -> list[PacketRecord]:
    """选择属于指定流的关键包"""
    flow_pkts = [
        p for p in packets
        if _packet_matches_flow(p, flow)
    ]

    if len(flow_pkts) <= max_packets:
        return flow_pkts

    # 取前半（握手/初始）+ 后半（结束/异常）
    half = max_packets // 2
    head = flow_pkts[:half]
    tail = flow_pkts[-half:]
    return head + tail


def _packet_matches_flow(pkt: PacketRecord, flow: FlowRecord) -> bool:
    """判断包是否属于指定流（方向无关）"""
    if pkt.protocol != flow.protocol:
        return False

    p_sp = pkt.src_port or 0
    p_dp = pkt.dst_port or 0

    return (
        (pkt.src_ip == flow.src_ip and pkt.dst_ip == flow.dst_ip
         and p_sp == flow.src_port and p_dp == flow.dst_port)
        or
        (pkt.src_ip == flow.dst_ip and pkt.dst_ip == flow.src_ip
         and p_sp == flow.dst_port and p_dp == flow.src_port)
    )
