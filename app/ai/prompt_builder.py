"""提示词构建器 — 三层渐进式架构

Layer 1: 全量流量分析（全部流 + 每流 5 个采样包 + 统计 + 异常）
Layer 2: 可疑流逐包深度分析（单流 + 更多包数据 + Layer1 上下文）
Layer 3: 综合报告（汇总 Layer1 + Layer2 结果）
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.ai.prompts.system_prompt import get_system_prompt
from app.ai.prompts.quick_analysis import get_layer1_template
from app.ai.prompts.deep_analysis import get_layer2_template, get_layer3_template
from app.config.ai_defaults import AI_DEFAULTS
from app.preprocessing.protocol_classifier import classify_service

if TYPE_CHECKING:
    from app.models.flow_record import FlowRecord
    from app.models.packet_record import PacketRecord

logger = logging.getLogger(__name__)

# Layer 1 每条流的固定采样包数（从配置读取）
PACKETS_PER_FLOW_LAYER1 = AI_DEFAULTS["packets_per_flow_layer1"]

# Layer 3 截断长度（字符数），基于 max_input_chars 按比例分配
_LAYER3_LAYER1_RATIO = 0.40   # Layer1 结果占输入上限的 40%
_LAYER3_LAYER2_RATIO = 0.60   # Layer2 结果占输入上限的 60%


class PromptBuilder:
    """构建 AI 分析提示词"""

    def __init__(
        self,
        context_window_tokens: int | None = None,
        max_input_chars: int | None = None,
    ):
        self._context_window_tokens = (
            context_window_tokens if context_window_tokens is not None
            else AI_DEFAULTS["context_window_tokens"]
        )
        self._max_input_chars = (
            max_input_chars if max_input_chars is not None
            else AI_DEFAULTS["max_input_chars"]
        )

    # ── Layer 1: 全量流量分析 ──

    def build_layer1_prompt(
        self,
        flows: list[FlowRecord],
        packets: list[PacketRecord],
        stats: dict,
        anomalies: list[dict],
    ) -> tuple[str, str]:
        """构建 Layer 1 提示词（全部流 + 每流 5 个采样包）

        Returns:
            (user_prompt, system_prompt)
        """
        system = get_system_prompt()

        # 统计数据格式化
        proto_dist = stats.get("protocol_distribution", {})
        proto_lines = [f"  {k}: {v} 包" for k, v in proto_dist.items()]

        top_src = stats.get("top_talkers_src", [])[:10]
        top_dst = stats.get("top_talkers_dst", [])[:10]
        src_lines = [f"  {ip}: {cnt} 包" for ip, cnt in top_src]
        dst_lines = [f"  {ip}: {cnt} 包" for ip, cnt in top_dst]

        anomaly_lines = []
        if anomalies:
            for a in anomalies:
                anomaly_lines.append(f"  [{a['severity']}] {a['description']}")
        else:
            anomaly_lines.append("  未检测到明显异常")

        # 每条流 + 采样包
        flow_sections = []
        for flow in flows:
            section = _format_flow_with_packets(flow, packets, PACKETS_PER_FLOW_LAYER1)
            flow_sections.append(section)

        user_prompt = get_layer1_template().format(
            total_packets=stats.get("total_packets", 0),
            total_bytes=stats.get("total_bytes", 0),
            total_flows=stats.get("total_flows", 0),
            duration=stats.get("duration", 0),
            bandwidth_bps=stats.get("bandwidth_bps", 0),
            protocol_distribution="\n".join(proto_lines) or "无数据",
            top_src="\n".join(src_lines) or "无数据",
            top_dst="\n".join(dst_lines) or "无数据",
            anomaly_summary="\n".join(anomaly_lines),
            all_flows_with_packets="\n".join(flow_sections),
        )

        # 输入长度安全检查
        prompt_len = len(user_prompt) + len(system)
        if prompt_len > self._max_input_chars:
            logger.warning(
                f"Layer1 prompt 长度 {prompt_len} 超过安全上限 "
                f"{self._max_input_chars}，可能触发 API 限制"
            )

        logger.info(
            f"Layer1 prompt: {len(flows)} 条流, "
            f"每流 {PACKETS_PER_FLOW_LAYER1} 包采样, "
            f"prompt 长度 {len(user_prompt)} 字符"
        )

        return user_prompt, system

    # ── Layer 2: 单流逐包分析 ──

    def build_layer2_prompt(
        self,
        flow: FlowRecord,
        packets: list[PacketRecord],
        context: str = "",
    ) -> tuple[str, str]:
        """构建 Layer 2 提示词（单流深度分析）"""
        system = get_system_prompt()

        relevant_packets = _select_relevant_packets(packets, flow, max_packets=50)

        pkt_lines = []
        for p in relevant_packets:
            pkt_lines.append(
                f"  #{p.index} {p.src_ip}:{p.src_port} -> {p.dst_ip}:{p.dst_port} "
                f"[{p.protocol}] len={p.length} {p.info}"
            )

        user_prompt = get_layer2_template().format(
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            packet_count=flow.packet_count,
            byte_count=flow.byte_count,
            duration=f"{flow.duration:.2f}",
            flags=",".join(sorted(flow.flags_set)) or "无",
            packets_detail="\n".join(pkt_lines),
            context=context or "无额外上下文",
        )

        return user_prompt, system

    # ── Layer 3: 综合报告 ──

    def build_layer3_prompt(
        self,
        layer1_raw: str,
        layer2_results: list[str],
        stats: dict,
        suspicious_flow_count: int,
        confirmed_flow_count: int,
    ) -> tuple[str, str]:
        """构建 Layer 3 综合报告提示词"""
        system = get_system_prompt()

        layer2_combined = "\n\n---\n\n".join(layer2_results) if layer2_results else "无可疑流需要深度分析"

        # 基于配置的 max_input_chars 动态计算截断长度
        layer1_limit = int(self._max_input_chars * _LAYER3_LAYER1_RATIO)
        layer2_limit = int(self._max_input_chars * _LAYER3_LAYER2_RATIO)

        user_prompt = get_layer3_template().format(
            layer1_result=layer1_raw[:layer1_limit],
            layer2_results=layer2_combined[:layer2_limit],
            total_packets=stats.get("total_packets", 0),
            total_flows=stats.get("total_flows", 0),
            suspicious_flow_count=suspicious_flow_count,
            confirmed_flow_count=confirmed_flow_count,
        )

        return user_prompt, system


# ── 格式化工具函数 ──

def _format_flow_with_packets(
    flow: FlowRecord,
    packets: list[PacketRecord],
    max_packets: int,
) -> str:
    """格式化单条流记录 + 采样包"""
    svc = flow.service or classify_service(flow.src_port, flow.dst_port, flow.protocol)
    svc_tag = f" [{svc}]" if svc else ""

    # 流摘要行（flags_set 排序保证输出一致性）
    header = (
        f"### 流 [{flow.flow_id}] {flow.src_ip}:{flow.src_port} -> "
        f"{flow.dst_ip}:{flow.dst_port} ({flow.protocol}) "
        f"{flow.packet_count}包 {flow.byte_count}B dur={flow.duration:.2f}s "
        f"flags={','.join(sorted(flow.flags_set)) or '-'}{svc_tag}"
    )

    # 选择属于该流的包
    flow_pkts = _select_relevant_packets(packets, flow, max_packets=max_packets)

    pkt_lines = []
    for p in flow_pkts:
        pkt_lines.append(
            f"  #{p.index} {p.src_ip}:{p.src_port} -> {p.dst_ip}:{p.dst_port} "
            f"[{p.protocol}] len={p.length} {p.info}"
        )

    pkt_section = "\n".join(pkt_lines)
    if not pkt_section:
        pkt_section = "  （无可用包数据）"

    return f"{header}\n{pkt_section}"


def _select_relevant_packets(
    packets: list[PacketRecord],
    flow: FlowRecord,
    max_packets: int = 5,
) -> list[PacketRecord]:
    """选择属于指定流的关键包

    采样策略：前2（握手/请求）+ 中间均匀采样 + 后2（结束/异常）
    """
    flow_pkts = [
        p for p in packets
        if _packet_matches_flow(p, flow)
    ]

    if len(flow_pkts) <= max_packets:
        return flow_pkts

    if max_packets <= 4:
        # 包数很少时直接取前N个
        return flow_pkts[:max_packets]

    head_count = 2
    tail_count = 2
    mid_count = max_packets - head_count - tail_count

    head = flow_pkts[:head_count]
    tail = flow_pkts[-tail_count:]

    # 中间均匀采样
    mid_start = head_count
    mid_end = len(flow_pkts) - tail_count
    mid_range = mid_end - mid_start

    if mid_count <= 0 or mid_range <= 0:
        return head + tail

    step = max(mid_range // mid_count, 1)
    mid = [flow_pkts[mid_start + i * step] for i in range(mid_count)
           if mid_start + i * step < mid_end]

    return head + mid + tail


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
