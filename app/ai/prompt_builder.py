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
from app.preprocessing.protocol_classifier import classify_service, is_internal_ip

if TYPE_CHECKING:
    from app.models.flow_record import FlowRecord
    from app.models.packet_record import PacketRecord

logger = logging.getLogger(__name__)


def _smart_truncate_text(text: str, limit: int) -> str:
    """智能截断：在换行符边界处截断，避免破坏文本结构"""
    if len(text) <= limit:
        return text
    # 在限制范围内找最后一个换行符
    cut_pos = text.rfind("\n", 0, limit)
    if cut_pos <= 0:
        # 没有合适的换行符，直接在限制处截断
        cut_pos = limit
    return text[:cut_pos] + "\n...[已截断]"


def _smart_truncate_blocks(text: str, limit: int, separator: str = "\n\n---\n\n") -> str:
    """在分隔符边界处截断块状文本（用于 Layer 2 拼接结果）"""
    if len(text) <= limit:
        return text
    blocks = text.split(separator)
    result_parts: list[str] = []
    current_len = 0
    omitted = 0
    for block in blocks:
        block_len = len(block)
        # 加上分隔符长度（如果不是第一个块）
        extra = len(separator) if result_parts else 0
        if current_len + extra + block_len > limit:
            omitted += 1
            continue
        result_parts.append(block)
        current_len += extra + block_len
    if omitted > 0:
        result_parts.append(f"...[已截断，省略 {omitted} 条流的详细分析]")
    return separator.join(result_parts)

# Layer 1 每条流默认采样包数（仅做兜底，实际值从 PromptBuilder 实例读取）
_DEFAULT_PACKETS_PER_FLOW = AI_DEFAULTS["packets_per_flow_layer1"]

# Layer 3 截断长度（字符数），基于 max_input_chars 按比例分配
_LAYER3_LAYER1_RATIO = 0.40   # Layer1 结果占输入上限的 40%
_LAYER3_LAYER2_RATIO = 0.60   # Layer2 结果占输入上限的 60%


# 异常告警 detail 字段展示优先级（越靠前越优先展示）
_PRIORITY_DETAIL_KEYS = [
    "ip", "src_ip", "target_ip", "source_ip",
    "mac_count", "macs",
    "port_count", "unique_ports", "ports_sample",
    "global_retransmit_rate", "total_retransmits", "total_tcp_packets",
    "flow_retransmit_rate", "retransmit_count",
    "failure_rate", "failure_count", "response_count", "rcode_breakdown",
    "max_pps", "median_pps", "spike_ratio", "rate_pps",
    "rst_count", "zero_window_count",
    "error_count", "total_errors", "by_type",
    "overlap_count", "incomplete_count", "total_frag_packets",
    "servfail_count",
]


class PromptBuilder:
    """构建 AI 分析提示词"""

    def __init__(
        self,
        context_window_tokens: int | None = None,
        max_input_chars: int | None = None,
        packets_per_flow_layer1: int | None = None,
    ):
        self._context_window_tokens = (
            context_window_tokens if context_window_tokens is not None
            else AI_DEFAULTS["context_window_tokens"]
        )
        self._max_input_chars = (
            max_input_chars if max_input_chars is not None
            else AI_DEFAULTS["max_input_chars"]
        )
        self._packets_per_flow_layer1 = (
            packets_per_flow_layer1 if packets_per_flow_layer1 is not None
            else _DEFAULT_PACKETS_PER_FLOW
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
        start_t = stats.get("capture_start_time", "")
        end_t = stats.get("capture_end_time", "")
        time_range = f"{start_t} ~ {end_t}" if start_t else "未知"

        proto_dist = stats.get("protocol_distribution", {})
        proto_lines = [f"  {k}: {v} 包" for k, v in proto_dist.items()]

        top_src = stats.get("top_talkers_src", [])[:10]
        top_dst = stats.get("top_talkers_dst", [])[:10]
        src_lines = [f"  {ip}: {cnt} 包" for ip, cnt in top_src]
        dst_lines = [f"  {ip}: {cnt} 包" for ip, cnt in top_dst]

        anomaly_lines = []
        if anomalies:
            for a in anomalies:
                line = f"  [{a['severity']}] {a['description']}"
                # 追加相关流 ID（前 5 个）
                affected = a.get("affected_flows", [])
                if affected:
                    flow_sample = ", ".join(str(f) for f in affected[:5])
                    if len(affected) > 5:
                        flow_sample += f" ...({len(affected)} total)"
                    line += f" [相关流: {flow_sample}]"
                # 追加关键 detail 字段（按优先级排序，取前 5 个）
                detail = a.get("detail", {})
                if detail:
                    sorted_items = sorted(
                        detail.items(),
                        key=lambda kv: (
                            _PRIORITY_DETAIL_KEYS.index(kv[0])
                            if kv[0] in _PRIORITY_DETAIL_KEYS
                            else 999
                        ),
                    )
                    detail_items = sorted_items[:5]
                    detail_str = ", ".join(f"{k}={v}" for k, v in detail_items)
                    line += f" ({detail_str})"
                anomaly_lines.append(line)
        else:
            anomaly_lines.append("  未检测到明显异常")

        # Top flows 格式化
        top_flows_data = stats.get("top_flows", [])
        top_flow_lines = []
        for f in top_flows_data:
            top_flow_lines.append(
                f"  [{f.get('flow_id', '?')}] {f.get('src', '?')} -> {f.get('dst', '?')} "
                f"({f.get('protocol', '?')}) {f.get('bytes', 0)}B {f.get('packets', 0)}包"
            )

        # TCP 健康指标格式化
        tcp_health_data = stats.get("tcp_health", {})
        if tcp_health_data and tcp_health_data.get("total_tcp_packets", 0) > 0:
            tcp_health_lines = [
                f"  TCP 总包: {tcp_health_data.get('total_tcp_packets', 0)}",
                f"  重传率: {tcp_health_data.get('retransmit_rate', 0):.2%}",
                f"  零窗口: {tcp_health_data.get('zero_window_count', 0)}",
                f"  RST: {tcp_health_data.get('rst_count', 0)}",
            ]
            tcp_health_str = "\n".join(tcp_health_lines)
        else:
            tcp_health_str = "  无 TCP 数据"

        # DNS 健康指标格式化
        dns_health_data = stats.get("dns_health", {})
        if dns_health_data and dns_health_data.get("response_count", 0) > 0:
            dns_health_str = (
                f"  DNS 响应: {dns_health_data.get('response_count', 0)}, "
                f"失败: {dns_health_data.get('failure_count', 0)}, "
                f"失败率: {dns_health_data.get('failure_rate', 0):.2%}"
            )
        else:
            dns_health_str = "  无 DNS 响应数据"

        # ICMP 错误格式化
        icmp_data = stats.get("icmp_error_summary", {})
        if icmp_data and icmp_data.get("total_errors", 0) > 0:
            by_type = icmp_data.get("by_type", {})
            type_str = ", ".join(f"Type{t}={c}" for t, c in by_type.items())
            icmp_errors_str = f"  ICMP 错误: {icmp_data.get('total_errors', 0)} ({type_str})"
        else:
            icmp_errors_str = "  无 ICMP 错误"

        # TTL 分布格式化
        ttl_data = stats.get("ttl_distribution", {})
        anomalous = ttl_data.get("anomalous_sources", [])
        if anomalous:
            ttl_lines = [f"  {a['ip']}: TTL跨度={a['ttl_range']} ({a['samples']}样本)" for a in anomalous[:5]]
            ttl_distribution_str = "\n".join(ttl_lines)
        else:
            ttl_distribution_str = "  无 TTL 异常"

        # 分片统计格式化
        frag_data = stats.get("fragment_stats", {})
        if frag_data and frag_data.get("frag_packets", 0) > 0:
            fragment_stats_str = (
                f"  分片包: {frag_data.get('frag_packets', 0)}, "
                f"重叠: {frag_data.get('overlaps', 0)}, "
                f"不完整: {frag_data.get('incomplete', 0)}"
            )
        else:
            fragment_stats_str = "  无分片数据"

        # 广播/组播/ARP 统计格式化
        bc_mc_data = stats.get("broadcast_multicast", {})
        bc_mc_parts = []
        if bc_mc_data:
            if bc_mc_data.get("broadcast_count", 0) > 0:
                bc_mc_parts.append(
                    f"广播: {bc_mc_data['broadcast_count']}包 ({bc_mc_data['broadcast_ratio']:.1%})"
                )
            if bc_mc_data.get("multicast_count", 0) > 0:
                bc_mc_parts.append(
                    f"组播: {bc_mc_data['multicast_count']}包 ({bc_mc_data['multicast_ratio']:.1%})"
                )
            arp_req = bc_mc_data.get("arp_request_count", 0)
            arp_rep = bc_mc_data.get("arp_reply_count", 0)
            if arp_req > 0 or arp_rep > 0:
                bc_mc_parts.append(f"ARP请求: {arp_req}, 应答: {arp_rep}")
        if bc_mc_parts:
            broadcast_multicast_str = "  " + ", ".join(bc_mc_parts)
        else:
            broadcast_multicast_str = "  无广播/组播数据"

        # PPS 时间线格式化
        pps_data = stats.get("pps_timeline", {})
        if pps_data and pps_data.get("max_pps", 0) > 0:
            pps_timeline_str = (
                f"  峰值 PPS: {pps_data.get('max_pps', 0)}, "
                f"中位数: {pps_data.get('median_pps', 0):.0f}, "
                f"突刺比: {pps_data.get('spike_ratio', 0):.1f}x"
            )
        else:
            pps_timeline_str = "  无 PPS 数据"

        # 异常流 ID 集合（用于自适应采样）
        anomalous_flow_ids: set[str] = set()
        for a in anomalies:
            for fid in a.get("affected_flows", []):
                anomalous_flow_ids.add(fid)

        # 每条流 + 采样包（异常流提高采样数）
        pkt_index = _build_packet_flow_index(packets)
        flow_sections = []
        for flow in flows:
            if flow.flow_id in anomalous_flow_ids:
                sample_count = min(self._packets_per_flow_layer1 * 3, 20)
            else:
                sample_count = self._packets_per_flow_layer1
            section = _format_flow_with_packets(flow, packets, sample_count, _index=pkt_index)
            flow_sections.append(section)

        user_prompt = get_layer1_template().format(
            total_packets=stats.get("total_packets", 0),
            total_bytes=stats.get("total_bytes", 0),
            total_flows=stats.get("total_flows", 0),
            duration=stats.get("duration", 0),
            time_range=time_range,
            bandwidth_bps=stats.get("bandwidth_bps", 0),
            avg_packet_size=stats.get("avg_packet_size", 0),
            avg_flow_size=stats.get("avg_flow_size", 0),
            flow_size_median=stats.get("flow_size_median", 0),
            protocol_distribution="\n".join(proto_lines) or "无数据",
            top_src="\n".join(src_lines) or "无数据",
            top_dst="\n".join(dst_lines) or "无数据",
            top_flows="\n".join(top_flow_lines) or "无数据",
            anomaly_summary="\n".join(anomaly_lines),
            tcp_health=tcp_health_str,
            dns_health=dns_health_str,
            icmp_errors=icmp_errors_str,
            ttl_distribution=ttl_distribution_str,
            fragment_stats=fragment_stats_str,
            broadcast_multicast=broadcast_multicast_str,
            pps_timeline=pps_timeline_str,
            all_flows_with_packets="\n".join(flow_sections),
        )

        # 输入长度安全检查 + 截断保护
        prompt_len = len(user_prompt) + len(system)
        if prompt_len > self._max_input_chars:
            budget = self._max_input_chars - len(system)
            if budget > 1000:
                user_prompt = _smart_truncate_text(user_prompt, budget)
            logger.warning(
                f"Layer1 prompt 截断: {prompt_len} -> "
                f"{len(user_prompt) + len(system)} (budget {self._max_input_chars})"
            )

        logger.info(
            f"Layer1 prompt: {len(flows)} 条流, "
            f"每流 {self._packets_per_flow_layer1} 包采样, "
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
        base_ts = flow.first_seen if flow.first_seen > 0 else 0.0

        pkt_lines = [_format_packet_line(p, base_ts) for p in relevant_packets]

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
            layer1_result=_smart_truncate_text(layer1_raw, layer1_limit),
            layer2_results=_smart_truncate_blocks(layer2_combined, layer2_limit),
            total_packets=stats.get("total_packets", 0),
            total_flows=stats.get("total_flows", 0),
            suspicious_flow_count=suspicious_flow_count,
            confirmed_flow_count=confirmed_flow_count,
        )

        return user_prompt, system


# ── 格式化工具函数 ──

# 无端口协议（ARP/ICMP 等不使用端口号的协议）
_NO_PORT_PROTOCOLS = frozenset({"ARP", "ICMP"})


def _format_endpoint(ip: str, port: int | None, protocol: str) -> str:
    """格式化端点地址，无端口协议不输出端口号"""
    if protocol in _NO_PORT_PROTOCOLS or port is None:
        return ip
    return f"{ip}:{port}"


def _format_packet_line(p: PacketRecord, base_ts: float) -> str:
    """格式化单个包行为可读行"""
    rel_ts = f"+{p.timestamp - base_ts:.3f}s " if base_ts > 0 else ""

    src = _format_endpoint(p.src_ip, p.src_port, p.protocol)
    dst = _format_endpoint(p.dst_ip, p.dst_port, p.protocol)

    line = f"  #{p.index} {rel_ts}{src} -> {dst} [{p.protocol}] len={p.length} {p.info}"

    # TTL 始终展示（让 AI 能从包级别发现 TTL 异常）
    extras = []
    if p.ttl is not None:
        extras.append(f"TTL={p.ttl}")
    # TCP 零窗口高亮
    if p.protocol == "TCP" and p.tcp_window == 0:
        extras.append("Win=0!")
    if extras:
        line += " " + " ".join(extras)

    return line


def _format_flow_header(flow: FlowRecord, svc_tag: str, dir_tag: str) -> str:
    """格式化流摘要 header 行"""
    src = _format_endpoint(flow.src_ip, flow.src_port, flow.protocol)
    dst = _format_endpoint(flow.dst_ip, flow.dst_port, flow.protocol)

    header = (
        f"### 流 [{flow.flow_id}] {src} -> {dst} ({flow.protocol}) "
        f"{flow.packet_count}包 {flow.byte_count}B dur={flow.duration:.2f}s "
        f"flags={','.join(sorted(flow.flags_set)) or '-'}{svc_tag}{dir_tag}"
    )

    # 流速率信息（duration > 0 时展示）
    if flow.duration > 0:
        header += f" avg={flow.bps / 1024:.1f}Kbps {flow.pps:.1f}pps"

    # TCP 流附带健康指标
    if flow.protocol == "TCP" and (
        flow.retransmit_count or flow.zero_window_count
        or flow.rst_count or flow.dup_ack_count
    ):
        header += (
            f"\n  TCP健康: 重传={flow.retransmit_count} "
            f"零窗口={flow.zero_window_count} "
            f"RST={flow.rst_count} 重复ACK={flow.dup_ack_count}"
        )

    return header


def _format_flow_with_packets(
    flow: FlowRecord,
    packets: list[PacketRecord],
    max_packets: int,
    _index: dict[tuple, list[PacketRecord]] | None = None,
) -> str:
    """格式化单条流记录 + 采样包"""
    svc = flow.service or classify_service(flow.src_port, flow.dst_port, flow.protocol)
    svc_tag = f" [{svc}]" if svc else ""

    # 内外网方向标签
    src_in = is_internal_ip(flow.src_ip)
    dst_in = is_internal_ip(flow.dst_ip)
    if src_in and not dst_in:
        dir_tag = " [内→外]"
    elif not src_in and dst_in:
        dir_tag = " [外→内]"
    elif src_in and dst_in:
        dir_tag = " [内→内]"
    else:
        dir_tag = " [外→外]"

    header = _format_flow_header(flow, svc_tag, dir_tag)

    # 选择属于该流的包
    flow_pkts = _select_relevant_packets(packets, flow, max_packets=max_packets, _index=_index)
    base_ts = flow.first_seen if flow.first_seen > 0 else 0.0

    pkt_lines = [_format_packet_line(p, base_ts) for p in flow_pkts]
    pkt_section = "\n".join(pkt_lines)
    if not pkt_section:
        pkt_section = "  （无可用包数据）"

    return f"{header}\n{pkt_section}"


def _select_relevant_packets(
    packets: list[PacketRecord],
    flow: FlowRecord,
    max_packets: int = 5,
    _index: dict[tuple, list[PacketRecord]] | None = None,
) -> list[PacketRecord]:
    """选择属于指定流的关键包

    采样策略：前2（握手/请求）+ 中间均匀采样 + 后2（结束/异常）
    """
    if _index is not None:
        f_sp = flow.src_port
        f_dp = flow.dst_port
        fwd = (flow.src_ip, f_sp, flow.dst_ip, f_dp)
        rev = (flow.dst_ip, f_dp, flow.src_ip, f_sp)
        key = (min(fwd, rev), max(fwd, rev), flow.protocol)
        flow_pkts = _index.get(key, [])
    else:
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


def _build_packet_flow_index(
    packets: list[PacketRecord],
) -> dict[tuple, list[PacketRecord]]:
    """构建 flow_key -> [packets] 索引，将 O(N*M) 降至 O(M + N*k)"""
    index: dict[tuple, list[PacketRecord]] = {}
    for p in packets:
        p_sp = p.src_port or 0
        p_dp = p.dst_port or 0
        fwd = (p.src_ip, p_sp, p.dst_ip, p_dp)
        rev = (p.dst_ip, p_dp, p.src_ip, p_sp)
        key = (min(fwd, rev), max(fwd, rev), p.protocol)
        if key not in index:
            index[key] = []
        index[key].append(p)
    return index
