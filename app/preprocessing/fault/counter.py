"""故障检测增量计数器

在抓包过程中实时统计各类故障信号，O(1) 每包开销。
与 StormCounter 互补：StormCounter 覆盖广播/组播/ARP 泛洪/ICMP Echo，
本计数器覆盖 TCP 健康/ICMP 错误/DNS/分片/TTL/PPS/ARP 欺骗。
"""

from __future__ import annotations

from collections import defaultdict

from app.models.packet_record import PacketRecord

# 内存增长上限
_MAX_FRAG_SETS = 500
_MAX_TTL_SOURCES = 500
_MAX_ARP_IP_MAC_ENTRIES = 500


class FaultCounter:
    """轻量级故障计数器 — 在 CaptureEngine._on_poll() 中增量更新"""

    def __init__(self) -> None:
        # TCP 健康度（聚合）
        self.tcp_total: int = 0
        self.tcp_zero_windows: int = 0
        self.tcp_rst_count: int = 0

        # ICMP 错误（type 3=不可达, 5=重定向, 11=超时）
        self.icmp_error_count: int = 0
        self.icmp_error_by_type: dict[int, int] = {}

        # DNS 健康
        self.dns_response_count: int = 0
        self.dns_failure_count: int = 0
        self.dns_rcode_breakdown: dict[int, int] = {}

        # IP 分片
        self.frag_packets: int = 0
        self.frag_overlaps: int = 0
        self.frag_incomplete: int = 0
        self._frag_sets: dict[tuple[str, int], dict] = {}

        # TTL 追踪（按 src_ip，限制 IP 数量）
        self.ttl_by_src: dict[str, list[int]] = {}
        self._ttl_sample_limit: int = 100

        # PPS 突发追踪（1 秒分桶，60 桶环形缓冲）
        self.pps_buckets: list[int] = [0] * 60
        self._current_bucket_ts: float = 0.0
        self._bucket_idx: int = 0

        # ARP 欺骗增量追踪（IP → MAC 集合）
        self.arp_ip_mac_map: dict[str, set[str]] = defaultdict(set)
        self.arp_ip_packet_count: dict[str, int] = defaultdict(int)

    def update(self, pkt: PacketRecord) -> None:
        """处理单个包，更新对应计数器"""
        self._update_pps_bucket(pkt.timestamp)

        # TCP 健康度
        if pkt.protocol == "TCP":
            self.tcp_total += 1
            if pkt.tcp_window == 0:
                self.tcp_zero_windows += 1
            if pkt.flags and "R" in pkt.flags:
                self.tcp_rst_count += 1

        # ICMP 错误（type 3/5/11 是错误类，排除 Echo 0/8）
        if pkt.protocol == "ICMP" and pkt.icmp_type is not None:
            if pkt.icmp_type in (3, 5, 11):
                self.icmp_error_count += 1
                self.icmp_error_by_type[pkt.icmp_type] = (
                    self.icmp_error_by_type.get(pkt.icmp_type, 0) + 1
                )

        # DNS 响应统计
        if pkt.dns_rcode is not None:
            self.dns_response_count += 1
            if pkt.dns_rcode != 0:
                self.dns_failure_count += 1
            self.dns_rcode_breakdown[pkt.dns_rcode] = (
                self.dns_rcode_breakdown.get(pkt.dns_rcode, 0) + 1
            )

        # IP 分片
        if pkt.ip_flags_mf or pkt.ip_frag > 0:
            self.frag_packets += 1
            if len(self._frag_sets) < _MAX_FRAG_SETS:
                self._track_fragment(pkt)

        # TTL 追踪（限制追踪的源 IP 数量）
        if pkt.ttl is not None and pkt.src_ip:
            if pkt.src_ip in self.ttl_by_src or len(self.ttl_by_src) < _MAX_TTL_SOURCES:
                samples = self.ttl_by_src.get(pkt.src_ip)
                if samples is None:
                    self.ttl_by_src[pkt.src_ip] = [pkt.ttl]
                elif len(samples) < self._ttl_sample_limit:
                    samples.append(pkt.ttl)

        # ARP 欺骗增量追踪
        if (
            pkt.protocol == "ARP"
            and pkt.arp_op == 2
            and pkt.src_mac
            and pkt.src_ip
            and len(self.arp_ip_mac_map) < _MAX_ARP_IP_MAC_ENTRIES
        ):
            self.arp_ip_mac_map[pkt.src_ip].add(pkt.src_mac.lower())
            self.arp_ip_packet_count[pkt.src_ip] += 1

    def _update_pps_bucket(self, ts: float) -> None:
        """推进 PPS 时间分桶"""
        if self._current_bucket_ts == 0.0:
            self._current_bucket_ts = ts

        elapsed = ts - self._current_bucket_ts
        bucket_advance = int(elapsed)

        if bucket_advance > 0:
            if bucket_advance >= 60:
                self.pps_buckets = [0] * 60
                self._bucket_idx = 0
            else:
                for _ in range(bucket_advance):
                    self._bucket_idx = (self._bucket_idx + 1) % 60
                    self.pps_buckets[self._bucket_idx] = 0
            self._current_bucket_ts += bucket_advance

        self.pps_buckets[self._bucket_idx] += 1

    def _track_fragment(self, pkt: PacketRecord) -> None:
        """追踪分片状态，检测区间重叠/不完整"""
        ip_id = 0
        if pkt.raw_bytes and len(pkt.raw_bytes) >= 20:
            ip_id = (pkt.raw_bytes[18] << 8) | pkt.raw_bytes[19]
        key = (pkt.src_ip, ip_id)

        state = self._frag_sets.get(key)
        if state is None:
            state = {"ranges": [], "has_last": False}
            self._frag_sets[key] = state

        offset = pkt.ip_frag * 8  # 转为字节偏移
        frag_len = 0
        if pkt.raw_bytes and len(pkt.raw_bytes) >= 20:
            total_len = (pkt.raw_bytes[2] << 8) | pkt.raw_bytes[3]
            hdr_len = (pkt.raw_bytes[0] & 0x0F) * 4
            frag_len = max(0, total_len - hdr_len)
        end = offset + frag_len

        for (s, e) in state["ranges"]:
            if offset < e and end > s:
                self.frag_overlaps += 1
                break
        state["ranges"].append((offset, end))

        if not pkt.ip_flags_mf:
            state["has_last"] = True

    def finalize_fragments(self) -> None:
        """统计未完成的分片组并清理已完成的分片组"""
        incomplete = 0
        completed_keys = []
        for key, state in self._frag_sets.items():
            if not state["has_last"]:
                incomplete += 1
            else:
                completed_keys.append(key)
        self.frag_incomplete = incomplete
        for key in completed_keys:
            del self._frag_sets[key]

    def get_pps_stats(self) -> dict:
        """返回 PPS 统计摘要（median 仅基于已使用桶）"""
        max_pps = max(self.pps_buckets) if self.pps_buckets else 0
        used = [b for b in self.pps_buckets if b > 0]
        if not used:
            return {"max_pps": max_pps, "median_pps": 0.0, "spike_ratio": 0.0}
        sorted_used = sorted(used)
        n = len(sorted_used)
        mid = n // 2
        if n % 2 == 0:
            median_pps = (sorted_used[mid - 1] + sorted_used[mid]) / 2.0
        else:
            median_pps = float(sorted_used[mid])
        spike_ratio = max_pps / median_pps if median_pps > 0 else 0.0
        return {
            "max_pps": max_pps,
            "median_pps": median_pps,
            "spike_ratio": round(spike_ratio, 2),
        }

    def reset(self) -> None:
        self.__init__()
