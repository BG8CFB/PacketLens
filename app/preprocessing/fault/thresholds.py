"""故障检测阈值常量

所有阈值集中配置，便于后续调优。
检测触发条件：同时满足绝对数量阈值和速率/比例阈值。
严重级别升级：当达到 Critical 阈值时，告警级别从 Warning 升级为 Critical。
"""

from __future__ import annotations

# ── ARP 欺骗（同 IP 出现多个 MAC） ──────────────────────
ARP_SPOOF_CONFLICT_THRESHOLD = 2       # 同 IP 映射 >=2 个不同 MAC → Warning
ARP_SPOOF_CRITICAL_THRESHOLD = 5       # >=5 个 MAC → Critical
ARP_SPOOF_MIN_PACKETS = 3              # 每个 IP 至少 3 个 ARP 包才纳入评估

# ── TCP 重传 ───────────────────────────────────────────
TCP_RETRANSMIT_RATE_WARNING = 0.05     # 全局重传率 >5% → Warning
TCP_RETRANSMIT_RATE_CRITICAL = 0.15    # >15% → Critical
TCP_RETRANSMIT_MIN_PACKETS = 50        # 全局 TCP 包 >=50 才评估

# ── TCP 零窗口 ─────────────────────────────────────────
TCP_ZERO_WINDOW_WARNING = 10           # >=10 个零窗口包 → Warning
TCP_ZERO_WINDOW_CRITICAL = 50          # >=50 → Critical

# ── RST 风暴 ───────────────────────────────────────────
RST_STORM_PACKET_THRESHOLD = 100       # >=100 个 RST 包
RST_STORM_RATE_THRESHOLD = 5.0         # >=5 RST/s
RST_STORM_CRITICAL_THRESHOLD = 500     # >=500 → Critical

# ── ICMP 错误风暴（type 3/5/11） ───────────────────────
ICMP_ERROR_PACKET_THRESHOLD = 50       # >=50 个错误包
ICMP_ERROR_RATE_THRESHOLD = 5.0        # >=5 错误/s
ICMP_ERROR_CRITICAL_THRESHOLD = 200    # >=200 → Critical

# ── TTL 异常（路由环路/不对称路由） ─────────────────────
TTL_ANOMALY_RANGE = 5                  # 同源 IP 的 TTL 跨度 >5 → 异常
TTL_ANOMALY_MIN_SAMPLES = 20           # 每个 IP 至少 20 个包才评估

# ── DNS 解析失败 ───────────────────────────────────────
DNS_FAILURE_RATE_WARNING = 0.10        # 失败率 >10% → Warning
DNS_FAILURE_MIN_RESPONSES = 10         # 至少 10 个 DNS 响应才评估
DNS_SERVFAIL_THRESHOLD = 5             # >=5 个 SERVFAIL → 独立 Warning

# ── IP 分片异常 ────────────────────────────────────────
FRAG_OVERLAP_THRESHOLD = 5             # >=5 重叠分片 → Warning
FRAG_INCOMPLETE_THRESHOLD = 10         # >=10 不完整分片集 → Warning
FRAG_TINY_THRESHOLD = 10               # >=10 微型分片(<8字节载荷) → Warning

# ── 流量突发（PPS 突刺） ───────────────────────────────
BURST_SPIKE_MULTIPLIER = 3.0           # PPS 峰值 >3x 中位数
BURST_MIN_PPS = 100                    # 绝对 PPS >=100 才视为突发
