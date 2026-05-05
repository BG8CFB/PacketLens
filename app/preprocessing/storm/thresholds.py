"""风暴检测阈值常量

所有阈值集中配置，便于后续调优。
检测触发条件：同时满足绝对数量阈值 和 速率阈值。
严重级别升级：当包数量达到 Critical 阈值时，告警级别从 Warning 升级为 Critical。
"""

from __future__ import annotations

# ── 广播风暴 ──────────────────────────────────────
BROADCAST_STORM_PACKET_THRESHOLD = 100
BROADCAST_STORM_RATE_THRESHOLD = 10.0  # pkt/s
BROADCAST_STORM_CRITICAL_THRESHOLD = 500  # 升级为 Critical 的包数量阈值

# ── 组播泛洪 ──────────────────────────────────────
MULTICAST_FLOOD_PACKET_THRESHOLD = 100
MULTICAST_FLOOD_RATE_THRESHOLD = 10.0  # pkt/s
MULTICAST_FLOOD_CRITICAL_THRESHOLD = 500

# ── ARP 泛洪 ──────────────────────────────────────
ARP_FLOOD_PACKET_THRESHOLD = 100
ARP_FLOOD_RATE_THRESHOLD = 5.0  # pkt/s
ARP_FLOOD_CRITICAL_THRESHOLD = 500

# ── ICMP 泛洪 (ping flood) ────────────────────────
ICMP_FLOOD_PACKET_THRESHOLD = 100
ICMP_FLOOD_RATE_THRESHOLD = 10.0  # pkt/s
ICMP_FLOOD_CRITICAL_THRESHOLD = 500
