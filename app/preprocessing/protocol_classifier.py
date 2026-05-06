"""协议识别与分类"""

from __future__ import annotations

import ipaddress

from app.constants import PROTOCOL_COLORS

# 常见端口 → 服务名映射
WELL_KNOWN_PORTS: dict[tuple[int, str], str] = {
    (20, "TCP"): "FTP-Data",
    (21, "TCP"): "FTP",
    (22, "TCP"): "SSH",
    (23, "TCP"): "Telnet",
    (25, "TCP"): "SMTP",
    (53, "TCP"): "DNS",
    (53, "UDP"): "DNS",
    (67, "UDP"): "DHCP",
    (68, "UDP"): "DHCP",
    (80, "TCP"): "HTTP",
    (110, "TCP"): "POP3",
    (123, "UDP"): "NTP",
    (143, "TCP"): "IMAP",
    (161, "UDP"): "SNMP",
    (443, "TCP"): "TLS",
    (445, "TCP"): "SMB",
    (993, "TCP"): "IMAPS",
    (995, "TCP"): "POP3S",
    (1433, "TCP"): "MSSQL",
    (3306, "TCP"): "MySQL",
    (3389, "TCP"): "RDP",
    (5432, "TCP"): "PostgreSQL",
    (5900, "TCP"): "VNC",
    (6379, "TCP"): "Redis",
    (8080, "TCP"): "HTTP-Alt",
    (8443, "TCP"): "TLS-Alt",
    (27017, "TCP"): "MongoDB",
    # --- P2 增强：常见协议补充 ---
    (443, "UDP"): "QUIC",
    (5353, "UDP"): "mDNS",
    (3478, "UDP"): "STUN",
    (1900, "UDP"): "SSDP",
    (51820, "UDP"): "WireGuard",
    (137, "UDP"): "NetBIOS",
    (138, "UDP"): "NetBIOS",
    (427, "TCP"): "SLP",
    (427, "UDP"): "SLP",
    (1723, "TCP"): "PPTP",
    (5222, "TCP"): "XMPP",
}


def classify_service(src_port: int | None, dst_port: int | None, protocol: str) -> str | None:
    """根据端口号推断服务名

    优先匹配目标端口，其次匹配源端口。
    跳过 None 和 0 值端口（ICMP 等无端口协议的端口会被填为 0）。
    """
    for port in (dst_port, src_port):
        if port is not None and port > 0:
            key = (port, protocol)
            if key in WELL_KNOWN_PORTS:
                return WELL_KNOWN_PORTS[key]
    return None


def get_protocol_color(protocol: str) -> str:
    """获取协议对应颜色"""
    return PROTOCOL_COLORS.get(protocol, "#CCCCCC")


# RFC 1918 + loopback + link-local
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_internal_ip(ip_str: str) -> bool:
    """判断 IP 是否为内网地址（RFC 1918 + loopback + link-local）"""
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False
