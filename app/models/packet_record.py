"""数据包摘要数据模型"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PacketRecord:
    """轻量级数据包摘要，用于 UI 展示和预处理"""

    index: int  # 顺序编号
    timestamp: float  # Unix 时间戳
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str  # TCP, UDP, ICMP, ARP 等
    length: int  # 总字节长度
    info: str  # 人类可读摘要行
    raw_bytes: bytes  # 原始字节（Hex 视图 + PCAP 写入）
    ttl: int | None = None
    flags: str | None = None  # TCP flags 字符串
    summary: str = ""  # Scapy summary

    @classmethod
    def from_scapy_packet(cls, index: int, pkt) -> PacketRecord:
        """从 Scapy 原始包解析为 PacketRecord"""
        from scapy.all import IP, TCP, UDP, ICMP, ARP

        timestamp = float(pkt.time)
        raw_bytes = bytes(pkt)
        length = len(raw_bytes)
        summary = pkt.summary()

        src_ip = ""
        dst_ip = ""
        src_port = None
        dst_port = None
        protocol = "Other"
        ttl = None
        flags = None
        info = ""

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ttl = ip_layer.ttl

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                protocol = "TCP"
                src_port = tcp.sport
                dst_port = tcp.dport
                flags = str(tcp.flags)
                info = _tcp_info(tcp)

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                protocol = "UDP"
                src_port = udp.sport
                dst_port = udp.dport
                info = _udp_info(udp)

            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
                icmp = pkt[ICMP]
                info = f"ICMP type={icmp.type} code={icmp.code}"

            else:
                protocol = f"IP proto={ip_layer.proto}"
                info = f"IP {src_ip} → {dst_ip} proto={ip_layer.proto}"

        elif pkt.haslayer(ARP):
            arp = pkt[ARP]
            protocol = "ARP"
            src_ip = arp.psrc or ""
            dst_ip = arp.pdst or ""
            info = f"ARP op={arp.op}: {arp.psrc} → {arp.pdst}"

        else:
            info = summary

        return cls(
            index=index,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=length,
            info=info,
            raw_bytes=raw_bytes,
            ttl=ttl,
            flags=flags,
            summary=summary,
        )


def _tcp_info(tcp) -> str:
    """生成 TCP 层信息摘要"""
    parts = [str(tcp.flags)]
    parts.append(f"seq={tcp.seq}")
    if tcp.flags.A:
        parts.append(f"ack={tcp.ack}")
    if tcp.window:
        parts.append(f"win={tcp.window}")
    payload_len = len(tcp.payload) if tcp.payload else 0
    if payload_len:
        parts.append(f"len={payload_len}")
    return " ".join(parts)


def _udp_info(udp) -> str:
    """生成 UDP 层信息摘要"""
    payload_len = len(udp.payload) if udp.payload else 0
    return f"len={payload_len}"
