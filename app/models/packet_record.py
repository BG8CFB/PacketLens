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
        from scapy.all import IP, TCP, UDP, ICMP, ARP, Raw

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
                # 应用层推断
                app_hint = _infer_tcp_app_layer(tcp, dst_port, src_port)
                if app_hint:
                    info = f"{info} {app_hint}"

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                protocol = "UDP"
                src_port = udp.sport
                dst_port = udp.dport
                info = _udp_info(udp)
                app_hint = _infer_udp_app_layer(udp, dst_port, src_port)
                if app_hint:
                    info = f"{info} {app_hint}"

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


def _safe_decode(data, max_len: int = 200) -> str:
    """安全解码 payload 前 N 字节"""
    try:
        return data[:max_len].decode("ascii", errors="replace").strip()
    except Exception:
        return ""


def _infer_tcp_app_layer(tcp, dst_port: int | None, src_port: int | None) -> str:
    """基于端口 + payload 推断 TCP 应用层协议"""
    from scapy.all import Raw

    payload = bytes(tcp.payload) if tcp.payload else b""
    if not payload:
        return ""

    port = dst_port or 0
    hint = ""

    if port in (80, 8080, 8000, 8888):
        text = _safe_decode(payload, 80)
        for method in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "):
            if text.startswith(method):
                path = text.split(" ")[1] if " " in text[4:] else "/"
                path = path[:60]
                return f"[HTTP] {method.strip()} {path}"
        if text.startswith("HTTP/"):
            return f"[HTTP] {text[:60]}"
        hint = "[HTTP]"

    elif port in (443, 8443):
        # TLS record: content_type(1) + version(2) + length(2)
        if len(payload) >= 5 and payload[0] in (0x16, 0x14, 0x15, 0x17):
            ct = {0x16: "Handshake", 0x14: "ChangeCipherSpec",
                  0x15: "Alert", 0x17: "ApplicationData"}
            return f"[TLS] {ct.get(payload[0], 'Unknown')}"
        hint = "[TLS]"

    elif port == 22:
        text = _safe_decode(payload, 40)
        if text.startswith("SSH-"):
            return f"[SSH] {text[:40]}"
        hint = "[SSH]"

    elif port in (21, 20):
        text = _safe_decode(payload, 60)
        if text and (text[0:1].isdigit() or text.startswith("USER") or text.startswith("PASS")):
            return f"[FTP] {text[:60]}"
        hint = "[FTP]"

    elif port == 25:
        text = _safe_decode(payload, 60)
        for cmd in ("EHLO", "HELO", "MAIL", "RCPT", "DATA", "QUIT"):
            if text.startswith(cmd):
                return f"[SMTP] {text[:60]}"
        hint = "[SMTP]"

    elif port == 110:
        hint = "[POP3]"

    elif port == 143:
        hint = "[IMAP]"

    elif port == 23:
        hint = "[Telnet]"

    elif port == 3389:
        hint = "[RDP]"

    elif port == 445:
        hint = "[SMB]"

    elif port == 3306:
        text = _safe_decode(payload, 30)
        if text:
            return f"[MySQL] {text[:30]}"
        hint = "[MySQL]"

    return hint


def _infer_udp_app_layer(udp, dst_port: int | None, src_port: int | None) -> str:
    """基于端口 + payload 推断 UDP 应用层协议"""
    payload = bytes(udp.payload) if udp.payload else b""
    if not payload:
        return ""

    port = dst_port or 0

    if port == 53:
        # DNS: 12 bytes header minimum
        if len(payload) >= 12:
            qr = (payload[2] >> 7) & 1  # QR bit: 0=query, 1=response
            qdcount = (payload[4] << 8) | payload[5]
            # 提取查询域名
            domain = _extract_dns_name(payload, 12)
            if domain:
                direction = "Response" if qr else "Query"
                return f"[DNS] {direction} {domain}"
            return f"[DNS] {direction}"
        return "[DNS]"

    elif port in (67, 68):
        return "[DHCP]"

    elif port == 123:
        return "[NTP]"

    elif port == 161:
        return "[SNMP]"

    elif port == 443:
        # QUIC
        if len(payload) >= 5 and payload[0] in (0x16, 0x14, 0x15, 0x17):
            return "[QUIC] Handshake"
        return "[QUIC]"

    return ""


def _extract_dns_name(data: bytes, offset: int) -> str:
    """从 DNS payload 中提取查询域名"""
    labels = []
    pos = offset
    try:
        while pos < len(data) and pos < offset + 256:
            length = data[pos]
            if length == 0:
                break
            if (length & 0xC0) == 0xC0:
                # DNS compression pointer
                ptr = ((length & 0x3F) << 8) | data[pos + 1]
                rest = _extract_dns_name(data, ptr)
                if rest:
                    labels.append(rest)
                break
            pos += 1
            label = data[pos:pos + length].decode("ascii", errors="replace")
            labels.append(label)
            pos += length
    except (IndexError, ValueError):
        pass
    return ".".join(labels) if labels else ""
