"""数据包摘要数据模型"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


# ── 协议名映射（Wireshark 风格 info 列文案的来源） ───────────────────────────

# RFC 792 / 1122 / 1812
ICMP_TYPES: dict[int, str] = {
    0: "Echo (ping) reply",
    3: "Destination unreachable",
    4: "Source quench",
    5: "Redirect",
    8: "Echo (ping) request",
    9: "Router advertisement",
    10: "Router solicitation",
    11: "Time exceeded",
    12: "Parameter problem",
    13: "Timestamp request",
    14: "Timestamp reply",
    15: "Information request",
    16: "Information reply",
    17: "Address mask request",
    18: "Address mask reply",
}

# Type=3 (Destination unreachable) 的 code 子类型
ICMP_DEST_UNREACH_CODES: dict[int, str] = {
    0: "Net unreachable",
    1: "Host unreachable",
    2: "Protocol unreachable",
    3: "Port unreachable",
    4: "Fragmentation needed",
    5: "Source route failed",
    6: "Destination network unknown",
    7: "Destination host unknown",
    13: "Communication administratively prohibited",
}

# Type=11 (Time exceeded) 的 code 子类型
ICMP_TIME_EXCEEDED_CODES: dict[int, str] = {
    0: "TTL expired in transit",
    1: "Fragment reassembly time exceeded",
}

# RFC 5246 §7.4 — TLS Handshake 子类型
TLS_HANDSHAKE_TYPES: dict[int, str] = {
    0: "Hello Request",
    1: "Client Hello",
    2: "Server Hello",
    4: "New Session Ticket",
    11: "Certificate",
    12: "Server Key Exchange",
    13: "Certificate Request",
    14: "Server Hello Done",
    15: "Certificate Verify",
    16: "Client Key Exchange",
    20: "Finished",
}

# RFC 1035 §3.2.2 / §3.2.3 — 常见 DNS Query Type
DNS_QTYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    41: "OPT",
    65: "HTTPS",
    255: "ANY",
}

# RFC 1035 §4.1.1 — DNS Response Code
DNS_RCODES: dict[int, str] = {
    0: "No error",
    1: "Format error",
    2: "Server failure",
    3: "NXDOMAIN",
    4: "Not implemented",
    5: "Refused",
}


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
    is_broadcast: bool = False  # 目的 IP 或二层目的 MAC 是否为广播
    is_multicast: bool = False  # 目的 IP 是否为组播地址
    arp_op: int | None = None  # ARP 操作码 (1=request, 2=reply)，仅 ARP 包有效
    icmp_type: int | None = None  # ICMP 类型 (0=reply, 8=request)，仅 ICMP 包有效
    summary: str = ""  # Scapy summary
    # ── 故障检测扩展字段 ──
    src_mac: str | None = None  # Ethernet 源 MAC — ARP 欺骗检测必需
    dst_mac: str | None = None  # Ethernet 目的 MAC
    tcp_seq: int | None = None  # TCP 序列号 — 重传/乱序检测
    tcp_ack: int | None = None  # TCP 确认号 — 重复 ACK 检测
    tcp_window: int | None = None  # TCP 窗口大小 — 零窗口检测
    ip_flags_df: bool = False  # IP Don't Fragment 标志
    ip_flags_mf: bool = False  # IP More Fragments 标志
    ip_frag: int = 0  # IP 分片偏移（8 字节单位）
    icmp_code: int | None = None  # ICMP code — 区分 DestUnreachable 子类型
    dns_rcode: int | None = None  # DNS 响应码 — NXDOMAIN/SERVFAIL

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
        is_broadcast = False
        is_multicast = False
        arp_op = None
        icmp_type = None
        src_mac = None
        dst_mac = None
        tcp_seq = None
        tcp_ack = None
        tcp_window = None
        ip_flags_df = False
        ip_flags_mf = False
        ip_frag = 0
        icmp_code = None
        dns_rcode = None

        # Ethernet 层提取（MAC 地址）
        from scapy.all import Ether
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ttl = ip_layer.ttl
            # IP 分片标志
            ip_flags_df = bool(ip_layer.flags.DF)
            ip_flags_mf = bool(ip_layer.flags.MF)
            ip_frag = ip_layer.frag
            # 广播判断: 有限广播 + 私有子网广播 (避免公网 .255 误报)
            if dst_ip == "255.255.255.255":
                is_broadcast = True
            else:
                try:
                    ip_obj = ipaddress.ip_address(dst_ip)
                    is_multicast = ip_obj.is_multicast
                    is_broadcast = (
                        not is_multicast
                        and dst_ip.endswith(".255")
                        and _is_private_subnet_broadcast(ip_obj)
                    )
                except ValueError:
                    is_broadcast = False
                    is_multicast = False

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                protocol = "TCP"
                src_port = tcp.sport
                dst_port = tcp.dport
                flags = str(tcp.flags)
                tcp_seq = tcp.seq
                tcp_ack = tcp.ack if tcp.flags.A else None
                tcp_window = tcp.window
                info = _tcp_info(tcp)
                # 应用层推断
                app_hint = _infer_tcp_app_layer(tcp, dst_port, src_port)
                if app_hint:
                    info = f"{info} {app_hint}"
                # DNS over TCP rcode 提取（仅响应包）
                if (dst_port == 53 or src_port == 53) and tcp.payload:
                    dns_payload = bytes(tcp.payload)
                    # TCP DNS 有 2 字节长度前缀 (RFC 1035 §4.2.2)
                    if len(dns_payload) >= 14:
                        dns_payload = dns_payload[2:]  # 跳过长度前缀
                    if len(dns_payload) >= 4:
                        dns_flags = (dns_payload[2] << 8) | dns_payload[3]
                        if (dns_flags >> 15) & 1:
                            dns_rcode = dns_flags & 0x0F

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                protocol = "UDP"
                src_port = udp.sport
                dst_port = udp.dport
                info = _udp_info(udp)
                app_hint = _infer_udp_app_layer(udp, dst_port, src_port)
                if app_hint:
                    info = f"{info} {app_hint}"
                # DNS rcode 提取（仅响应包）
                if (dst_port == 53 or src_port == 53) and udp.payload:
                    dns_payload = bytes(udp.payload)
                    if len(dns_payload) >= 4:
                        dns_flags = (dns_payload[2] << 8) | dns_payload[3]
                        if (dns_flags >> 15) & 1:  # qr=1 表示响应
                            dns_rcode = dns_flags & 0x0F

            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
                icmp = pkt[ICMP]
                icmp_type = icmp.type
                icmp_code = icmp.code
                info = _icmp_info(icmp)

            else:
                protocol = f"IP proto={ip_layer.proto}"
                info = f"IP {src_ip} → {dst_ip} proto={ip_layer.proto}"

        elif pkt.haslayer(ARP):
            arp = pkt[ARP]
            protocol = "ARP"
            src_ip = arp.psrc or ""
            dst_ip = arp.pdst or ""
            arp_op = arp.op
            info = _arp_info(arp)
            # ARP Request (op=1) 在二层是广播 (目的 MAC = ff:ff:ff:ff:ff:ff)
            # ARP Reply (op=2) 是单播，不应标记为广播
            is_broadcast = arp.op == 1

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
            is_broadcast=is_broadcast,
            is_multicast=is_multicast,
            arp_op=arp_op,
            icmp_type=icmp_type,
            summary=summary,
            src_mac=src_mac,
            dst_mac=dst_mac,
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            tcp_window=tcp_window,
            ip_flags_df=ip_flags_df,
            ip_flags_mf=ip_flags_mf,
            ip_frag=ip_frag,
            icmp_code=icmp_code,
            dns_rcode=dns_rcode,
        )

    def to_dict(self) -> dict:
        """序列化为字典（raw_bytes 以 hex 字符串形式存储）"""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length": self.length,
            "info": self.info,
            "raw_bytes": self.raw_bytes.hex(),
            "ttl": self.ttl,
            "flags": self.flags,
            "is_broadcast": self.is_broadcast,
            "is_multicast": self.is_multicast,
            "arp_op": self.arp_op,
            "icmp_type": self.icmp_type,
            "summary": self.summary,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "tcp_seq": self.tcp_seq,
            "tcp_ack": self.tcp_ack,
            "tcp_window": self.tcp_window,
            "ip_flags_df": self.ip_flags_df,
            "ip_flags_mf": self.ip_flags_mf,
            "ip_frag": self.ip_frag,
            "icmp_code": self.icmp_code,
            "dns_rcode": self.dns_rcode,
        }

    @classmethod
    def from_dict(cls, data: dict) -> PacketRecord:
        """从字典反序列化（raw_bytes 从 hex 字符串还原）"""
        raw_hex = data.get("raw_bytes", "")
        try:
            raw_bytes = bytes.fromhex(raw_hex) if raw_hex else b""
        except ValueError:
            raw_bytes = b""
        return cls(
            index=data.get("index", 0),
            timestamp=data.get("timestamp", 0.0),
            src_ip=data.get("src_ip", ""),
            dst_ip=data.get("dst_ip", ""),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            protocol=data.get("protocol", "Other"),
            length=data.get("length", 0),
            info=data.get("info", ""),
            raw_bytes=raw_bytes,
            ttl=data.get("ttl"),
            flags=data.get("flags"),
            is_broadcast=data.get("is_broadcast", False),
            is_multicast=data.get("is_multicast", False),
            arp_op=data.get("arp_op"),
            icmp_type=data.get("icmp_type"),
            summary=data.get("summary", ""),
            src_mac=data.get("src_mac"),
            dst_mac=data.get("dst_mac"),
            tcp_seq=data.get("tcp_seq"),
            tcp_ack=data.get("tcp_ack"),
            tcp_window=data.get("tcp_window"),
            ip_flags_df=data.get("ip_flags_df", False),
            ip_flags_mf=data.get("ip_flags_mf", False),
            ip_frag=data.get("ip_frag", 0),
            icmp_code=data.get("icmp_code"),
            dns_rcode=data.get("dns_rcode"),
        )


def _is_private_subnet_broadcast(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """判断地址是否为私有/本地子网广播地址

    仅对 IPv4 有效: 10.x.x.255 / 172.16-31.x.255 / 192.168.x.255 / 169.254.x.255
    避免公网 .255 地址 (如 1.2.3.255) 被误判为广播。
    """
    if not isinstance(ip_obj, ipaddress.IPv4Address):
        return False
    # RFC 1918 + 本地链路
    return (
        ip_obj.is_private
        or ip_obj.is_link_local
    )


def _tcp_flags_pretty(flags) -> str:
    """转换 Scapy TCP flags 为 Wireshark 风格 [SYN, ACK]

    Scapy 的 flags 对象支持位访问: flags.S/A/F/R/P/U/E/C
    """
    names: list[str] = []
    if flags.F:
        names.append("FIN")
    if flags.S:
        names.append("SYN")
    if flags.R:
        names.append("RST")
    if flags.P:
        names.append("PSH")
    if flags.A:
        names.append("ACK")
    if flags.U:
        names.append("URG")
    if flags.E:
        names.append("ECE")
    if flags.C:
        names.append("CWR")
    return "[" + ", ".join(names) + "]" if names else "[None]"


def _tcp_info(tcp) -> str:
    """生成 TCP 层信息摘要 (Wireshark 风格)

    格式: [FLAGS] Seq=N [Ack=N] [Win=N] [Len=N]
    示例: [SYN] Seq=0 Win=64240
          [SYN, ACK] Seq=0 Ack=1 Win=29200
          [PSH, ACK] Seq=1 Ack=1 Win=502 Len=517
    """
    parts = [_tcp_flags_pretty(tcp.flags), f"Seq={tcp.seq}"]
    if tcp.flags.A:
        parts.append(f"Ack={tcp.ack}")
    if tcp.window:
        parts.append(f"Win={tcp.window}")
    payload_len = len(tcp.payload) if tcp.payload else 0
    if payload_len:
        parts.append(f"Len={payload_len}")
    return " ".join(parts)


def _udp_info(udp) -> str:
    """生成 UDP 层信息摘要 (Wireshark 风格 Len=N)"""
    payload_len = len(udp.payload) if udp.payload else 0
    return f"Len={payload_len}"


def _icmp_info(icmp) -> str:
    """生成 ICMP 信息摘要 (Wireshark 风格)

    示例: Echo (ping) request id=0x0001, seq=1/256
          Destination unreachable (Port unreachable)
          Time exceeded (TTL expired in transit)
    """
    type_name = ICMP_TYPES.get(icmp.type, f"Unknown ICMP type {icmp.type}")
    parts = [type_name]

    # 子类型 code 解释
    if icmp.type == 3 and icmp.code in ICMP_DEST_UNREACH_CODES:
        parts.append(f"({ICMP_DEST_UNREACH_CODES[icmp.code]})")
    elif icmp.type == 11 and icmp.code in ICMP_TIME_EXCEEDED_CODES:
        parts.append(f"({ICMP_TIME_EXCEEDED_CODES[icmp.code]})")
    elif icmp.code:
        parts.append(f"(code={icmp.code})")

    # Echo 请求/应答专属字段：id 与 seq
    icmp_id = getattr(icmp, "id", None)
    icmp_seq = getattr(icmp, "seq", None)
    if icmp.type in (0, 8) and icmp_id is not None:
        parts.append(f"id=0x{icmp_id:04x}")
    if icmp.type in (0, 8) and icmp_seq is not None:
        parts.append(f"seq={icmp_seq}")

    return " ".join(parts)


def _arp_info(arp) -> str:
    """生成 ARP 信息摘要 (Wireshark 风格)

    示例: Who has 192.168.1.1? Tell 192.168.1.100
          192.168.1.1 is at aa:bb:cc:dd:ee:ff
    """
    psrc = arp.psrc or "?"
    pdst = arp.pdst or "?"
    if arp.op == 1:  # request
        return f"Who has {pdst}? Tell {psrc}"
    if arp.op == 2:  # reply
        hwsrc = arp.hwsrc or "?"
        return f"{psrc} is at {hwsrc}"
    return f"ARP opcode={arp.op}: {psrc} → {pdst}"


def _safe_decode(data, max_len: int = 200) -> str:
    """安全解码 payload 前 N 字节"""
    try:
        return data[:max_len].decode("ascii", errors="replace").strip()
    except Exception:
        return ""


def _match_port(
    dst_port: int | None,
    src_port: int | None,
    port_groups: list[tuple[int, ...]],
) -> int:
    """在 src_port 和 dst_port 中查找匹配的已知端口

    优先匹配 dst_port（客户端→服务器方向更常见），
    若不匹配则检查 src_port（捕获服务器响应）。
    返回匹配到的端口号，未匹配返回 0。
    """
    for group in port_groups:
        if dst_port in group:
            return dst_port or 0
        if src_port in group:
            return src_port or 0
    return 0


def _infer_tcp_app_layer(tcp, dst_port: int | None, src_port: int | None) -> str:
    """基于端口 + payload 推断 TCP 应用层协议，同时检查 src/dst 端口"""
    from scapy.all import Raw

    payload = bytes(tcp.payload) if tcp.payload else b""
    if not payload:
        return ""

    port = _match_port(dst_port, src_port, [
        (80, 8080, 8000, 8888),    # HTTP
        (443, 8443),               # TLS
        (22,),                     # SSH
        (21, 20),                  # FTP
        (25,),                     # SMTP
        (110,),                    # POP3
        (143,),                    # IMAP
        (23,),                     # Telnet
        (3389,),                   # RDP
        (445,),                    # SMB
        (3306,),                   # MySQL
    ])
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
        # TLS record: content_type(1) + version(2) + length(2) + (handshake_type(1) for type=0x16)
        if len(payload) >= 5 and payload[0] in (0x16, 0x14, 0x15, 0x17):
            ct = payload[0]
            if ct == 0x16 and len(payload) >= 6:
                hs_type = payload[5]
                hs_name = TLS_HANDSHAKE_TYPES.get(hs_type, f"Handshake type {hs_type}")
                return f"[TLS] {hs_name}"
            ct_names = {
                0x14: "Change Cipher Spec",
                0x15: "Alert",
                0x16: "Handshake",
                0x17: "Application Data",
            }
            return f"[TLS] {ct_names.get(ct, 'Unknown')}"
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
    """基于端口 + payload 推断 UDP 应用层协议，同时检查 src/dst 端口"""
    payload = bytes(udp.payload) if udp.payload else b""
    if not payload:
        return ""

    port = _match_port(dst_port, src_port, [
        (53,),       # DNS
        (67, 68),    # DHCP
        (123,),      # NTP
        (161,),      # SNMP
        (443,),      # QUIC
    ])

    if port == 53:
        # DNS: 12 字节 header + question section
        if len(payload) >= 12:
            return _format_dns_info(payload)
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


def _extract_dns_name(data: bytes, offset: int, _depth: int = 0) -> str:
    """从 DNS payload 中提取查询域名"""
    if _depth > 10:
        return ""
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
                rest = _extract_dns_name(data, ptr, _depth + 1)
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


def _dns_name_length(data: bytes, offset: int) -> int:
    """返回 DNS name 在 data 中占用的字节数（用于跳过 name 后定位 qtype/qclass）

    与 _extract_dns_name 不同，本函数仅计算长度，不递归解析压缩指针的目标。
    """
    pos = offset
    try:
        while pos < len(data) and pos < offset + 256:
            length = data[pos]
            if length == 0:
                return pos - offset + 1
            if (length & 0xC0) == 0xC0:
                # 压缩指针固定 2 字节
                return pos - offset + 2
            pos += 1 + length
    except (IndexError, ValueError):
        pass
    return pos - offset


def _format_dns_info(payload: bytes) -> str:
    """格式化 DNS payload 为 Wireshark 风格信息行

    格式:
      请求: [DNS] Standard query 0xTXID QTYPE name
      响应: [DNS] Standard query response 0xTXID QTYPE name [RCODE]

    payload 必须至少 12 字节（DNS header 长度）。
    """
    try:
        txid = (payload[0] << 8) | payload[1]
        flags = (payload[2] << 8) | payload[3]
        qr = (flags >> 15) & 1
        rcode = flags & 0x0F
        qdcount = (payload[4] << 8) | payload[5]
    except (IndexError, ValueError):
        return "[DNS]"

    direction = "Standard query response" if qr else "Standard query"

    # 提取第一个 question
    domain = ""
    qtype_str = ""
    if qdcount > 0:
        domain = _extract_dns_name(payload, 12)
        name_len = _dns_name_length(payload, 12)
        qtype_offset = 12 + name_len
        if qtype_offset + 2 <= len(payload):
            qtype = (payload[qtype_offset] << 8) | payload[qtype_offset + 1]
            qtype_str = DNS_QTYPES.get(qtype, str(qtype))

    parts = [direction, f"0x{txid:04x}"]
    if qtype_str:
        parts.append(qtype_str)
    if domain:
        parts.append(domain)
    if qr and rcode != 0:
        parts.append(DNS_RCODES.get(rcode, f"RCode {rcode}"))

    return "[DNS] " + " ".join(parts)
