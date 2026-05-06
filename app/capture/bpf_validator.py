"""BPF 过滤器语法验证"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# 明显非法字符（BPF 语法中不应出现）
_BPF_ILLEGAL_CHARS = re.compile(r'[\[\]{}\\`一-鿿]')

# BPF 已知协议/关键字白名单（用于检测完全不合法的表达式）
_BPF_KNOWN_TOKENS = frozenset({
    "tcp", "udp", "icmp", "icmp6", "arp", "rarp", "ip", "ip6",
    "ether", "fddi", "tr", "wlan", "ppp", "slip", "link",
    "host", "net", "port", "portrange",
    "src", "dst",
    "and", "or", "not",
    "less", "greater", "proto", "protochain",
    "broadcast", "multicast", "inbound", "outbound",
    "vlan", "mpls", "sctp",
})


def _validate_bpf_basic(filter_str: str) -> tuple[bool, str]:
    """轻量级 BPF 语法校验（compile_filter 不可用时的回退）

    仅捕获最明显的语法错误，不替代 libpcap 编译器的精确验证。
    比误拒合法过滤器更糟的是——阻止用户使用有效过滤器。
    """
    stripped = filter_str.strip()
    if not stripped:
        return True, ""

    # 检查明显非法字符
    m = _BPF_ILLEGAL_CHARS.search(stripped)
    if m:
        return False, f"BPF 过滤器包含非法字符: '{m.group()}'"

    # 检查是否包含至少一个 BPF 已知 token（排除纯随机文本）
    tokens = stripped.lower().split()
    has_known = any(t in _BPF_KNOWN_TOKENS for t in tokens)
    has_ip = any(re.match(r'\d{1,3}(\.\d{1,3}){3}', t) for t in tokens)
    has_number = any(t.isdigit() for t in tokens)

    if not has_known and not has_ip and not has_number:
        return False, "BPF 过滤器不包含任何已知关键字或有效值"

    # 检查负端口号
    for token in tokens:
        if token.startswith("-") and len(token) > 1 and token[1:].isdigit():
            return False, f"负数端口号无效: {token}"

    return True, ""


def validate_bpf(filter_str: str) -> tuple[bool, str]:
    """验证 BPF 过滤器语法是否正确

    使用 Scapy 底层 BPF 编译接口验证语法，不触发实际抓包。
    返回: (是否有效, 错误信息)
    """
    if not filter_str or not filter_str.strip():
        return True, ""

    try:
        from scapy.all import compile_filter

        compile_filter(filter_str)
        return True, ""
    except ImportError:
        # 旧版 Scapy 无 compile_filter — 使用轻量校验
        logger.debug("compile_filter 不可用，使用基础 BPF 语法校验")
        return _validate_bpf_basic(filter_str)
    except Exception as e:
        error_msg = str(e)
        logger.debug(f"BPF 过滤器验证失败: {filter_str} -> {error_msg}")
        return False, error_msg
