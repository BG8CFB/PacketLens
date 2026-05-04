"""BPF 过滤器语法验证"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def validate_bpf(filter_str: str) -> tuple[bool, str]:
    """验证 BPF 过滤器语法是否正确

    使用 scapy.sniff(count=1) 配合极短超时做干跑验证。
    count=1 确保在所有 scapy 版本中都能触发 BPF 编译器验证语法。
    返回: (是否有效, 错误信息)
    """
    if not filter_str or not filter_str.strip():
        return True, ""

    try:
        from scapy.all import sniff

        # count=1 比 count=0 更可靠地触发 BPF 编译验证
        sniff(count=1, filter=filter_str, timeout=0.1)
        return True, ""
    except Exception as e:
        error_msg = str(e)
        logger.debug(f"BPF 过滤器验证失败: {filter_str} -> {error_msg}")
        return False, error_msg
