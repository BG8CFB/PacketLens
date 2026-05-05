"""BPF 过滤器语法验证"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


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
        # 旧版 Scapy 无 compile_filter，回退到 sniff 方式
        try:
            from scapy.all import sniff
            sniff(count=1, filter=filter_str, timeout=0.1)
            return True, ""
        except Exception as e:
            error_msg = str(e)
            logger.debug(f"BPF 过滤器验证失败: {filter_str} -> {error_msg}")
            return False, error_msg
    except Exception as e:
        error_msg = str(e)
        logger.debug(f"BPF 过滤器验证失败: {filter_str} -> {error_msg}")
        return False, error_msg
