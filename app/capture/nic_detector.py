"""网卡枚举与 Npcap 检测"""

from __future__ import annotations

import logging

from app.models.nic_info import NICInfo
from app.utils.npcap_installer import is_npcap_installed

logger = logging.getLogger(__name__)


class NpcapNotFoundError(Exception):
    """Npcap 未安装异常"""

    def __init__(self):
        super().__init__(
            "Npcap 未安装。请访问 https://npcap.com/#download 下载并安装 Npcap，然后重新启动本应用。"
        )


def check_npcap() -> None:
    """检测 Npcap 是否安装，未安装则抛出异常"""
    if not is_npcap_installed():
        raise NpcapNotFoundError()
    logger.info("Npcap 已检测到")


def list_interfaces() -> list[NICInfo]:
    """枚举系统所有可用网卡，返回按物理网卡优先排序的列表"""
    from scapy.all import get_working_ifaces, get_if_addr, get_if_hwaddr

    check_npcap()

    raw_ifaces = get_working_ifaces()
    result: list[NICInfo] = []

    for iface in raw_ifaces:
        try:
            ip = get_if_addr(iface)
        except (ValueError, OSError):
            ip = None
        try:
            mac = get_if_hwaddr(iface)
        except (ValueError, OSError):
            mac = None

        # 判断是否为回环
        description = getattr(iface, "description", str(iface)) or str(iface)
        name = getattr(iface, "name", str(iface)) or str(iface)

        nic = NICInfo(
            name=name,
            description=description,
            ip_address=ip if ip and ip != "0.0.0.0" else None,
            mac_address=mac,
            is_up=True,
            index=getattr(iface, "index", 0) or 0,
        )
        result.append(nic)

    # 有 IP 的物理网卡排前，回环排后
    result.sort(key=lambda n: (n.ip_address is None, "Loopback" in n.description))
    return result


def get_default_interface() -> NICInfo | None:
    """获取默认网卡"""
    from scapy.all import get_working_if, get_if_addr, get_if_hwaddr

    check_npcap()

    iface = get_working_if()
    if iface is None:
        return None

    try:
        ip = get_if_addr(iface)
    except (ValueError, OSError):
        ip = None
    try:
        mac = get_if_hwaddr(iface)
    except (ValueError, OSError):
        mac = None

    return NICInfo(
        name=getattr(iface, "name", str(iface)),
        description=getattr(iface, "description", str(iface)) or str(iface),
        ip_address=ip if ip and ip != "0.0.0.0" else None,
        mac_address=mac,
        is_up=True,
        index=getattr(iface, "index", 0) or 0,
    )
