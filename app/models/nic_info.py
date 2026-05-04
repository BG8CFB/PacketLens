"""网卡信息数据模型"""

from dataclasses import dataclass


@dataclass
class NICInfo:
    """网络接口信息"""

    name: str  # Scapy 接口名
    description: str  # 友好描述
    ip_address: str | None = None
    mac_address: str | None = None
    is_up: bool = False
    index: int = 0

    @property
    def display_name(self) -> str:
        """UI 展示名称"""
        parts = [self.description or self.name]
        if self.ip_address:
            parts.append(f"({self.ip_address})")
        return " ".join(parts)
