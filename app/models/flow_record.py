"""五元组流聚合数据模型"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FlowRecord:
    """五元组聚合流记录"""

    flow_id: str  # 五元组哈希
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # L4 协议
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    flags_set: set[str] = field(default_factory=set)
    has_payload: bool = False
    service: str | None = None  # 推断的服务名（HTTP, DNS, TLS 等）

    @property
    def duration(self) -> float:
        if self.first_seen == 0.0:
            return 0.0
        return self.last_seen - self.first_seen

    @property
    def bps(self) -> float:
        """平均比特率"""
        dur = self.duration
        if dur <= 0:
            return 0.0
        return (self.byte_count * 8) / dur

    @property
    def pps(self) -> float:
        """平均包速率"""
        dur = self.duration
        if dur <= 0:
            return 0.0
        return self.packet_count / dur

    def to_dict(self) -> dict:
        """序列化为字典，仅包含存储属性；flags_set 转为 sorted list 以支持 JSON"""
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "flags_set": sorted(self.flags_set),
            "has_payload": self.has_payload,
            "service": self.service,
        }

    @classmethod
    def from_dict(cls, data: dict) -> FlowRecord:
        """从字典反序列化"""
        flags_data = data.get("flags_set", [])
        return cls(
            flow_id=data.get("flow_id", ""),
            src_ip=data.get("src_ip", ""),
            dst_ip=data.get("dst_ip", ""),
            src_port=data.get("src_port", 0),
            dst_port=data.get("dst_port", 0),
            protocol=data.get("protocol", ""),
            packet_count=data.get("packet_count", 0),
            byte_count=data.get("byte_count", 0),
            first_seen=data.get("first_seen", 0.0),
            last_seen=data.get("last_seen", 0.0),
            flags_set=set(flags_data) if flags_data else set(),
            has_payload=data.get("has_payload", False),
            service=data.get("service"),
        )
