"""故障检测基础类型"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FaultAlert:
    """故障告警（与 StormAlert 结构统一）"""

    type: str
    severity: str  # Critical | Warning | Info
    description: str
    affected_flows: list[str] = field(default_factory=list)
    affected_ips: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "severity": self.severity,
            "description": self.description,
            "affected_flows": self.affected_flows,
            "affected_ips": self.affected_ips,
            "detail": self.detail,
        }
