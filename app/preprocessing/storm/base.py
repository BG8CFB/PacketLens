"""风暴检测基础类型"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class StormAlert:
    """风暴告警"""

    type: str
    severity: str
    description: str
    affected_flows: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "severity": self.severity,
            "description": self.description,
            "affected_flows": self.affected_flows,
            "detail": self.detail,
        }
