"""AI 分析结果数据模型"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class AnalysisIssue:
    """单个分析发现"""

    severity: str  # Critical, Warning, Info, Normal
    category: str  # Security, Performance, Anomaly, Protocol, Configuration
    title: str
    description: str
    affected_flows: list[str] = field(default_factory=list)
    recommendation: str = ""
    raw_detail: str | None = None


@dataclass
class AnalysisResult:
    """AI 分析完整结果"""

    session_id: str = ""
    analysis_mode: str = "quick"  # quick or deep
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    summary: str = ""
    issues: list[AnalysisIssue] = field(default_factory=list)
    protocol_insights: dict = field(default_factory=dict)
    overall_assessment: str = ""
    raw_ai_response: str = ""
    token_usage: dict = field(default_factory=dict)
    duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity.lower() == "critical")

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity.lower() == "warning")

    @property
    def info_count(self) -> int:
        return sum(1 for i in self.issues if i.severity.lower() == "info")

    @property
    def has_critical(self) -> bool:
        return self.critical_count > 0

    @property
    def has_warnings(self) -> bool:
        return self.warning_count > 0
