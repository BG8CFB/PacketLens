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
    affected_ips: list[str] = field(default_factory=list)
    recommendation: str = ""
    raw_detail: str | None = None

    def to_dict(self) -> dict:
        """序列化为字典"""
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "affected_flows": self.affected_flows,
            "affected_ips": self.affected_ips,
            "recommendation": self.recommendation,
            "raw_detail": self.raw_detail,
        }

    @classmethod
    def from_dict(cls, data: dict) -> AnalysisIssue:
        """从字典反序列化"""
        return cls(
            severity=data.get("severity", "Info"),
            category=data.get("category", "General"),
            title=data.get("title", ""),
            description=data.get("description", ""),
            affected_flows=data.get("affected_flows", []),
            affected_ips=data.get("affected_ips", []),
            recommendation=data.get("recommendation", ""),
            raw_detail=data.get("raw_detail"),
        )


@dataclass
class FlowAnalysis:
    """Layer 2 单流分析结果"""

    flow_id: str
    verdict: str  # malicious | suspicious | benign | inconclusive
    confidence: float  # 0.0 ~ 1.0
    issues: list[AnalysisIssue] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    raw_text: str = ""

    VALID_VERDICTS = frozenset({"malicious", "suspicious", "benign", "inconclusive", "degraded"})

    def to_dict(self) -> dict:
        """序列化为字典"""
        return {
            "flow_id": self.flow_id,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "issues": [issue.to_dict() for issue in self.issues],
            "evidence": self.evidence,
            "raw_text": self.raw_text,
        }

    @classmethod
    def from_dict(cls, data: dict) -> FlowAnalysis:
        """从字典反序列化"""
        issues_data = data.get("issues", [])
        issues = [AnalysisIssue.from_dict(i) for i in issues_data]
        return cls(
            flow_id=data.get("flow_id", ""),
            verdict=data.get("verdict", "inconclusive"),
            confidence=max(0.0, min(1.0, data.get("confidence", 0.0))),
            issues=issues,
            evidence=data.get("evidence", []),
            raw_text=data.get("raw_text", ""),
        )


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
    risk_level: str = ""  # Critical | High | Medium | Low | Normal
    flow_analyses: list[FlowAnalysis] = field(default_factory=list)
    fault_insights: dict = field(default_factory=dict)

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

    def to_dict(self) -> dict:
        """序列化为字典（不包含计算属性）"""
        return {
            "session_id": self.session_id,
            "analysis_mode": self.analysis_mode,
            "timestamp": self.timestamp.isoformat(),
            "summary": self.summary,
            "issues": [issue.to_dict() for issue in self.issues],
            "protocol_insights": self.protocol_insights,
            "overall_assessment": self.overall_assessment,
            "raw_ai_response": self.raw_ai_response,
            "token_usage": self.token_usage,
            "duration_seconds": self.duration_seconds,
            "risk_level": self.risk_level,
            "flow_analyses": [fa.to_dict() for fa in self.flow_analyses],
            "fault_insights": self.fault_insights,
        }

    @classmethod
    def from_dict(cls, data: dict) -> AnalysisResult:
        """从字典反序列化"""
        issues_data = data.get("issues", [])
        issues = [AnalysisIssue.from_dict(i) for i in issues_data]
        flow_analyses_data = data.get("flow_analyses", [])
        flow_analyses = [FlowAnalysis.from_dict(fa) for fa in flow_analyses_data]
        timestamp_str = data.get("timestamp", "")
        if timestamp_str:
            timestamp = datetime.fromisoformat(timestamp_str)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp = datetime.now(tz=timezone.utc)
        return cls(
            session_id=data.get("session_id", ""),
            analysis_mode=data.get("analysis_mode", "quick"),
            timestamp=timestamp,
            summary=data.get("summary", ""),
            issues=issues,
            protocol_insights=data.get("protocol_insights", {}),
            overall_assessment=data.get("overall_assessment", ""),
            raw_ai_response=data.get("raw_ai_response", ""),
            token_usage=data.get("token_usage", {}),
            duration_seconds=data.get("duration_seconds", 0.0),
            risk_level=data.get("risk_level", ""),
            flow_analyses=flow_analyses,
            fault_insights=data.get("fault_insights", {}),
        )
