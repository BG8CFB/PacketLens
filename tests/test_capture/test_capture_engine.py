"""CaptureEngine 单元测试 — 覆盖预处理信号载荷格式与状态字段（修复4）"""

from __future__ import annotations

from collections import Counter

import pytest
from PySide6.QtWidgets import QApplication

from app.capture.capture_engine import CaptureEngine
from app.models.packet_record import PacketRecord
from app.ui.packet_table_model import PacketTableModel


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def engine(qapp) -> CaptureEngine:
    model = PacketTableModel()
    return CaptureEngine(model)


def _seed_engine_state(engine: CaptureEngine) -> None:
    """填充预处理所需的最少增量状态，用于触发 _run_preprocessing"""
    engine._running_proto_dist = Counter({"TCP": 4, "UDP": 1})
    engine._running_src_counter = Counter({"10.0.0.1": 3, "10.0.0.2": 2})
    engine._running_dst_counter = Counter({"8.8.8.8": 5})
    engine._running_total_packets = 5
    engine._running_total_bytes = 320
    engine._running_first_ts = 1700000000.0
    engine._running_last_ts = 1700000005.0


class TestPreprocessingSignalPayload:
    """修复4：preprocessing_done 信号必须携带 flows/stats/anomalies 完整快照"""

    def test_signal_payload_is_dict_with_three_keys(self, engine: CaptureEngine):
        _seed_engine_state(engine)

        captured: list[dict] = []
        engine.signals.preprocessing_done.connect(captured.append)

        engine._run_preprocessing()

        assert len(captured) == 1, "preprocessing_done 应被 emit 一次"
        payload = captured[0]
        assert isinstance(payload, dict)
        assert set(payload.keys()) >= {"flows", "stats", "anomalies"}

    def test_signal_payload_flows_is_list(self, engine: CaptureEngine):
        _seed_engine_state(engine)

        captured: list[dict] = []
        engine.signals.preprocessing_done.connect(captured.append)
        engine._run_preprocessing()

        assert isinstance(captured[0]["flows"], list)

    def test_signal_payload_stats_is_dict(self, engine: CaptureEngine):
        _seed_engine_state(engine)

        captured: list[dict] = []
        engine.signals.preprocessing_done.connect(captured.append)
        engine._run_preprocessing()

        stats = captured[0]["stats"]
        assert isinstance(stats, dict)
        # 至少包含核心计数字段
        assert "total_packets" in stats

    def test_signal_payload_anomalies_is_list(self, engine: CaptureEngine):
        _seed_engine_state(engine)

        captured: list[dict] = []
        engine.signals.preprocessing_done.connect(captured.append)
        engine._run_preprocessing()

        assert isinstance(captured[0]["anomalies"], list)

    def test_payload_matches_engine_attributes(self, engine: CaptureEngine):
        """信号载荷应与 engine 的 flows/stats/anomalies 属性等值

        注：PySide6 跨线程信号传递时会对载荷做 marshalling，
        因此只能保证值相等（==），不保证对象同一性（is）。
        """
        _seed_engine_state(engine)

        captured: list[dict] = []
        engine.signals.preprocessing_done.connect(captured.append)
        engine._run_preprocessing()

        payload = captured[0]
        assert payload["flows"] == engine.flows
        assert payload["stats"] == engine.stats
        assert payload["anomalies"] == engine.anomalies


class TestEngineInitialState:
    """初始状态约束 — 防止后续重构破坏不变式"""

    def test_initial_not_capturing(self, engine: CaptureEngine):
        assert engine.is_capturing is False

    def test_initial_total_captured_zero(self, engine: CaptureEngine):
        assert engine.total_captured == 0

    def test_initial_flows_empty(self, engine: CaptureEngine):
        assert engine.flows == []

    def test_initial_stats_empty(self, engine: CaptureEngine):
        assert engine.stats == {}

    def test_initial_anomalies_empty(self, engine: CaptureEngine):
        assert engine.anomalies == []

    def test_signals_object_exposed(self, engine: CaptureEngine):
        sigs = engine.signals
        # 关键信号应可订阅
        assert hasattr(sigs, "preprocessing_done")
        assert hasattr(sigs, "capture_started")
        assert hasattr(sigs, "capture_stopped")
        assert hasattr(sigs, "capture_error")
