"""主窗口 — 核心布局与事件编排"""

from __future__ import annotations

import logging

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from app.ai.ai_engine import AIEngine
from app.ai.analysis_worker import AnalysisWorker
from app.ai.prompt_builder import PromptBuilder
from app.ai.result_parser import ResultParser
from app.capture.capture_engine import CaptureEngine
from app.capture.nic_detector import NpcapNotFoundError, list_interfaces
from app.models.analysis_result import AnalysisResult
from app.storage.config_manager import ConfigManager
from app.ui.analysis_panel import AnalysisPanel
from app.ui.capture_controls import CaptureControls
from app.ui.flow_table_model import FlowTableModel
from app.ui.packet_detail_panel import PacketDetailPanel
from app.ui.packet_table_model import PacketTableModel
from app.ui.packet_table_view import PacketTableView
from app.ui.settings_dialog import SettingsDialog

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """应用主窗口"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PacketLens — 抓包 + AI 分析工具")
        self.resize(1200, 700)

        # 数据模型
        self._table_model = PacketTableModel()
        self._flow_model = FlowTableModel()

        # 配置管理
        self._config = ConfigManager()

        # AI 组件（从配置加载）
        ai_cfg = self._config.get_ai_config()
        self._ai_engine = AIEngine(
            api_key=ai_cfg["api_key"],
            base_url=ai_cfg["base_url"],
            model=ai_cfg["model"],
            timeout=ai_cfg["timeout"],
            context_window_tokens=ai_cfg["context_window_tokens"],
            max_tokens=ai_cfg["max_tokens"],
        )
        self._prompt_builder = PromptBuilder(
            context_window_tokens=ai_cfg["context_window_tokens"],
        )
        self._result_parser = ResultParser()
        self._analysis_worker: AnalysisWorker | None = None

        # 抓包引擎
        self._engine = CaptureEngine(self._table_model)
        self._engine.signals.capture_started.connect(self._on_capture_started)
        self._engine.signals.capture_stopped.connect(self._on_capture_stopped)
        self._engine.signals.packet_captured.connect(self._on_packet_captured)
        self._engine.signals.capture_error.connect(self._on_capture_error)
        self._engine.signals.preprocessing_done.connect(self._on_preprocessing_done)

        # 构建界面
        self._setup_ui()
        self._setup_menu()
        self._setup_status_bar()

        # 初始化网卡列表
        self._init_nics()

    def _setup_ui(self) -> None:
        """构建主界面布局"""
        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # 抓包控制栏
        self._controls = CaptureControls()
        self._controls.start_requested.connect(self._start_capture)
        self._controls.stop_requested.connect(self._stop_capture)
        self._controls.set_default_duration(
            self._config.get("default_capture_duration", 60)
        )
        layout.addWidget(self._controls)

        # 主分割器
        splitter = QSplitter(Qt.Vertical)

        # 上方：包列表
        self._table_view = PacketTableView()
        self._table_view.setModel(self._table_model)
        self._table_view.set_model_columns_width()
        self._table_view.packet_selected.connect(self._on_packet_selected)
        self._table_view.packet_double_clicked.connect(self._on_packet_double_clicked)
        splitter.addWidget(self._table_view)

        # 下方：标签页
        self._bottom_tabs = QTabWidget()

        # AI 分析 Tab（默认选中）
        self._analysis_panel = AnalysisPanel()
        self._analysis_panel.deep_analysis_button.clicked.connect(self._start_deep_analysis)
        self._analysis_panel.reanalyze_button.clicked.connect(self._start_quick_analysis)
        self._bottom_tabs.addTab(self._analysis_panel, "AI 分析")

        # 流列表 Tab
        self._flow_view = QTableView()
        self._flow_view.setModel(self._flow_model)
        self._flow_view.setAlternatingRowColors(True)
        self._flow_view.setShowGrid(False)
        self._flow_view.verticalHeader().hide()
        self._flow_view.setSelectionBehavior(QTableView.SelectRows)
        self._bottom_tabs.addTab(self._flow_view, "流聚合")

        # 统计摘要 Tab
        self._stats_label = QLabel("抓包完成后显示统计信息")
        self._stats_label.setWordWrap(True)
        self._stats_label.setStyleSheet("padding: 12px; font-size: 14px;")
        self._bottom_tabs.addTab(self._stats_label, "统计摘要")

        # 包详情 Tab
        self._detail_panel = PacketDetailPanel()
        self._bottom_tabs.addTab(self._detail_panel, "包详情")

        splitter.addWidget(self._bottom_tabs)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

    def _setup_status_bar(self) -> None:
        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)
        self._status_bar.showMessage("就绪 — 选择网卡后点击「开始抓包」")

    def _setup_menu(self) -> None:
        menubar = self.menuBar()
        settings_menu = menubar.addMenu("设置")
        settings_action = settings_menu.addAction("配置")
        settings_action.triggered.connect(self._open_settings)

    def _open_settings(self) -> None:
        dialog = SettingsDialog(self._config, parent=self)
        if dialog.exec() == QDialog.Accepted:
            ai_cfg = self._config.get_ai_config()
            self._ai_engine = AIEngine(
                api_key=ai_cfg["api_key"],
                base_url=ai_cfg["base_url"],
                model=ai_cfg["model"],
                timeout=ai_cfg["timeout"],
                context_window_tokens=ai_cfg["context_window_tokens"],
                max_tokens=ai_cfg["max_tokens"],
            )
            self._status_bar.showMessage("配置已更新")

    def _init_nics(self) -> None:
        try:
            nics = list_interfaces()
            self._controls.populate_nics(nics)
            if nics:
                self._status_bar.showMessage(f"就绪 — 检测到 {len(nics)} 个网卡")
            else:
                self._status_bar.showMessage("未检测到可用网卡")
        except NpcapNotFoundError:
            QMessageBox.critical(
                self, "Npcap 未安装",
                "本工具依赖 Npcap 进行网络抓包。\n\n"
                "请访问 https://npcap.com/#download 下载并安装 Npcap，\n"
                "安装后重新启动本应用。",
            )
            self._status_bar.showMessage("错误: Npcap 未安装")
            self._controls.setEnabled(False)
        except Exception as e:
            logger.error(f"网卡初始化失败: {e}")
            self._status_bar.showMessage(f"网卡初始化失败: {e}")

    # ── 抓包控制 ──

    def _start_capture(self, iface: str, bpf: str, duration: int, promisc: bool) -> None:
        success = self._engine.start_capture(
            iface=iface, bpf_filter=bpf, duration=duration, promisc=promisc,
        )
        if not success:
            self._status_bar.showMessage("抓包启动失败")

    def _stop_capture(self) -> None:
        self._engine.stop_capture()

    # ── AI 分析 ──

    def _start_quick_analysis(self) -> None:
        """启动快速 AI 分析"""
        if not self._engine.flows:
            self._status_bar.showMessage("没有抓包数据，无法分析")
            return

        self._analysis_panel.set_loading()
        self._bottom_tabs.setCurrentIndex(0)  # 切换到 AI 分析 Tab
        self._status_bar.showMessage("AI 快速分析中...")

        ai_cfg = self._config.get_ai_config()
        self._analysis_worker = AnalysisWorker(
            engine=self._ai_engine,
            prompt_builder=self._prompt_builder,
            result_parser=self._result_parser,
            mode="quick",
            flows=self._engine.flows,
            stats=self._engine.stats,
            anomalies=self._engine.anomalies,
            packets=self._table_model.all_packets(),
            temperature=ai_cfg["temperature"],
            max_tokens=ai_cfg["max_tokens"],
        )
        self._analysis_worker.analysis_progress.connect(self._on_analysis_progress)
        self._analysis_worker.analysis_completed.connect(self._on_analysis_completed)
        self._analysis_worker.analysis_error.connect(self._on_analysis_error)
        self._analysis_worker.start()

    def _start_deep_analysis(self) -> None:
        """启动深度 AI 分析"""
        if not self._engine.flows:
            self._status_bar.showMessage("没有抓包数据，无法分析")
            return

        self._analysis_panel.set_loading()
        self._bottom_tabs.setCurrentIndex(0)
        self._status_bar.showMessage("AI 深度分析中...")

        ai_cfg = self._config.get_ai_config()
        self._analysis_worker = AnalysisWorker(
            engine=self._ai_engine,
            prompt_builder=self._prompt_builder,
            result_parser=self._result_parser,
            mode="deep",
            flows=self._engine.flows,
            stats=self._engine.stats,
            anomalies=self._engine.anomalies,
            packets=self._table_model.all_packets(),
            temperature=ai_cfg["temperature"],
            max_tokens=ai_cfg["max_tokens"],
        )
        self._analysis_worker.analysis_progress.connect(self._on_analysis_progress)
        self._analysis_worker.analysis_completed.connect(self._on_analysis_completed)
        self._analysis_worker.analysis_error.connect(self._on_analysis_error)
        self._analysis_worker.start()

    # ── 信号处理 ──

    def _on_capture_started(self) -> None:
        self._controls.set_capturing(True)
        self._flow_model.clear()
        self._stats_label.setText("抓包进行中...")

    def _on_capture_stopped(self, total: int) -> None:
        self._controls.set_capturing(False)
        pcap = self._engine.pcap_path
        msg = f"抓包完成: {total} 个包"
        if pcap:
            msg += f" | PCAP: {pcap}"
        self._status_bar.showMessage(msg)

    def _on_packet_captured(self, count: int) -> None:
        self._controls.update_packet_count(count)

    def _on_capture_error(self, error: str) -> None:
        self._controls.set_capturing(False)
        QMessageBox.critical(self, "抓包错误", error)
        self._status_bar.showMessage(f"错误: {error}")

    def _on_preprocessing_done(self, stats: dict) -> None:
        """预处理完成：更新 UI 并自动触发快速分析"""
        self._flow_model.set_flows(self._engine.flows)

        # 更新统计摘要
        lines = [
            f"<b>抓包统计</b><br>",
            f"总包数: {stats.get('total_packets', 0)} | "
            f"总字节: {stats.get('total_bytes', 0):,} | "
            f"总流数: {stats.get('total_flows', 0)}<br>",
            f"平均包大小: {stats.get('avg_packet_size', 0)} bytes | "
            f"时长: {stats.get('duration', 0)}s | "
            f"带宽: {stats.get('bandwidth_bps', 0):,.0f} bps<br><br>",
            f"<b>协议分布</b><br>",
        ]
        for proto, count in stats.get("protocol_distribution", {}).items():
            lines.append(f"  {proto}: {count}<br>")

        anomalies = self._engine.anomalies
        if anomalies:
            lines.append(f"<br><b>异常检测</b> ({len(anomalies)} 项)<br>")
            for a in anomalies:
                lines.append(f"  [{a['severity']}] {a['description']}<br>")

        self._stats_label.setText("".join(lines))

        # 根据配置决定是否自动触发快速分析
        if self._config.get("auto_analyze", True):
            self._start_quick_analysis()

    def _on_analysis_progress(self, chunk: str) -> None:
        self._analysis_panel.update_progress(chunk)

    def _on_analysis_completed(self, result: AnalysisResult) -> None:
        self._analysis_panel.display_results(result)
        self._status_bar.showMessage(
            f"AI 分析完成: {len(result.issues)} 个发现, "
            f"{result.critical_count} Critical, "
            f"{result.warning_count} Warning, "
            f"耗时 {result.duration_seconds:.1f}s"
        )
        self._analysis_worker = None

    def _on_analysis_error(self, error: str) -> None:
        self._status_bar.showMessage(f"AI 分析失败: {error[:100]}")
        self._analysis_worker = None

    def _on_packet_selected(self, row: int) -> None:
        """选中包时更新详情面板"""
        pkt = self._table_model.get_packet(row)
        self._detail_panel.display_packet(pkt)

    def _on_packet_double_clicked(self, row: int) -> None:
        pkt = self._table_model.get_packet(row)
        if pkt:
            logger.info(f"双击包 #{pkt.index}: {pkt.summary}")

    def closeEvent(self, event) -> None:
        if self._engine.is_capturing:
            self._engine.stop_capture()
        if self._analysis_worker and self._analysis_worker.isRunning():
            self._analysis_worker.requestInterruption()
            self._analysis_worker.wait(5000)
        event.accept()
