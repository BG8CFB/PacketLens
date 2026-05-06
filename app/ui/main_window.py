"""主窗口 — 核心布局与事件编排"""

from __future__ import annotations

import logging

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableView,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from app.application import SCROLLBAR_STYLE
from app.ai.ai_engine import AIEngine
from app.ai.analysis_worker import AnalysisWorker
from app.ai.component_factory import create_ai_engine, create_prompt_builder, create_result_parser
from app.ai.prompt_builder import PromptBuilder
from app.ai.result_parser import ResultParser
from app.capture.capture_engine import CaptureEngine
from app.constants import DEFAULT_CAPTURE_DURATION
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
        self._ai_engine = create_ai_engine(ai_cfg)
        self._prompt_builder = create_prompt_builder(ai_cfg)
        self._result_parser = create_result_parser()
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
        # 主窗口留出更舒适的呼吸感，避免内容贴边
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # 抓包控制栏
        self._controls = CaptureControls()
        # 工具栏高度锁定为 sizeHint，避免最大化时被 QVBoxLayout 拉高产生空白
        # （默认 Preferred/Preferred 在大窗口下会与下方 splitter 平分多余空间）
        self._controls.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        self._controls.start_requested.connect(self._start_capture)
        self._controls.stop_requested.connect(self._stop_capture)
        self._controls.set_default_duration(
            self._config.get("default_capture_duration", DEFAULT_CAPTURE_DURATION)
        )
        layout.addWidget(self._controls)

        # 整体水平分割器
        main_splitter = QSplitter(Qt.Horizontal)
        main_splitter.setChildrenCollapsible(False)
        main_splitter.setHandleWidth(6)

        # 左侧：包列表与底部 Tabs 的垂直分割器
        left_splitter = QSplitter(Qt.Vertical)
        left_splitter.setChildrenCollapsible(False)
        left_splitter.setHandleWidth(6)

        # 上方：包列表
        self._table_view = PacketTableView()
        self._table_view.setModel(self._table_model)
        self._table_view.set_model_columns_width()
        self._table_view.packet_selected.connect(self._on_packet_selected)
        self._table_view.packet_double_clicked.connect(self._on_packet_double_clicked)
        left_splitter.addWidget(self._table_view)

        # 下方：标签页 (流聚合, 统计摘要, 包详情)
        self._bottom_tabs = QTabWidget()
        self._bottom_tabs.setDocumentMode(True)
        self._bottom_tabs.setMinimumHeight(200)

        # 流列表 Tab
        self._flow_view = QTableView()
        self._flow_view.setModel(self._flow_model)
        self._flow_view.setAlternatingRowColors(True)
        self._flow_view.setShowGrid(False)
        self._flow_view.verticalHeader().hide()
        self._flow_view.setSelectionBehavior(QTableView.SelectRows)
        self._flow_view.setSelectionMode(QTableView.SingleSelection)
        self._flow_view.setSortingEnabled(True)
        self._flow_view.horizontalHeader().setStretchLastSection(True)
        self._flow_view.horizontalHeader().setMinimumSectionSize(60)
        self._flow_view.setStyleSheet(SCROLLBAR_STYLE)
        self._bottom_tabs.addTab(self._flow_view, "流聚合")

        # 统计摘要 Tab
        self._stats_label = QTextBrowser()
        self._stats_label.setOpenExternalLinks(True)
        self._stats_label.setHtml("抓包完成后显示统计信息")
        self._stats_label.setStyleSheet("padding: 10px; font-size: 13px;" + SCROLLBAR_STYLE)
        self._bottom_tabs.addTab(self._stats_label, "统计摘要")

        # 包详情 Tab
        self._detail_panel = PacketDetailPanel()
        self._bottom_tabs.addTab(self._detail_panel, "包详情")

        left_splitter.addWidget(self._bottom_tabs)
        left_splitter.setStretchFactor(0, 2)
        left_splitter.setStretchFactor(1, 1)

        # 右侧：AI 分析面板 (独立显示)
        self._analysis_panel = AnalysisPanel()
        self._analysis_panel.deep_analysis_button.clicked.connect(self._start_deep_analysis)
        self._analysis_panel.reanalyze_button.clicked.connect(self._start_quick_analysis)

        main_splitter.addWidget(left_splitter)
        main_splitter.addWidget(self._analysis_panel)
        main_splitter.setStretchFactor(0, 2)
        main_splitter.setStretchFactor(1, 1)
        main_splitter.setSizes([800, 400])

        # stretch=1 让分割器吸收所有剩余垂直空间，避免最大化时出现工具栏与表格之间的空白
        layout.addWidget(main_splitter, 1)

    def _setup_status_bar(self) -> None:
        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)
        self._status_bar.showMessage("就绪 — 选择网卡后点击「开始抓包」")

    def _setup_menu(self) -> None:
        menubar = self.menuBar()
        settings_menu = menubar.addMenu("设置")
        settings_action = settings_menu.addAction("配置")
        settings_action.triggered.connect(self._open_settings)

        help_menu = menubar.addMenu("帮助")
        about_action = help_menu.addAction("关于 PacketLens")
        about_action.triggered.connect(self._show_about)

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "关于 PacketLens",
            "<h3>PacketLens</h3>"
            "<p>Windows 桌面抓包 + AI 流量分析工具</p>"
            "<p>基于 Python 3.11 / PySide6 / Scapy / LangChain</p>"
            f"<p>版本: {__import__('app.constants', fromlist=['APP_VERSION']).APP_VERSION}</p>",
        )

    def _open_settings(self) -> None:
        dialog = SettingsDialog(self._config, parent=self)
        if dialog.exec() == QDialog.Accepted:
            self._cancel_active_worker()
            ai_cfg = self._config.get_ai_config()
            self._ai_engine = create_ai_engine(ai_cfg)
            self._prompt_builder = create_prompt_builder(ai_cfg)
            self._controls.set_default_duration(
                self._config.get("default_capture_duration", DEFAULT_CAPTURE_DURATION)
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

    def _cancel_active_worker(self) -> None:
        """取消正在运行的 AI 分析 Worker"""
        if self._analysis_worker is not None and self._analysis_worker.isRunning():
            self._analysis_worker.requestInterruption()
            try:
                self._analysis_worker.analysis_completed.disconnect(self._on_analysis_completed)
            except RuntimeError:
                pass
            try:
                self._analysis_worker.analysis_error.disconnect(self._on_analysis_error)
            except RuntimeError:
                pass
            try:
                self._analysis_worker.analysis_progress.disconnect(self._on_analysis_progress)
            except RuntimeError:
                pass
            try:
                self._analysis_worker.analysis_stage.disconnect(self._on_analysis_stage)
            except RuntimeError:
                pass
            finished = self._analysis_worker.wait(3000)
            if finished:
                self._analysis_worker = None
            else:
                # 超时后仍清除引用，断开的信号防止旧 Worker 回呼
                logger.warning("AI Worker 未在 3 秒内停止，清除引用")
                self._analysis_worker = None

    def _start_quick_analysis(self) -> None:
        """启动快速 AI 分析"""
        if not self._engine.flows:
            self._status_bar.showMessage("没有抓包数据，无法分析")
            return

        self._cancel_active_worker()
        self._analysis_panel.set_loading()
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
            max_concurrency=ai_cfg["max_concurrency"],
            max_layer2_flows=ai_cfg["max_layer2_flows"],
        )
        self._analysis_worker.analysis_progress.connect(self._on_analysis_progress)
        self._analysis_worker.analysis_completed.connect(self._on_analysis_completed)
        self._analysis_worker.analysis_error.connect(self._on_analysis_error)
        self._analysis_worker.analysis_stage.connect(self._on_analysis_stage)
        self._analysis_worker.start()

    def _start_deep_analysis(self) -> None:
        """启动深度 AI 分析（Layer 1 → 2 → 3）"""
        if not self._engine.flows:
            self._status_bar.showMessage("没有抓包数据，无法分析")
            return

        self._cancel_active_worker()
        self._analysis_panel.set_loading()
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
            max_concurrency=ai_cfg["max_concurrency"],
            max_layer2_flows=ai_cfg["max_layer2_flows"],
        )
        self._analysis_worker.analysis_progress.connect(self._on_analysis_progress)
        self._analysis_worker.analysis_completed.connect(self._on_analysis_completed)
        self._analysis_worker.analysis_error.connect(self._on_analysis_error)
        self._analysis_worker.analysis_stage.connect(self._on_analysis_stage)
        self._analysis_worker.start()

    # ── 信号处理 ──

    def _on_capture_started(self) -> None:
        self._controls.set_capturing(True)
        self._flow_model.clear()
        self._stats_label.setHtml("抓包进行中...")

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

    def _on_preprocessing_done(self, payload: dict) -> None:
        """预处理完成：更新 UI 并自动触发快速分析

        payload 由 CaptureEngine 提供，结构：
            {"flows": [...], "stats": {...}, "anomalies": [...]}
        优先使用 payload 而非读取 self._engine.* 共享状态，避免跨线程可见性疑虑。
        旧版本只传 stats 的兼容路径已废弃（CaptureEngine 与 MainWindow 同仓库迭代）。
        """
        flows = payload.get("flows", [])
        stats = payload.get("stats", {})
        anomalies = payload.get("anomalies", [])

        self._flow_model.set_flows(flows)

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

        if anomalies:
            lines.append(f"<br><b>异常检测</b> ({len(anomalies)} 项)<br>")
            for a in anomalies:
                lines.append(f"  [{a['severity']}] {a['description']}<br>")

        self._stats_label.setHtml("".join(lines))

        # 根据配置决定是否自动触发快速分析
        if self._config.get("auto_analyze", True):
            self._start_quick_analysis()

    def _on_analysis_progress(self, chunk: str) -> None:
        self._analysis_panel.update_progress(chunk)

    def _on_analysis_stage(self, stage: str) -> None:
        self._analysis_panel.update_stage(stage)

    def _on_analysis_completed(self, result: AnalysisResult) -> None:
        # 防止已取消/替换的 worker 回调
        if self._analysis_worker is not None and self.sender() != self._analysis_worker:
            return
        self._analysis_panel.display_results(result)
        self._status_bar.showMessage(
            f"AI 分析完成: {len(result.issues)} 个发现, "
            f"{result.critical_count} Critical, "
            f"{result.warning_count} Warning, "
            f"耗时 {result.duration_seconds:.1f}s"
        )
        self._analysis_worker = None

    def _on_analysis_error(self, error: str) -> None:
        if self._analysis_worker is not None and self.sender() != self._analysis_worker:
            return
        self._analysis_panel.reset_from_error(error)
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
        """窗口关闭时清理所有资源"""
        if self._engine.is_capturing:
            self._engine.stop_capture()
        self._engine.cleanup()
        self._cancel_active_worker()
        event.accept()
