"""设置对话框 — AI 模型配置 + 抓包配置（Tab 分页）

AI 模型 Tab 的结构：
1. 左侧：当前使用模型（精简只读卡片，随激活模型动态刷新）
2. 右侧：模型管理（下拉框包含所有模型，内置排第一并标记"内置"）
3. 选中模型展示详情表单（自定义可编辑，内置只读）
4. 连接检测测试当前「选中」模型
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractSpinBox,
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.ai.component_factory import test_connection
from app.config.ai_defaults import AI_DEFAULTS
from app.storage.config_manager import ConfigManager


class SettingsDialog(QDialog):
    """PacketLens 设置对话框"""

    def __init__(self, config: ConfigManager, parent=None):
        super().__init__(parent)
        self._config = config
        self._providers = config.get_providers()
        self._active_name = config.get_active_provider_name()
        self._builtin: dict | None = next(
            (p for p in self._providers if p.get("is_default")), None
        )
        # _selected_index 指向当前在下拉框中选中的 provider 在 self._providers 中的索引
        self._selected_index: int = -1

        self._test_poll_timer = None  # 测试连接轮询定时器

        self.setWindowTitle("PacketLens 设置")
        self.setMinimumWidth(820)
        self.setMinimumHeight(520)
        self._setup_ui()
        self._load_capture_values()
        self._refresh_provider_combo()

    # ── 顶层 UI ──

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._create_ai_tab(), "AI 模型配置")
        self._tabs.addTab(self._create_capture_tab(), "抓包设置")
        layout.addWidget(self._tabs)

        # 底部按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self._cancel_btn = QPushButton("取消")
        self._cancel_btn.setFixedWidth(96)
        self._cancel_btn.clicked.connect(self.reject)

        self._save_btn = QPushButton("保存")
        self._save_btn.setFixedWidth(96)
        self._save_btn.setDefault(True)
        self._save_btn.clicked.connect(self._save_and_accept)

        btn_layout.addWidget(self._cancel_btn)
        btn_layout.addWidget(self._save_btn)
        layout.addLayout(btn_layout)

    # ── AI 模型配置 Tab ──

    def _create_ai_tab(self) -> QWidget:
        """AI 模型配置 Tab — 左右分栏：左侧当前模型，右侧模型管理"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setSpacing(16)

        layout.addWidget(self._create_active_box(), 1)
        layout.addWidget(self._create_provider_box(), 2)
        return widget

    def _create_active_box(self) -> QGroupBox:
        """当前使用模型信息卡片（随激活模型动态刷新）"""
        box = QGroupBox("当前使用模型")
        layout = QVBoxLayout(box)
        layout.setContentsMargins(12, 14, 12, 12)
        layout.setSpacing(10)

        # 固定信息网格 — 避免动态增删 widget 导致 Qt 内存问题
        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(6)

        self._active_name_lbl = QLabel("—")
        self._active_proto_lbl = QLabel("—")
        self._active_model_lbl = QLabel("—")
        self._active_base_lbl = QLabel("—")
        self._active_key_lbl = QLabel("—")

        def _add(row: int, label: str, widget: QLabel) -> None:
            lbl = QLabel(label)
            lbl.setStyleSheet("color: #9399b2;")
            widget.setStyleSheet("color: #cdd6f4;")
            widget.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addWidget(lbl, row, 0)
            grid.addWidget(widget, row, 1)

        _add(0, "名称:", self._active_name_lbl)
        _add(1, "协议:", self._active_proto_lbl)
        _add(2, "模型:", self._active_model_lbl)
        _add(3, "地址:", self._active_base_lbl)
        _add(4, "Key:", self._active_key_lbl)

        layout.addLayout(grid)

        # 限制信息分四列短文本，避免换行
        limits_grid = QGridLayout()
        limits_grid.setHorizontalSpacing(12)
        limits_grid.setVerticalSpacing(4)

        self._active_ctx_lbl = QLabel("—")
        self._active_max_lbl = QLabel("—")
        self._active_temp_lbl = QLabel("—")
        self._active_timeout_lbl = QLabel("—")

        def _lim(row: int, col: int, label: str, widget: QLabel) -> None:
            lbl = QLabel(label)
            lbl.setStyleSheet("color: #9399b2;")
            widget.setStyleSheet("color: #cdd6f4;")
            limits_grid.addWidget(lbl, row, col * 2)
            limits_grid.addWidget(widget, row, col * 2 + 1)

        _lim(0, 0, "窗口:", self._active_ctx_lbl)
        _lim(0, 1, "最大:", self._active_max_lbl)
        _lim(1, 0, "温度:", self._active_temp_lbl)
        _lim(1, 1, "超时:", self._active_timeout_lbl)

        layout.addLayout(limits_grid)
        layout.addStretch()

        self._refresh_active_box()
        return box

    def _refresh_active_box(self) -> None:
        """刷新左侧当前模型信息"""
        active = next(
            (p for p in self._providers if p["name"] == self._active_name), None
        )
        if active is None:
            self._active_name_lbl.setText("—")
            self._active_proto_lbl.setText("—")
            self._active_model_lbl.setText("—")
            self._active_base_lbl.setText("—")
            self._active_key_lbl.setText("—")
            self._active_ctx_lbl.setText("—")
            self._active_max_lbl.setText("—")
            self._active_temp_lbl.setText("—")
            self._active_timeout_lbl.setText("—")
            return

        proto_text = (
            "Anthropic 原生协议"
            if active.get("provider_type") == "anthropic"
            else "OpenAI 兼容协议"
        )
        self._active_name_lbl.setText(active.get("name", "—"))
        self._active_proto_lbl.setText(proto_text)
        self._active_model_lbl.setText(active.get("model", "—"))
        self._active_base_lbl.setText(active.get("api_base") or "官方")
        self._active_key_lbl.setText("•" * 8 if active.get("api_key") else "(未设置)")
        self._active_ctx_lbl.setText(f"{active.get('context_window_tokens', 0):,}")
        self._active_max_lbl.setText(f"{active.get('max_tokens', 0):,}")
        self._active_temp_lbl.setText(f"{active.get('temperature', 0)}")
        self._active_timeout_lbl.setText(f"{active.get('timeout', 0)}s")

    def _create_provider_box(self) -> QGroupBox:
        """模型管理区 — 下拉框包含所有模型（内置+自定义）"""
        box = QGroupBox("模型管理")
        layout = QVBoxLayout(box)
        layout.setContentsMargins(12, 14, 12, 12)
        layout.setSpacing(10)

        # 选择 + 增删行
        selector_row = QHBoxLayout()
        selector_row.addWidget(QLabel("当前编辑:"))
        self._provider_combo = QComboBox()
        self._provider_combo.currentIndexChanged.connect(self._on_provider_switched)
        selector_row.addWidget(self._provider_combo, 1)

        self._add_btn = QPushButton("添加")
        self._add_btn.setFixedWidth(64)
        self._add_btn.clicked.connect(self._add_provider)
        selector_row.addWidget(self._add_btn)

        self._del_btn = QPushButton("删除")
        self._del_btn.setFixedWidth(64)
        self._del_btn.clicked.connect(self._del_provider)
        selector_row.addWidget(self._del_btn)
        layout.addLayout(selector_row)

        # 状态行
        status_row = QHBoxLayout()
        self._use_selected_btn = QPushButton("切换为当前使用")
        self._use_selected_btn.setFixedWidth(130)
        self._use_selected_btn.clicked.connect(self._activate_selected)
        self._selected_active_label = QLabel("")
        status_row.addWidget(self._use_selected_btn)
        status_row.addWidget(self._selected_active_label, 1)
        layout.addLayout(status_row)

        # 空状态提示
        self._empty_hint = QLabel("尚未配置任何模型。")
        self._empty_hint.setStyleSheet(
            "color: #a6adc8; font-style: italic; padding: 16px;"
        )
        self._empty_hint.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._empty_hint)

        # 表单容器
        self._form_widget = QWidget()
        form_outer = QVBoxLayout(self._form_widget)
        form_outer.setContentsMargins(0, 0, 0, 0)
        form_outer.setSpacing(10)

        # ── 双列表单 ──
        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(10)

        def _lbl(text: str) -> QLabel:
            label = QLabel(text)
            label.setStyleSheet("color: #cdd6f4;")
            return label

        self._name_edit = QLineEdit()
        grid.addWidget(_lbl("名称:"), 0, 0)
        grid.addWidget(self._name_edit, 0, 1)

        self._type_combo = QComboBox()
        self._type_combo.addItem("OpenAI 兼容协议", "openai")
        self._type_combo.addItem("Anthropic 原生协议", "anthropic")
        self._type_combo.currentIndexChanged.connect(self._on_type_changed)
        grid.addWidget(_lbl("协议类型:"), 0, 2)
        grid.addWidget(self._type_combo, 0, 3)

        self._api_base_edit = QLineEdit()
        self._api_base_edit.setPlaceholderText("例: https://api.openai.com/v1")
        grid.addWidget(_lbl("API 地址:"), 1, 0)
        grid.addWidget(self._api_base_edit, 1, 1)

        self._model_edit = QLineEdit()
        self._model_edit.setPlaceholderText("例: gpt-4o, MiniMax-M2.7")
        grid.addWidget(_lbl("模型 ID:"), 1, 2)
        grid.addWidget(self._model_edit, 1, 3)

        key_layout = QHBoxLayout()
        key_layout.setSpacing(4)
        self._api_key_edit = QLineEdit()
        self._api_key_edit.setEchoMode(QLineEdit.Password)
        self._api_key_edit.setPlaceholderText("输入 API Key")
        self._toggle_key_btn = QPushButton("显示")
        self._toggle_key_btn.setFixedWidth(56)
        self._toggle_key_btn.clicked.connect(self._toggle_key_visibility)
        key_layout.addWidget(self._api_key_edit)
        key_layout.addWidget(self._toggle_key_btn)
        grid.addWidget(_lbl("API Key:"), 2, 0)
        grid.addLayout(key_layout, 2, 1, 1, 3)

        self._temperature_spin = QDoubleSpinBox()
        self._temperature_spin.setRange(0.0, 1.0)
        self._temperature_spin.setSingleStep(0.1)
        self._temperature_spin.setDecimals(1)
        grid.addWidget(_lbl("温度:"), 3, 0)
        grid.addWidget(self._temperature_spin, 3, 1)

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(10, 600)
        self._timeout_spin.setSuffix(" 秒")
        grid.addWidget(_lbl("超时:"), 3, 2)
        grid.addWidget(self._timeout_spin, 3, 3)

        self._context_window_spin = QSpinBox()
        self._context_window_spin.setRange(4096, 1048576)
        self._context_window_spin.setSingleStep(32768)
        grid.addWidget(_lbl("上下文窗口:"), 4, 0)
        grid.addWidget(self._context_window_spin, 4, 1)

        self._max_tokens_spin = QSpinBox()
        self._max_tokens_spin.setRange(256, 524288)
        self._max_tokens_spin.setSingleStep(4096)
        grid.addWidget(_lbl("最大 Token:"), 4, 2)
        grid.addWidget(self._max_tokens_spin, 4, 3)

        self._concurrency_spin = QSpinBox()
        self._concurrency_spin.setRange(1, 10)
        self._concurrency_spin.setToolTip(
            "深度分析时同时进行的 AI 请求数量，受 API 速率限制约束"
        )
        grid.addWidget(_lbl("并发数:"), 5, 0)
        grid.addWidget(self._concurrency_spin, 5, 1)

        form_outer.addLayout(grid)

        limits_hint = QLabel(
            "根据模型上下文窗口和 API 限速调整 Token 与并发数，避免超限。"
        )
        limits_hint.setStyleSheet("color: #a6adc8; font-size: 11px;")
        limits_hint.setWordWrap(True)
        form_outer.addWidget(limits_hint)

        # 连接检测行
        test_row = QHBoxLayout()
        test_row.setSpacing(10)
        self._test_btn = QPushButton("测试当前选中模型")
        self._test_btn.setFixedWidth(160)
        self._test_btn.clicked.connect(self._test_connection)
        self._test_status = QLabel("")
        self._test_status.setWordWrap(True)
        test_row.addWidget(self._test_btn)
        test_row.addWidget(self._test_status, 1)
        form_outer.addLayout(test_row)

        layout.addWidget(self._form_widget)
        return box

    # ── 抓包设置 Tab ──

    def _create_capture_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(12)

        capture_box = QGroupBox("抓包行为")
        capture_layout = QVBoxLayout(capture_box)
        capture_layout.setContentsMargins(12, 12, 12, 12)
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(10)

        self._duration_spin = QSpinBox()
        self._duration_spin.setRange(10, 300)
        self._duration_spin.setSuffix(" 秒")
        form.addRow("默认抓包时长:", self._duration_spin)

        self._auto_analyze_cb = QCheckBox("抓包完成后自动 AI 分析")
        form.addRow("", self._auto_analyze_cb)

        self._auto_save_cb = QCheckBox("自动保存 PCAP 文件")
        form.addRow("", self._auto_save_cb)

        capture_layout.addLayout(form)

        capture_hint = QLabel(
            "这些选项只影响界面默认行为与自动化偏好，不会改变底层抓包能力。"
        )
        capture_hint.setWordWrap(True)
        capture_hint.setStyleSheet("color: #a6adc8;")
        capture_layout.addWidget(capture_hint)

        layout.addWidget(capture_box)
        layout.addStretch()
        return widget

    # ── Provider 列表辅助 ──

    def _refresh_provider_combo(self) -> None:
        """刷新下拉框，包含所有模型（内置在前，自定义在后）"""
        self._provider_combo.blockSignals(True)
        self._provider_combo.clear()

        for i, p in enumerate(self._providers):
            name = p["name"]
            if p.get("is_default"):
                name = f"{name} (内置)"
            self._provider_combo.addItem(name)

        if self._providers:
            active_idx = next(
                (
                    i
                    for i, p in enumerate(self._providers)
                    if p["name"] == self._active_name
                ),
                0,
            )
            self._selected_index = active_idx
            self._provider_combo.setCurrentIndex(active_idx)
        else:
            self._selected_index = -1

        self._provider_combo.blockSignals(False)

        if self._providers:
            self._show_form(True)
            self._load_provider_to_form()
        else:
            self._show_form(False)

        self._update_active_indicators()
        self._refresh_active_box()

    def _show_form(self, show: bool) -> None:
        self._form_widget.setVisible(show)
        self._empty_hint.setVisible(not show)
        self._del_btn.setEnabled(show)
        self._use_selected_btn.setEnabled(show)

    def _on_provider_switched(self, combo_pos: int) -> None:
        """用户在下拉框中切换 provider"""
        if combo_pos < 0 or combo_pos >= len(self._providers):
            return
        self._save_provider_form()
        self._selected_index = combo_pos
        self._load_provider_to_form()
        self._update_active_indicators()

    def _on_type_changed(self, _index: int) -> None:
        provider_type = self._type_combo.currentData()
        if provider_type == "anthropic":
            self._api_base_edit.setPlaceholderText(
                "可选；填写代理/中转地址（如 http://nas.example:11434），留空走官方"
            )
            self._api_base_edit.setToolTip(
                "Anthropic 协议默认走官方 API，需要中转/自建端点时填此处"
            )
            self._model_edit.setPlaceholderText(
                "例: claude-sonnet-4-20250514, claude-opus-4-20250514"
            )
        else:
            self._api_base_edit.setPlaceholderText("例: https://api.openai.com/v1")
            self._api_base_edit.setToolTip("")
            self._model_edit.setPlaceholderText(
                "例: gpt-4o, deepseek-chat, MiniMax-M2.7"
            )

    def _load_provider_to_form(self) -> None:
        """把当前选中的 provider 加载到表单"""
        if self._selected_index < 0 or self._selected_index >= len(self._providers):
            return
        p = self._providers[self._selected_index]
        is_builtin = p.get("is_default", False)

        self._name_edit.setText(p.get("name", ""))
        self._api_base_edit.setText(p.get("api_base", ""))
        self._api_key_edit.setText(p.get("api_key", ""))
        self._model_edit.setText(p.get("model", ""))
        self._context_window_spin.setValue(
            p.get("context_window_tokens", AI_DEFAULTS["context_window_tokens"])
        )
        self._max_tokens_spin.setValue(p.get("max_tokens", AI_DEFAULTS["max_tokens"]))
        self._temperature_spin.setValue(
            p.get("temperature", AI_DEFAULTS["temperature"])
        )
        self._timeout_spin.setValue(p.get("timeout", AI_DEFAULTS["timeout"]))
        self._concurrency_spin.setValue(
            p.get("max_concurrency", AI_DEFAULTS["max_concurrency"])
        )

        provider_type = p.get("provider_type", "openai")
        idx = self._type_combo.findData(provider_type)
        self._type_combo.setCurrentIndex(idx if idx >= 0 else 0)

        # 内置模型只读
        ro = is_builtin
        sym = QAbstractSpinBox.NoButtons if ro else QAbstractSpinBox.UpDownArrows
        self._name_edit.setReadOnly(ro)
        self._api_base_edit.setReadOnly(ro)
        self._api_key_edit.setReadOnly(ro)
        self._model_edit.setReadOnly(ro)
        self._type_combo.setEnabled(not ro)
        self._context_window_spin.setReadOnly(ro)
        self._context_window_spin.setButtonSymbols(sym)
        self._max_tokens_spin.setReadOnly(ro)
        self._max_tokens_spin.setButtonSymbols(sym)
        self._temperature_spin.setReadOnly(ro)
        self._temperature_spin.setButtonSymbols(sym)
        self._timeout_spin.setReadOnly(ro)
        self._timeout_spin.setButtonSymbols(sym)
        self._concurrency_spin.setReadOnly(ro)
        self._concurrency_spin.setButtonSymbols(sym)

    def _save_provider_form(self) -> None:
        """把表单写回当前选中的 provider；对改名同步 _active_name"""
        if self._selected_index < 0 or self._selected_index >= len(self._providers):
            return
        p = self._providers[self._selected_index]

        if p.get("is_default"):
            return  # 内置模型不可编辑

        old_name = p["name"]
        new_name = self._name_edit.text().strip() or old_name
        if new_name != old_name:
            if self._active_name == old_name:
                self._active_name = new_name
            p["name"] = new_name
            current_pos = self._provider_combo.currentIndex()
            if current_pos >= 0:
                self._provider_combo.blockSignals(True)
                display = f"{new_name} (内置)" if p.get("is_default") else new_name
                self._provider_combo.setItemText(current_pos, display)
                self._provider_combo.blockSignals(False)
        p["api_base"] = self._api_base_edit.text().strip()
        p["api_key"] = self._api_key_edit.text().strip()
        p["model"] = self._model_edit.text().strip()
        p["context_window_tokens"] = self._context_window_spin.value()
        p["max_tokens"] = self._max_tokens_spin.value()
        p["temperature"] = self._temperature_spin.value()
        p["timeout"] = self._timeout_spin.value()
        p["max_concurrency"] = self._concurrency_spin.value()
        p["provider_type"] = self._type_combo.currentData()

    def _load_capture_values(self) -> None:
        self._duration_spin.setValue(self._config.get("default_capture_duration", 60))
        self._auto_analyze_cb.setChecked(self._config.get("auto_analyze", True))
        self._auto_save_cb.setChecked(self._config.get("auto_save_pcap", True))

    # ── 激活切换 ──

    def _activate_selected(self) -> None:
        """将当前选中的 provider 设为激活"""
        if self._selected_index < 0 or self._selected_index >= len(self._providers):
            return
        self._save_provider_form()
        self._active_name = self._providers[self._selected_index]["name"]
        self._update_active_indicators()
        self._refresh_active_box()

    def _update_active_indicators(self) -> None:
        """更新激活状态指示"""
        selected_loaded = 0 <= self._selected_index < len(self._providers)
        selected_active = (
            selected_loaded
            and self._providers[self._selected_index]["name"] == self._active_name
        )
        if selected_active:
            self._selected_active_label.setText("✓ 当前使用中")
            self._selected_active_label.setStyleSheet(
                "color: #a6e3a1; font-weight: bold;"
            )
            self._use_selected_btn.setEnabled(False)
        else:
            self._selected_active_label.setText("")
            self._use_selected_btn.setEnabled(selected_loaded)

        if hasattr(self, "_test_btn") and self._test_btn is not None:
            if selected_loaded:
                name = self._providers[self._selected_index]["name"]
                self._test_btn.setText(f"测试: {name}")
            else:
                self._test_btn.setText("测试")

    # ── 添加/删除 provider ──

    def _add_provider(self) -> None:
        name, ok = QInputDialog.getText(self, "添加模型", "请输入模型名称:")
        if not ok or not name.strip():
            return
        name = name.strip()
        if any(p["name"] == name for p in self._providers):
            QMessageBox.warning(self, "重名", f'已存在名为 "{name}" 的模型')
            return

        self._save_provider_form()
        new_provider = {
            "name": name,
            "provider_type": "openai",
            "api_base": "",
            "api_key": "",
            "model": "",
            "context_window_tokens": AI_DEFAULTS["context_window_tokens"],
            "max_tokens": AI_DEFAULTS["max_tokens"],
            "temperature": AI_DEFAULTS["temperature"],
            "timeout": AI_DEFAULTS["timeout"],
            "max_concurrency": AI_DEFAULTS["max_concurrency"],
            "is_default": False,
        }
        self._providers.append(new_provider)
        self._refresh_provider_combo()
        self._provider_combo.setCurrentIndex(len(self._providers) - 1)

    def _del_provider(self) -> None:
        if self._selected_index < 0 or self._selected_index >= len(self._providers):
            return
        p = self._providers[self._selected_index]
        if p.get("is_default"):
            QMessageBox.warning(
                self, "不可删除", "内置模型不能删除，请编辑 .env 文件。"
            )
            return
        name = p["name"]
        reply = QMessageBox.question(
            self,
            "确认删除",
            f'确定要删除模型 "{name}" 吗？',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        self._providers.pop(self._selected_index)

        if self._active_name == name:
            self._active_name = self._providers[0]["name"] if self._providers else ""

        self._refresh_provider_combo()

    # ── 保存 / 测试 / 工具 ──

    def _save_and_accept(self) -> None:
        self._save_provider_form()

        active = next(
            (p for p in self._providers if p["name"] == self._active_name), None
        )
        if active is None:
            QMessageBox.warning(
                self,
                "未选择模型",
                "请在 AI 模型配置中选择一个 AI 模型作为当前使用模型。",
            )
            return

        if not active.get("is_default", False):
            missing = []
            if not active.get("model", "").strip():
                missing.append("模型 ID")
            if (
                not active.get("api_base", "").strip()
                and active.get("provider_type", "openai") == "openai"
            ):
                missing.append("API 地址")
            if missing:
                QMessageBox.warning(
                    self,
                    "配置不完整",
                    f'激活的模型「{active["name"]}」缺少必填字段:\n\n'
                    + "\n".join(f"• {f}" for f in missing),
                )
                return

        self._config.set_providers(self._providers, self._active_name)
        self._config.set("default_capture_duration", self._duration_spin.value())
        self._config.set("auto_analyze", self._auto_analyze_cb.isChecked())
        self._config.set("auto_save_pcap", self._auto_save_cb.isChecked())
        self._config.save()
        self._cleanup_test_timer()
        self.accept()

    def _toggle_key_visibility(self) -> None:
        if self._api_key_edit.echoMode() == QLineEdit.Password:
            self._api_key_edit.setEchoMode(QLineEdit.Normal)
            self._toggle_key_btn.setText("隐藏")
        else:
            self._api_key_edit.setEchoMode(QLineEdit.Password)
            self._toggle_key_btn.setText("显示")

    def _cleanup_test_timer(self) -> None:
        if self._test_poll_timer is not None:
            self._test_poll_timer.stop()
            self._test_poll_timer = None

    def reject(self) -> None:
        self._cleanup_test_timer()
        super().reject()

    def _test_connection(self) -> None:
        """测试当前选中模型的连通性（异步线程 + QTimer 轮询，不阻塞 UI）"""
        self._save_provider_form()

        if self._selected_index < 0 or self._selected_index >= len(self._providers):
            self._test_status.setText("未选择模型")
            self._test_status.setStyleSheet("color: #FF4444;")
            return

        p = self._providers[self._selected_index]
        self._cleanup_test_timer()
        self._test_btn.setEnabled(False)
        self._test_status.setText(f"测试中... [{p['name']}]")
        self._test_status.setStyleSheet("color: #FFB020;")

        ai_config = {
            "provider_type": p.get("provider_type", "openai"),
            "api_key": p.get("api_key", ""),
            "base_url": p.get("api_base", ""),
            "model": p.get("model", ""),
            "timeout": p.get("timeout", AI_DEFAULTS["timeout"]),
            "context_window_tokens": p.get(
                "context_window_tokens", AI_DEFAULTS["context_window_tokens"]
            ),
            "max_tokens": p.get("max_tokens", AI_DEFAULTS["max_tokens"]),
        }

        import threading

        result = {"ok": False, "msg": ""}

        def run_test():
            try:
                result["ok"], result["msg"] = test_connection(ai_config)
            except Exception as e:
                result["ok"] = False
                result["msg"] = f"错误: {str(e)[:120]}"

        thread = threading.Thread(target=run_test, daemon=True)
        thread.start()

        from PySide6.QtCore import QTimer

        self._test_poll_timer = QTimer()
        self._test_poll_timer.setInterval(100)

        def check_done():
            if self._test_poll_timer is None:
                return
            if thread.is_alive():
                return
            self._test_poll_timer.stop()
            self._test_poll_timer = None
            if result["ok"]:
                self._test_status.setText(result["msg"])
                self._test_status.setStyleSheet("color: #44BB44;")
            else:
                self._test_status.setText(result["msg"])
                self._test_status.setStyleSheet("color: #FF4444;")
            self._test_btn.setEnabled(True)

        self._test_poll_timer.timeout.connect(check_done)
        self._test_poll_timer.start()
