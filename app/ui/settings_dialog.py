"""设置对话框 — AI 模型配置 + 抓包配置（Tab 分页）"""

from __future__ import annotations

import copy

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFormLayout,
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
        self._current_index = 0

        self._test_poll_timer = None  # 测试连接轮询定时器
        self.setWindowTitle("PacketLens 设置")
        self.setMinimumWidth(600)
        self.setMinimumHeight(520)
        self._setup_ui()
        self._load_capture_values()
        self._load_provider_to_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Tab 页
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
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(10)

        # Provider 选择行
        selector_layout = QHBoxLayout()
        selector_layout.addWidget(QLabel("当前模型:"))
        self._provider_combo = QComboBox()
        self._provider_combo.currentIndexChanged.connect(self._on_provider_switched)
        selector_layout.addWidget(self._provider_combo, 1)

        self._add_btn = QPushButton("添加")
        self._add_btn.setFixedWidth(72)
        self._add_btn.clicked.connect(self._add_provider)
        selector_layout.addWidget(self._add_btn)

        self._del_btn = QPushButton("删除")
        self._del_btn.setFixedWidth(72)
        self._del_btn.clicked.connect(self._del_provider)
        selector_layout.addWidget(self._del_btn)

        layout.addLayout(selector_layout)

        # Provider 字段表单
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)

        self._name_edit = QLineEdit()
        form.addRow("名称:", self._name_edit)

        self._api_base_edit = QLineEdit()
        self._api_base_edit.setPlaceholderText("例: https://api.openai.com/v1")
        form.addRow("API 地址:", self._api_base_edit)

        key_layout = QHBoxLayout()
        self._api_key_edit = QLineEdit()
        self._api_key_edit.setEchoMode(QLineEdit.Password)
        self._api_key_edit.setPlaceholderText("输入 API Key")
        self._toggle_key_btn = QPushButton("显示")
        self._toggle_key_btn.setFixedWidth(56)
        self._toggle_key_btn.clicked.connect(self._toggle_key_visibility)
        key_layout.addWidget(self._api_key_edit)
        key_layout.addWidget(self._toggle_key_btn)
        form.addRow("API Key:", key_layout)

        self._model_edit = QLineEdit()
        self._model_edit.setPlaceholderText("例: gpt-4o, deepseek-chat, MiniMax-M2.7")
        form.addRow("模型 ID:", self._model_edit)

        self._type_combo = QComboBox()
        self._type_combo.addItem("OpenAI 兼容协议", "openai")
        self._type_combo.addItem("Anthropic 原生协议", "anthropic")
        self._type_combo.currentIndexChanged.connect(self._on_type_changed)
        form.addRow("协议类型:", self._type_combo)

        self._context_window_spin = QSpinBox()
        self._context_window_spin.setRange(4096, 1048576)
        self._context_window_spin.setSingleStep(32768)
        self._context_window_spin.setSuffix("")
        form.addRow("上下文窗口:", self._context_window_spin)

        self._max_tokens_spin = QSpinBox()
        self._max_tokens_spin.setRange(256, 524288)
        self._max_tokens_spin.setSingleStep(4096)
        self._max_tokens_spin.setSuffix("")
        form.addRow("最大 Token:", self._max_tokens_spin)

        self._temperature_spin = QDoubleSpinBox()
        self._temperature_spin.setRange(0.0, 1.0)
        self._temperature_spin.setSingleStep(0.1)
        self._temperature_spin.setDecimals(1)
        form.addRow("温 度:", self._temperature_spin)

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(10, 600)
        self._timeout_spin.setSuffix(" 秒")
        form.addRow("超 时:", self._timeout_spin)

        self._concurrency_spin = QSpinBox()
        self._concurrency_spin.setRange(1, 10)
        self._concurrency_spin.setToolTip("深度分析时同时进行的 AI 请求数量，受 API 速率限制约束")
        form.addRow("并发数:", self._concurrency_spin)

        layout.addLayout(form)

        # 默认 provider 提示
        self._readonly_hint = QLabel("")
        self._readonly_hint.setStyleSheet("color: #888; font-style: italic; padding: 4px 0;")
        layout.addWidget(self._readonly_hint)

        # 测试连接
        test_layout = QHBoxLayout()
        self._test_btn = QPushButton("测试连接")
        self._test_btn.setFixedWidth(96)
        self._test_btn.clicked.connect(self._test_connection)
        self._test_status = QLabel("")
        test_layout.addWidget(self._test_btn)
        test_layout.addWidget(self._test_status, 1)
        layout.addLayout(test_layout)

        # 填充下拉框
        self._refresh_combo()

        return widget

    # ── 抓包设置 Tab ──

    def _create_capture_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(10)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)

        self._duration_spin = QSpinBox()
        self._duration_spin.setRange(10, 300)
        self._duration_spin.setSuffix(" 秒")
        form.addRow("默认抓包时长:", self._duration_spin)

        self._auto_analyze_cb = QCheckBox("抓包完成后自动 AI 分析")
        form.addRow("", self._auto_analyze_cb)

        self._auto_save_cb = QCheckBox("自动保存 PCAP 文件")
        form.addRow("", self._auto_save_cb)

        layout.addLayout(form)
        layout.addStretch()
        return widget

    # ── Provider 切换 ──

    def _refresh_combo(self) -> None:
        """刷新下拉框"""
        self._provider_combo.blockSignals(True)
        self._provider_combo.clear()
        for p in self._providers:
            suffix = " (默认)" if p.get("is_default") else ""
            self._provider_combo.addItem(p["name"] + suffix, p["name"])

        for i, p in enumerate(self._providers):
            if p["name"] == self._active_name:
                self._provider_combo.setCurrentIndex(i)
                self._current_index = i
                break
        self._provider_combo.blockSignals(False)
        self._update_del_button_state()

    def _on_provider_switched(self, index: int) -> None:
        """切换 provider 前保存当前编辑"""
        self._save_current_provider()
        self._current_index = index
        self._active_name = self._providers[index]["name"]
        self._load_provider_to_ui()

    def _on_type_changed(self, index: int) -> None:
        """切换协议类型时更新 UI 提示"""
        provider_type = self._type_combo.currentData()
        if provider_type == "anthropic":
            self._api_base_edit.setPlaceholderText("Anthropic 无需填写（固定官方 API）")
            self._api_base_edit.setToolTip("Anthropic 类型不使用自定义 API 地址")
            self._model_edit.setPlaceholderText("例: claude-sonnet-4-20250514, claude-opus-4-20250514")
        else:
            self._api_base_edit.setPlaceholderText("例: https://api.openai.com/v1")
            self._api_base_edit.setToolTip("")
            self._model_edit.setPlaceholderText("例: gpt-4o, deepseek-chat, MiniMax-M2.7")

    def _load_provider_to_ui(self) -> None:
        """从当前选中 provider 加载到 UI"""
        if not self._providers:
            return
        p = self._providers[self._current_index]
        self._name_edit.setText(p.get("name", ""))
        self._api_base_edit.setText(p.get("api_base", ""))
        self._api_key_edit.setText(p.get("api_key", ""))
        self._model_edit.setText(p.get("model", ""))
        self._context_window_spin.setValue(
            p.get("context_window_tokens", AI_DEFAULTS["context_window_tokens"])
        )
        self._max_tokens_spin.setValue(
            p.get("max_tokens", AI_DEFAULTS["max_tokens"])
        )
        self._temperature_spin.setValue(
            p.get("temperature", AI_DEFAULTS["temperature"])
        )
        self._timeout_spin.setValue(
            p.get("timeout", AI_DEFAULTS["timeout"])
        )
        self._concurrency_spin.setValue(
            p.get("max_concurrency", AI_DEFAULTS["max_concurrency"])
        )

        # 协议类型
        provider_type = p.get("provider_type", "openai")
        idx = self._type_combo.findData(provider_type)
        self._type_combo.setCurrentIndex(idx if idx >= 0 else 0)

        # 内置默认 provider 不可编辑，只能选择
        is_default = p.get("is_default", False)
        self._set_form_editable(not is_default)
        self._update_del_button_state()

    def _save_current_provider(self) -> None:
        """将 UI 当前值保存回 providers 列表"""
        if not self._providers or self._current_index >= len(self._providers):
            return
        p = self._providers[self._current_index]
        p["name"] = self._name_edit.text().strip() or p["name"]
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

    def _set_form_editable(self, editable: bool) -> None:
        """控制表单字段是否可编辑（默认 provider 只读）"""
        self._name_edit.setEnabled(editable)
        self._api_base_edit.setEnabled(editable)
        self._api_key_edit.setEnabled(editable)
        self._model_edit.setEnabled(editable)
        self._context_window_spin.setEnabled(editable)
        self._max_tokens_spin.setEnabled(editable)
        self._temperature_spin.setEnabled(editable)
        self._timeout_spin.setEnabled(editable)
        self._concurrency_spin.setEnabled(editable)
        self._type_combo.setEnabled(editable)
        self._toggle_key_btn.setEnabled(editable)

        if not editable:
            self._readonly_hint.setText("内置模型（.env 配置），仅可选择使用，不支持修改")
        else:
            self._readonly_hint.setText("")

    def _update_del_button_state(self) -> None:
        """内置默认 provider 不可删除"""
        if not self._providers:
            self._del_btn.setEnabled(False)
            return
        is_default = self._providers[self._current_index].get("is_default", False)
        self._del_btn.setEnabled(not is_default)

    # ── 添加/删除 Provider ──

    def _add_provider(self) -> None:
        name, ok = QInputDialog.getText(self, "添加模型", "请输入模型名称:")
        if not ok or not name.strip():
            return
        name = name.strip()
        if any(p["name"] == name for p in self._providers):
            QMessageBox.warning(self, "重名", f"已存在名为 \"{name}\" 的模型")
            return

        self._save_current_provider()
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
        self._active_name = name
        self._current_index = len(self._providers) - 1
        self._refresh_combo()
        self._load_provider_to_ui()

    def _del_provider(self) -> None:
        if not self._providers:
            return
        p = self._providers[self._current_index]
        if p.get("is_default"):
            return
        name = p["name"]
        reply = QMessageBox.question(
            self, "确认删除", f"确定要删除模型 \"{name}\" 吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        self._providers.pop(self._current_index)
        self._current_index = max(0, self._current_index - 1)
        self._active_name = self._providers[self._current_index]["name"]
        self._refresh_combo()
        self._load_provider_to_ui()

    # ── 保存/测试 ──

    def _save_and_accept(self) -> None:
        self._save_current_provider()
        self._config.set_providers(self._providers, self._active_name)
        self._config.set("default_capture_duration", self._duration_spin.value())
        self._config.set("auto_analyze", self._auto_analyze_cb.isChecked())
        self._config.set("auto_save_pcap", self._auto_save_cb.isChecked())
        self._config.save()
        self.accept()

    def _toggle_key_visibility(self) -> None:
        if self._api_key_edit.echoMode() == QLineEdit.Password:
            self._api_key_edit.setEchoMode(QLineEdit.Normal)
            self._toggle_key_btn.setText("隐藏")
        else:
            self._api_key_edit.setEchoMode(QLineEdit.Password)
            self._toggle_key_btn.setText("显示")

    def reject(self) -> None:
        """关闭对话框前清理测试连接资源"""
        if self._test_poll_timer is not None:
            self._test_poll_timer.stop()
            self._test_poll_timer = None
        super().reject()

    def _test_connection(self) -> None:
        """后台线程测试 API 连接，避免阻塞 UI"""
        self._test_btn.setEnabled(False)
        self._test_status.setText("测试中...")
        self._test_status.setStyleSheet("color: #FFB020;")

        api_key = self._api_key_edit.text().strip() or None
        base_url = self._api_base_edit.text().strip() or None
        model = self._model_edit.text().strip() or None
        provider_type = self._type_combo.currentData() or "openai"
        timeout = self._timeout_spin.value()
        ctx = self._context_window_spin.value()
        mt = self._max_tokens_spin.value()

        import threading

        result = {"ok": False, "msg": ""}

        def run_test():
            try:
                ai_config = {
                    "provider_type": provider_type,
                    "api_key": api_key or "",
                    "base_url": base_url or "",
                    "model": model or "",
                    "timeout": timeout,
                    "context_window_tokens": ctx,
                    "max_tokens": mt,
                }
                result["ok"], result["msg"] = test_connection(ai_config)
            except Exception as e:
                result["ok"] = False
                result["msg"] = f"错误: {str(e)[:100]}"

        thread = threading.Thread(target=run_test, daemon=True)
        thread.start()

        # QTimer 轮询等待线程完成
        from PySide6.QtCore import QTimer
        self._test_poll_timer = QTimer()
        self._test_poll_timer.setInterval(100)

        def check_done():
            if self._test_poll_timer is None:
                return  # 对话框已关闭
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
