"""SettingsDialog smoke 测试 — 真实 ConfigManager + Qt 控件，无 mock

新版 SettingsDialog 把 AI 模型配置拆成两块：
- 左侧：当前使用模型（精简只读卡片，随激活模型动态刷新）
- 右侧：模型管理（下拉框包含所有模型，内置排第一并标记"内置"）
  选中模型展示详情表单（自定义可编辑，内置只读）

覆盖范围:
- 对话框构造与 UI 状态加载
- 左侧当前模型卡片渲染
- 激活切换按钮与「✓ 当前使用中」指示
- 添加 / 删除 provider 流程（QMessageBox 通过 monkeypatch 桥接）
- 内置模型只读、不可删除
- 保存路径回写 ConfigManager
- 必填字段校验阻断保存（仅校验当前激活模型）
- API Key 显示/隐藏
- 测试连接定时器在关闭/保存时清理
"""

from __future__ import annotations

from pathlib import Path

import pytest
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QInputDialog,
    QLineEdit,
    QMessageBox,
)

from app.config import provider_loader
from app.config.ai_defaults import AI_DEFAULTS
from app.storage.config_manager import ConfigManager
from app.ui.settings_dialog import SettingsDialog


@pytest.fixture(autouse=True)
def _reset_builtin_cache(monkeypatch):
    """清空 .env 中的 AI_* 环境变量，避免内置 provider 被注入到 ConfigManager。

    与 tests/test_storage/test_config_manager.py 同模式：测试期间禁用 .env 自动加载。
    """
    for var in (
        "AI_NAME", "AI_API_KEY", "AI_MODEL", "AI_API_BASE",
        "AI_PROVIDER_TYPE", "AI_CONTEXT_WINDOW", "AI_MAX_TOKENS",
        "AI_TEMPERATURE", "AI_MAX_INPUT_CHARS", "AI_TIMEOUT",
        "AI_MAX_CONCURRENCY", "AI_MAX_LAYER2_FLOWS",
    ):
        monkeypatch.delenv(var, raising=False)
    provider_loader._builtin_provider_cache = provider_loader._NOT_LOADED
    provider_loader._dotenv_loaded = True
    yield
    provider_loader._builtin_provider_cache = provider_loader._NOT_LOADED


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _make_provider(name: str, *, is_default: bool = False, **overrides) -> dict:
    p = {
        "name": name,
        "provider_type": "openai",
        "api_base": f"https://{name.lower()}.test/v1",
        "api_key": f"sk-{name.lower()}",
        "model": f"{name.lower()}-model",
        "context_window_tokens": AI_DEFAULTS["context_window_tokens"],
        "max_tokens": AI_DEFAULTS["max_tokens"],
        "temperature": AI_DEFAULTS["temperature"],
        "timeout": AI_DEFAULTS["timeout"],
        "max_concurrency": AI_DEFAULTS["max_concurrency"],
        "max_input_chars": AI_DEFAULTS["max_input_chars"],
        "max_layer2_flows": AI_DEFAULTS["max_layer2_flows"],
        "is_default": is_default,
    }
    p.update(overrides)
    return p


@pytest.fixture
def config_with_providers(tmp_path: Path) -> ConfigManager:
    """ConfigManager 预置一个内置 provider + 一个自定义 provider，激活 Custom"""
    cfg = ConfigManager(config_path=tmp_path / "config.json")
    cfg.set_providers(
        [_make_provider("Builtin", is_default=True), _make_provider("Custom")],
        "Custom",
    )
    cfg.save()
    return cfg


@pytest.fixture
def config_only_default(tmp_path: Path) -> ConfigManager:
    """ConfigManager 只有一个内置默认 provider"""
    cfg = ConfigManager(config_path=tmp_path / "config.json")
    cfg.set_providers([_make_provider("Builtin", is_default=True)], "Builtin")
    cfg.save()
    return cfg


@pytest.fixture
def config_only_custom(tmp_path: Path) -> ConfigManager:
    """ConfigManager 没有内置，只有一条自定义"""
    cfg = ConfigManager(config_path=tmp_path / "config.json")
    cfg.set_providers([_make_provider("Solo")], "Solo")
    cfg.save()
    return cfg


class TestSettingsDialogConstruction:
    """对话框构造与初始 UI 状态"""

    def test_dialog_constructs(self, qapp, config_with_providers):
        dlg = SettingsDialog(config_with_providers)
        assert isinstance(dlg, QDialog)
        assert dlg.windowTitle() == "PacketLens 设置"
        dlg.deleteLater()

    def test_combo_lists_all_providers(self, qapp, config_with_providers):
        '''下拉框包含所有模型，内置标记"内置"'''
        dlg = SettingsDialog(config_with_providers)
        items = [dlg._provider_combo.itemText(i) for i in range(dlg._provider_combo.count())]
        assert "Builtin (内置)" in items
        assert "Custom" in items
        dlg.deleteLater()

    def test_combo_selects_active(self, qapp, config_with_providers):
        """初始激活的 provider 应被选中并加载到表单"""
        dlg = SettingsDialog(config_with_providers)
        assert dlg._provider_combo.currentText() == "Custom"
        assert dlg._name_edit.text() == "Custom"
        dlg.deleteLater()

    def test_active_box_shows_active_info(self, qapp, config_with_providers):
        """左侧卡片显示当前激活 provider 的信息"""
        dlg = SettingsDialog(config_with_providers)
        assert dlg._active_name == "Custom"
        assert dlg._active_name_lbl.text() == "Custom"
        assert "openai" in dlg._active_proto_lbl.text().lower()
        dlg.deleteLater()

    def test_no_builtin_shows_active_custom(self, qapp, config_only_custom):
        """无内置时左侧仍显示当前激活的自定义模型"""
        dlg = SettingsDialog(config_only_custom)
        assert dlg._builtin is None
        assert dlg._active_name == "Solo"
        assert dlg._active_name_lbl.text() == "Solo"
        dlg.deleteLater()

    def test_capture_tab_values_loaded(self, qapp, config_with_providers):
        dlg = SettingsDialog(config_with_providers)
        assert dlg._duration_spin.value() == config_with_providers.get("default_capture_duration", 60)
        assert dlg._auto_analyze_cb.isChecked() == config_with_providers.get("auto_analyze", True)
        assert dlg._auto_save_cb.isChecked() == config_with_providers.get("auto_save_pcap", True)
        dlg.deleteLater()


class TestSettingsDialogActivation:
    """激活切换按钮与状态指示"""

    def test_activate_builtin_updates_indicators(self, qapp, config_with_providers):
        """选中 Builtin 后点击「切换为当前使用」，激活切换为 Builtin"""
        dlg = SettingsDialog(config_with_providers)
        # 初始 Custom 激活
        assert dlg._active_name == "Custom"
        # 选中 Builtin (index 0)
        dlg._provider_combo.setCurrentIndex(0)
        dlg._activate_selected()
        assert dlg._active_name == "Builtin"
        # 按钮禁用 + ✓ 当前使用中
        assert not dlg._use_selected_btn.isEnabled()
        assert "当前使用中" in dlg._selected_active_label.text()
        dlg.deleteLater()

    def test_activate_custom_updates_indicators(self, qapp, config_with_providers):
        """切换激活到 Builtin 后再切回 Custom"""
        dlg = SettingsDialog(config_with_providers)
        # 先激活 Builtin
        dlg._provider_combo.setCurrentIndex(0)
        dlg._activate_selected()
        assert dlg._active_name == "Builtin"

        # 再切回 Custom
        dlg._provider_combo.setCurrentIndex(1)
        dlg._activate_selected()
        assert dlg._active_name == "Custom"
        assert "当前使用中" in dlg._selected_active_label.text()
        assert not dlg._use_selected_btn.isEnabled()
        dlg.deleteLater()

    def test_test_button_label_includes_selected_name(self, qapp, config_with_providers):
        """测试按钮文字附带当前选中模型名"""
        dlg = SettingsDialog(config_with_providers)
        # 初始选中 Custom
        assert "Custom" in dlg._test_btn.text()
        # 切到 Builtin
        dlg._provider_combo.setCurrentIndex(0)
        assert "Builtin" in dlg._test_btn.text()
        dlg.deleteLater()


class TestSettingsDialogAddDelete:
    """添加 / 删除 provider"""

    def test_add_provider_creates_entry(self, qapp, config_with_providers, monkeypatch):
        """添加 provider 后 combo 增加新项并切到该项"""
        monkeypatch.setattr(QInputDialog, "getText", lambda *a, **kw: ("NewProv", True))
        dlg = SettingsDialog(config_with_providers)
        before = dlg._provider_combo.count()
        dlg._add_provider()
        assert dlg._provider_combo.count() == before + 1
        assert dlg._provider_combo.currentText() == "NewProv"
        # 默认值来自 AI_DEFAULTS
        assert dlg._context_window_spin.value() == AI_DEFAULTS["context_window_tokens"]
        # 添加并不自动激活
        assert dlg._active_name == "Custom"
        dlg.deleteLater()

    def test_add_duplicate_name_blocked(self, qapp, config_with_providers, monkeypatch):
        """添加重名 provider 会被警告挡住"""
        monkeypatch.setattr(QInputDialog, "getText", lambda *a, **kw: ("Custom", True))
        warned = {"v": False}
        monkeypatch.setattr(
            QMessageBox, "warning",
            lambda *a, **kw: warned.update(v=True) or QMessageBox.Ok,
        )
        dlg = SettingsDialog(config_with_providers)
        before = dlg._provider_combo.count()
        dlg._add_provider()
        assert warned["v"] is True
        assert dlg._provider_combo.count() == before
        dlg.deleteLater()

    def test_add_duplicate_with_builtin_name_blocked(
        self, qapp, config_with_providers, monkeypatch
    ):
        """与内置 provider 重名也应被挡住"""
        monkeypatch.setattr(QInputDialog, "getText", lambda *a, **kw: ("Builtin", True))
        warned = {"v": False}
        monkeypatch.setattr(
            QMessageBox, "warning",
            lambda *a, **kw: warned.update(v=True) or QMessageBox.Ok,
        )
        dlg = SettingsDialog(config_with_providers)
        before = dlg._provider_combo.count()
        dlg._add_provider()
        assert warned["v"] is True
        assert dlg._provider_combo.count() == before
        dlg.deleteLater()

    def test_add_cancelled(self, qapp, config_with_providers, monkeypatch):
        """添加对话框取消时不创建 provider"""
        monkeypatch.setattr(QInputDialog, "getText", lambda *a, **kw: ("", False))
        dlg = SettingsDialog(config_with_providers)
        before = dlg._provider_combo.count()
        dlg._add_provider()
        assert dlg._provider_combo.count() == before
        dlg.deleteLater()

    def test_delete_custom_provider(self, qapp, config_with_providers, monkeypatch):
        """删除当前编辑的自定义 provider 后下拉框减少 1"""
        monkeypatch.setattr(QMessageBox, "question", lambda *a, **kw: QMessageBox.Yes)
        dlg = SettingsDialog(config_with_providers)
        # 选中 Custom (index 1)
        dlg._provider_combo.setCurrentIndex(1)
        before = dlg._provider_combo.count()
        dlg._del_provider()
        assert dlg._provider_combo.count() == before - 1
        dlg.deleteLater()

    def test_delete_active_custom_falls_back_to_builtin(
        self, qapp, config_with_providers, monkeypatch
    ):
        """删除激活的自定义 provider，激活回退到第一个剩余 provider"""
        monkeypatch.setattr(QMessageBox, "question", lambda *a, **kw: QMessageBox.Yes)
        dlg = SettingsDialog(config_with_providers)
        # 选中 Custom 并激活
        dlg._provider_combo.setCurrentIndex(1)
        dlg._activate_selected()
        assert dlg._active_name == "Custom"
        dlg._del_provider()
        # 回退到 Builtin
        assert dlg._active_name == "Builtin"
        # 左侧应刷新显示 Builtin
        assert "Builtin" in dlg._provider_combo.currentText()
        dlg.deleteLater()

    def test_delete_only_provider_clears_active(
        self, qapp, config_only_custom, monkeypatch
    ):
        """无内置时删除唯一 provider，active 退化为空，空状态提示出现"""
        monkeypatch.setattr(QMessageBox, "question", lambda *a, **kw: QMessageBox.Yes)
        dlg = SettingsDialog(config_only_custom)
        dlg._del_provider()
        assert dlg._provider_combo.count() == 0
        assert dlg._active_name == ""
        assert not dlg._empty_hint.isHidden()
        assert dlg._form_widget.isHidden()
        assert not dlg._del_btn.isEnabled()
        dlg.deleteLater()

    def test_only_builtin_allows_viewing(self, qapp, config_only_default):
        """只有内置时下拉框有 Builtin (内置)，表单可见且只读"""
        dlg = SettingsDialog(config_only_default)
        assert dlg._provider_combo.count() == 1
        assert "Builtin (内置)" in dlg._provider_combo.currentText()
        # 表单可见
        assert not dlg._form_widget.isHidden()
        # 内置只读
        assert dlg._name_edit.isReadOnly()
        # 激活是 Builtin
        assert dlg._active_name == "Builtin"
        dlg.deleteLater()

    def test_delete_builtin_blocked(self, qapp, config_only_default, monkeypatch):
        """删除内置 provider 会被警告挡住"""
        warned = {"v": False}
        monkeypatch.setattr(
            QMessageBox, "warning",
            lambda *a, **kw: warned.update(v=True) or QMessageBox.Ok,
        )
        dlg = SettingsDialog(config_only_default)
        dlg._del_provider()
        assert warned["v"] is True
        assert dlg._provider_combo.count() == 1
        dlg.deleteLater()

    def test_delete_cancelled_keeps_provider(
        self, qapp, config_with_providers, monkeypatch
    ):
        """取消删除确认后 provider 保留"""
        monkeypatch.setattr(QMessageBox, "question", lambda *a, **kw: QMessageBox.No)
        dlg = SettingsDialog(config_with_providers)
        before = dlg._provider_combo.count()
        dlg._del_provider()
        assert dlg._provider_combo.count() == before
        dlg.deleteLater()


class TestSettingsDialogSwitching:
    """下拉框切换行为"""

    def test_switching_preserves_unsaved_edits(self, qapp, tmp_path, monkeypatch):
        """切换两条 provider 之间，未保存编辑会落到原 provider 上"""
        cfg = ConfigManager(config_path=tmp_path / "config.json")
        cfg.set_providers(
            [_make_provider("CA"), _make_provider("CB")],
            "CA",
        )
        cfg.save()
        dlg = SettingsDialog(cfg)
        assert dlg._provider_combo.currentText() == "CA"
        # 修改 CA 的 api_key
        dlg._api_key_edit.setText("sk-modified-CA")
        # 切到 CB (index 1)
        dlg._provider_combo.setCurrentIndex(1)
        # 切回 CA (index 0)
        dlg._provider_combo.setCurrentIndex(0)
        assert dlg._api_key_edit.text() == "sk-modified-CA"
        dlg.deleteLater()

    def test_renaming_active_custom_syncs_active_name(self, qapp, config_with_providers):
        """对激活的自定义改名后，_active_name 会跟随更新"""
        dlg = SettingsDialog(config_with_providers)
        # 选中 Custom 并激活
        dlg._provider_combo.setCurrentIndex(1)
        dlg._activate_selected()
        assert dlg._active_name == "Custom"
        dlg._name_edit.setText("CustomRenamed")
        dlg._save_provider_form()
        assert dlg._active_name == "CustomRenamed"
        # combo 文本同步（带 (内置) 后缀的逻辑只在是内置时触发，这里 Custom 没有）
        assert dlg._provider_combo.currentText() == "CustomRenamed"
        dlg.deleteLater()


class TestSettingsDialogSave:
    """保存路径"""

    def test_save_persists_capture_settings(self, qapp, config_with_providers):
        dlg = SettingsDialog(config_with_providers)
        dlg._duration_spin.setValue(120)
        dlg._auto_analyze_cb.setChecked(False)
        dlg._auto_save_cb.setChecked(False)
        dlg._save_and_accept()
        assert config_with_providers.get("default_capture_duration") == 120
        assert config_with_providers.get("auto_analyze") is False
        assert config_with_providers.get("auto_save_pcap") is False
        dlg.deleteLater()

    def test_save_persists_custom_provider_edits(self, qapp, config_with_providers):
        dlg = SettingsDialog(config_with_providers)
        # 确保选中 Custom
        dlg._provider_combo.setCurrentIndex(1)
        dlg._api_key_edit.setText("sk-edited")
        dlg._model_edit.setText("model-edited")
        dlg._save_and_accept()
        providers = config_with_providers.get_providers()
        custom = next(p for p in providers if p["name"] == "Custom")
        assert custom["api_key"] == "sk-edited"
        assert custom["model"] == "model-edited"
        dlg.deleteLater()

    def test_save_persists_active_name(self, qapp, config_with_providers):
        """切换激活并保存后，配置中的 ai_active_provider 同步更新"""
        dlg = SettingsDialog(config_with_providers)
        # 选中 Builtin 并激活
        dlg._provider_combo.setCurrentIndex(0)
        dlg._activate_selected()
        dlg._save_and_accept()
        assert config_with_providers.get_active_provider_name() == "Builtin"
        dlg.deleteLater()

    def test_save_blocked_when_active_custom_missing_required(
        self, qapp, config_with_providers, monkeypatch
    ):
        """激活的自定义 provider 缺必填时阻断保存"""
        warned = {"v": False}
        monkeypatch.setattr(
            QMessageBox, "warning",
            lambda *a, **kw: warned.update(v=True) or QMessageBox.Ok,
        )
        dlg = SettingsDialog(config_with_providers)
        # 选中 Custom 并激活
        dlg._provider_combo.setCurrentIndex(1)
        dlg._activate_selected()
        dlg._model_edit.setText("")
        dlg._save_and_accept()
        assert warned["v"] is True
        assert dlg.result() != QDialog.Accepted
        dlg.deleteLater()

    def test_save_default_provider_skips_validation(self, qapp, config_only_default):
        """激活内置 provider 时不做必填校验"""
        dlg = SettingsDialog(config_only_default)
        # 初始已激活 Builtin
        dlg._save_and_accept()
        assert dlg.result() == QDialog.Accepted
        dlg.deleteLater()

    def test_save_blocks_when_no_active(self, qapp, config_only_custom, monkeypatch):
        """保存时若没有激活 provider 应阻断"""
        monkeypatch.setattr(QMessageBox, "question", lambda *a, **kw: QMessageBox.Yes)
        warned = {"v": False}
        monkeypatch.setattr(
            QMessageBox, "warning",
            lambda *a, **kw: warned.update(v=True) or QMessageBox.Ok,
        )
        dlg = SettingsDialog(config_only_custom)
        # 删掉唯一一个 → active 变空
        dlg._del_provider()
        assert dlg._active_name == ""
        dlg._save_and_accept()
        assert warned["v"] is True
        assert dlg.result() != QDialog.Accepted
        dlg.deleteLater()


class TestSettingsDialogMisc:
    """杂项 UI 行为"""

    def test_toggle_api_key_visibility(self, qapp, config_with_providers):
        dlg = SettingsDialog(config_with_providers)
        assert dlg._api_key_edit.echoMode() == QLineEdit.Password
        dlg._toggle_key_visibility()
        assert dlg._api_key_edit.echoMode() == QLineEdit.Normal
        assert dlg._toggle_key_btn.text() == "隐藏"
        dlg._toggle_key_visibility()
        assert dlg._api_key_edit.echoMode() == QLineEdit.Password
        assert dlg._toggle_key_btn.text() == "显示"
        dlg.deleteLater()

    def test_reject_cleans_up_test_timer(self, qapp, config_with_providers):
        from PySide6.QtCore import QTimer

        dlg = SettingsDialog(config_with_providers)
        dlg._test_poll_timer = QTimer()
        dlg._test_poll_timer.start(100)
        dlg.reject()
        assert dlg._test_poll_timer is None
        dlg.deleteLater()

    def test_save_cleans_up_test_timer(self, qapp, config_with_providers):
        from PySide6.QtCore import QTimer

        dlg = SettingsDialog(config_with_providers)
        dlg._test_poll_timer = QTimer()
        dlg._test_poll_timer.start(100)
        dlg._save_and_accept()
        assert dlg._test_poll_timer is None
        dlg.deleteLater()

    def test_protocol_type_changes_placeholder(self, qapp, config_with_providers):
        dlg = SettingsDialog(config_with_providers)
        anthropic_idx = dlg._type_combo.findData("anthropic")
        dlg._type_combo.setCurrentIndex(anthropic_idx)
        assert "claude" in dlg._model_edit.placeholderText().lower()
        openai_idx = dlg._type_combo.findData("openai")
        dlg._type_combo.setCurrentIndex(openai_idx)
        assert "gpt" in dlg._model_edit.placeholderText().lower()
        dlg.deleteLater()
