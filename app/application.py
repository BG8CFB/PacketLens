"""QApplication 初始化与全局配置"""

from __future__ import annotations

import logging
import sys

from PySide6.QtWidgets import QApplication


# Catppuccin Mocha 风格滚动条样式
# Qt QSS 特性：当一个 widget 设置了自己的 setStyleSheet 但未定义 QScrollBar 规则时，
# 其内部滚动条会回退到 Windows 原生外观（不会继承全局 stylesheet）。
# 解决办法：所有自带滚动条且设置了局部 stylesheet 的 widget，都需要把 SCROLLBAR_STYLE
# 追加到自己的样式串里，以便子级滚动条沿用统一的深色主题。
SCROLLBAR_STYLE = """
    QScrollBar:vertical {
        background: #11111b;
        width: 8px;
        margin: 0px;
        border: none;
    }
    QScrollBar::handle:vertical {
        background: #45475a;
        min-height: 24px;
        border-radius: 4px;
    }
    QScrollBar::handle:vertical:hover {
        background: #585b70;
    }
    QScrollBar::handle:vertical:pressed {
        background: #6c7086;
    }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        height: 0px;
        border: none;
        background: none;
    }
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
        background: transparent;
    }
    QScrollBar:horizontal {
        background: #11111b;
        height: 8px;
        margin: 0px;
        border: none;
    }
    QScrollBar::handle:horizontal {
        background: #45475a;
        min-width: 24px;
        border-radius: 4px;
    }
    QScrollBar::handle:horizontal:hover {
        background: #585b70;
    }
    QScrollBar::handle:horizontal:pressed {
        background: #6c7086;
    }
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
        width: 0px;
        border: none;
        background: none;
    }
    QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
        background: transparent;
    }
    QScrollBar::corner {
        background: #11111b;
        border: none;
    }
"""


def create_application() -> QApplication:
    """创建并配置 QApplication 实例"""
    app = QApplication(sys.argv)
    app.setApplicationName("PacketLens")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("PacketLens")

    # 强制 Fusion 风格，确保 QSS 在所有控件（含 QTableView 滚动条）上完全生效
    app.setStyle("Fusion")

    # 高 DPI 支持（PySide6 默认已启用）

    # 配置全局日志
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # 设置全局样式
    app.setStyleSheet(_get_base_stylesheet())

    return app


def _get_base_stylesheet() -> str:
    """获取基础样式表"""
    return """
        QMainWindow {
            background-color: #1e1e2e;
        }
        QWidget {
            color: #cdd6f4;
            font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
            font-size: 13px;
        }
        QWidget:disabled {
            color: #6c7086;
        }
        QTableView {
            background-color: #181825;
            alternate-background-color: #1e1e2e;
            gridline-color: #313244;
            selection-background-color: #45475a;
            selection-color: #cdd6f4;
            border: 1px solid #313244;
        }
        QHeaderView::section {
            background-color: #313244;
            color: #cdd6f4;
            padding: 4px 8px;
            border: none;
            border-right: 1px solid #45475a;
            font-weight: bold;
        }
        QComboBox {
            background-color: #313244;
            border: 1px solid #45475a;
            border-radius: 4px;
            padding: 4px 8px;
            min-height: 24px;
        }
        QComboBox::drop-down {
            border: none;
        }
        QComboBox QAbstractItemView {
            background-color: #313244;
            selection-background-color: #45475a;
        }
        QLineEdit {
            background-color: #313244;
            border: 1px solid #45475a;
            border-radius: 4px;
            padding: 4px 8px;
            min-height: 24px;
        }
        QSpinBox, QDoubleSpinBox {
            background-color: #313244;
            border: 1px solid #45475a;
            border-radius: 4px;
            padding: 2px 6px;
            min-height: 24px;
        }
        QSpinBox::up-button, QSpinBox::down-button,
        QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {
            width: 16px;
            border: none;
            background: transparent;
        }
        QPushButton {
            background-color: #89b4fa;
            color: #1e1e2e;
            border: none;
            border-radius: 4px;
            padding: 6px 16px;
            font-weight: bold;
            min-height: 28px;
        }
        QPushButton:hover {
            background-color: #b4befe;
        }
        QPushButton:pressed {
            background-color: #74c7ec;
        }
        QPushButton:disabled {
            background-color: #45475a;
            color: #6c7086;
        }
        QLabel {
            color: #cdd6f4;
        }
        QCheckBox {
            spacing: 6px;
        }
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
            border-radius: 4px;
            border: 2px solid #585b70;
            background-color: transparent;
        }
        QCheckBox::indicator:hover {
            border-color: #a6e3a1;
        }
        QCheckBox::indicator:checked {
            background-color: #a6e3a1;
            border: 2px solid #a6e3a1;
        }
        QCheckBox::indicator:checked:hover {
            background-color: #b9f0bc;
            border-color: #b9f0bc;
        }
        QCheckBox::indicator:pressed {
            background-color: #45475a;
            border-color: #45475a;
        }
        QGroupBox {
            border: 1px solid #313244;
            border-radius: 6px;
            margin-top: 10px;
            padding: 8px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top left;
            padding: 0 6px;
            color: #a6adc8;
            font-weight: bold;
        }
        QTabWidget::pane {
            border: 1px solid #313244;
            border-radius: 6px;
            top: -1px;
            background-color: #1e1e2e;
        }
        QTabWidget::tab-bar {
            alignment: left;
        }
        QTabBar {
            background-color: transparent;
        }
        QTabBar::tab {
            background-color: #181825;
            border: 1px solid #313244;
            border-bottom: none;
            padding: 6px 12px;
            margin-right: 4px;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            color: #a6adc8;
        }
        QTabBar::tab:selected {
            background-color: #1e1e2e;
            color: #cdd6f4;
            border-color: #45475a;
        }
        QTabBar::tab:hover:!selected {
            background-color: #1e1e2e;
            color: #cdd6f4;
        }
        QTextEdit, QTextBrowser {
            background-color: #1e1e2e;
            color: #cdd6f4;
            border: 1px solid #313244;
            border-radius: 4px;
            padding: 6px;
            selection-background-color: #45475a;
            selection-color: #cdd6f4;
        }
        QTreeWidget {
            background-color: #181825;
            alternate-background-color: #1e1e2e;
            border: 1px solid #313244;
        }
        QStatusBar {
            background-color: #181825;
            color: #a6adc8;
            border-top: 1px solid #313244;
        }
        QMenuBar {
            background-color: #181825;
            color: #cdd6f4;
            border-bottom: 1px solid #313244;
            padding: 2px;
        }
        QMenuBar::item {
            background-color: transparent;
            padding: 4px 12px;
        }
        QMenuBar::item:selected {
            background-color: #45475a;
            border-radius: 4px;
        }
        QMenu {
            background-color: #1e1e2e;
            color: #cdd6f4;
            border: 1px solid #313244;
            padding: 4px;
        }
        QMenu::item {
            padding: 6px 24px;
        }
        QMenu::item:selected {
            background-color: #45475a;
            border-radius: 4px;
        }
        QSplitter::handle {
            background-color: #1e1e2e;
            border: 1px solid #313244;
        }
        QSplitter::handle:horizontal {
            width: 4px;
        }
        QSplitter::handle:vertical {
            height: 4px;
        }
        QScrollBar:vertical {
            background: #11111b;
            width: 8px;
            margin: 0px;
            border: none;
        }
        QScrollBar::handle:vertical {
            background: #45475a;
            min-height: 24px;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical:hover {
            background: #585b70;
        }
        QScrollBar::handle:vertical:pressed {
            background: #6c7086;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
            border: none;
            background: none;
        }
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
            background: transparent;
        }
        QScrollBar:horizontal {
            background: #11111b;
            height: 8px;
            margin: 0px;
            border: none;
        }
        QScrollBar::handle:horizontal {
            background: #45475a;
            min-width: 24px;
            border-radius: 4px;
        }
        QScrollBar::handle:horizontal:hover {
            background: #585b70;
        }
        QScrollBar::handle:horizontal:pressed {
            background: #6c7086;
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0px;
            border: none;
            background: none;
        }
        QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
            background: transparent;
        }
        QScrollBar::corner {
            background: #11111b;
            border: none;
        }
        QToolTip {
            background-color: #11111b;
            color: #cdd6f4;
            border: 1px solid #313244;
            padding: 6px;
        }
        QMessageBox {
            background-color: #1e1e2e;
        }
        QDialog {
            background-color: #1e1e2e;
            color: #cdd6f4;
        }
        QInputDialog {
            background-color: #1e1e2e;
            color: #cdd6f4;
        }
    """
