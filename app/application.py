"""QApplication 初始化与全局配置"""

from __future__ import annotations

import logging
import sys

from PySide6.QtWidgets import QApplication


def create_application() -> QApplication:
    """创建并配置 QApplication 实例"""
    app = QApplication(sys.argv)
    app.setApplicationName("PacketLens")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("PacketLens")

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
            background-color: #313244;
            height: 2px;
        }
        QMessageBox {
            background-color: #1e1e2e;
        }
    """
