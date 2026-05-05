"""PacketLens — 抓包 + AI 分析工具入口

Nuitka 编译指令:
  # nuitka-project: --mode=onefile
  # nuitka-project: --standalone
  # nuitka-project: --enable-plugin=pyside6
  # nuitka-project: --windows-icon-from-ico=resources/app.ico
  # nuitka-project: --company-name=PacketLens
  # nuitka-project: --product-name=PacketLens
  # nuitka-project: --file-version=1.0.0
"""

import logging
import sys
import traceback


def _show_error_dialog(title: str, message: str) -> None:
    """使用 tkinter（不依赖 Qt）显示错误对话框"""
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(title, message)
        root.destroy()
    except Exception:
        print(f"\n{title}\n{message}", file=sys.stderr)


def main():
    # 在任何 app 模块导入之前加载 .env，确保 API Key 可用
    from pathlib import Path

    env_path = Path(__file__).resolve().parent / ".env"
    if env_path.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env_path)
        except ImportError:
            logging.warning("python-dotenv 未安装，.env 文件中的 API Key 将无法加载")

    try:
        from app.application import create_application
        from app.ui.main_window import MainWindow

        app = create_application()
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        tb = traceback.format_exc()
        _show_error_dialog("PacketLens 启动失败", f"{e}\n\n{tb}")
        sys.exit(1)


if __name__ == "__main__":
    main()
