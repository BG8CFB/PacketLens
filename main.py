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

import sys


def main():
    # 在任何 app 模块导入之前加载 .env，确保 API Key 可用
    from pathlib import Path
    env_path = Path(__file__).resolve().parent / ".env"
    if env_path.exists():
        from dotenv import load_dotenv
        load_dotenv(env_path)

    from app.application import create_application
    from app.ui.main_window import MainWindow

    app = create_application()
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
