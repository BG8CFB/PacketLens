"""PacketLens — 抓包 + AI 分析工具入口"""

import inspect
import logging
import os
import sys
import traceback
from pathlib import Path

# Nuitka 编译后某些模块的 __file__ 变成 dict 而非 str，
# 导致 inspect.getfile → getsourcefile → findsource 全链路崩溃。
# 必须在所有其他模块导入之前打补丁。
_original_getfile = inspect.getfile


def _patched_getfile(obj):
    result = _original_getfile(obj)
    if not isinstance(result, str):
        raise TypeError("{!r} is a built-in module".format(obj))
    return result


inspect.getfile = _patched_getfile


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
    # Nuitka standalone 模式下 __file__ 不可靠，用多种方式定位 exe 所在目录
    if getattr(sys, "frozen", False) or hasattr(sys, "_nuitka_version"):
        base_dir = Path(sys.executable).resolve().parent
    else:
        base_dir = Path(__file__).resolve().parent

    # Nuitka standalone 构建中 conda-forge OpenSSL 找不到 CA 证书，
    # 必须直接 patch ssl.create_default_context 注入 certifi 的 cafile
    certifi_cert = str(base_dir / "certifi" / "cacert.pem")
    if os.path.isfile(certifi_cert):
        import ssl

        _orig_create_ctx = ssl.create_default_context

        def _patched_create_ctx(purpose=ssl.Purpose.SERVER_AUTH, **kw):
            if "cafile" not in kw:
                kw["cafile"] = certifi_cert
            return _orig_create_ctx(purpose=purpose, **kw)

        ssl.create_default_context = _patched_create_ctx
        ssl._create_default_https_context = _patched_create_ctx

    # 加载 .env 文件（API Key 等）
    env_path = base_dir / ".env"
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
