"""路径辅助工具"""

import os
import sys
import tempfile
from pathlib import Path

from app.constants import APP_NAME


def get_app_data_dir() -> Path:
    """获取应用数据目录 (%APPDATA%/PacketLens/)"""
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path.home() / ".config"
    app_dir = base / APP_NAME
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir


def get_captures_dir() -> Path:
    """获取 PCAP 文件存储目录"""
    d = get_app_data_dir() / "captures"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_reports_dir() -> Path:
    """获取报告导出目录"""
    d = get_app_data_dir() / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_config_path() -> Path:
    """获取配置文件路径"""
    return get_app_data_dir() / "config.json"


def get_db_path() -> Path:
    """获取 SQLite 数据库路径"""
    return get_app_data_dir() / "history.db"


def resource_path(relative: str) -> Path:
    """获取资源文件路径（兼容 Nuitka 打包和开发模式）"""
    if getattr(sys, "frozen", False):
        # Nuitka/PyInstaller 打包模式
        base = Path(sys.executable).parent
    else:
        base = Path(__file__).parent.parent.parent
    return base / "resources" / relative


def atomic_write(path: Path, content: str, encoding: str = "utf-8") -> None:
    """原子写入文件：先写临时文件，再 os.replace() 替换

    os.replace() 在 POSIX 和 Windows 上都是原子操作。
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=path.name + ".tmp_",
    )
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
