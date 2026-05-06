"""PacketLens 打包构建脚本

使用 Nuitka 将项目编译为独立可执行文件（standalone 模式，生成完整目录）。
用法: conda run -n packetlens python build.py
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    print("=" * 60)
    print("  PacketLens — Nuitka 打包构建 (standalone)")
    print("=" * 60)

    entry = ROOT / "main.py"
    if not entry.exists():
        print(f"错误: 找不到入口文件 {entry}")
        sys.exit(1)

    try:
        result = subprocess.run(
            [sys.executable, "-m", "nuitka", "--version"],
            capture_output=True, text=True,
        )
        print(f"\nNuitka 版本: {result.stdout.strip()}")
    except Exception as e:
        print(f"错误: Nuitka 不可用 — {e}")
        sys.exit(1)

    try:
        import PySide6
        print(f"PySide6: {PySide6.__version__}")
    except ImportError:
        print("错误: PySide6 未安装")
        sys.exit(1)

    # 输出目录：构建在 %TEMP% 下避免 Defender 干扰，完成后拷贝到项目 dist/
    import tempfile
    temp_build = Path(tempfile.gettempdir()) / "packetlens-build"
    temp_build.mkdir(exist_ok=True)

    final_dist = ROOT / "dist"

    icon_path = ROOT / "resources" / "app.ico"
    icon_args = [f"--windows-icon-from-ico={icon_path}"] if icon_path.exists() else []

    cpu_count = os.cpu_count() or 4
    print(f"并行编译: {cpu_count} 核心")
    print(f"构建目录: {temp_build}")

    cmd = [
        sys.executable, "-m", "nuitka",
        "--mode=standalone",
        "--enable-plugin=pyside6",
        "--output-dir=" + str(temp_build),
        "--output-filename=PacketLens.exe",
        # 反误报：不弹黑框、固定解压路径
        "--windows-console-mode=disable",
        # 并行编译
        f"--jobs={cpu_count}",
        # 依赖追踪
        "--assume-yes-for-downloads",
        "--follow-imports",
        # 项目包
        "--include-package=app",
        # langchain 全家桶（langchain_openai 依赖 langchain_core 等）
        "--include-package=langchain_core",
        "--include-package=langchain_openai",
        "--include-package=langchain_anthropic",
        "--include-package=langchain_protocol",
        "--include-package=langsmith",
        # scapy 及其数据文件
        "--include-package=scapy",
        "--include-package-data=scapy",
        # dotenv
        "--include-module=dotenv",
    ] + icon_args + [str(entry)]

    print(f"\n入口文件: {entry}")
    print(f"\n开始编译...\n")
    print(" ".join(cmd))
    print()

    result = subprocess.run(cmd, cwd=str(ROOT))
    if result.returncode != 0:
        print(f"\n构建失败，退出码: {result.returncode}")
        sys.exit(result.returncode)

    # standalone 模式输出在 temp_build/main.dist/
    source_dist = temp_build / "main.dist"
    exe_in_dist = source_dist / "PacketLens.exe"

    if not exe_in_dist.exists():
        print(f"\n警告: 编译完成但未找到 {exe_in_dist}")
        sys.exit(1)

    # 拷贝到项目 dist/ 目录
    if final_dist.exists():
        shutil.rmtree(final_dist)
    shutil.copytree(source_dist, final_dist)

    # 统计
    total_size = sum(f.stat().st_size for f in final_dist.rglob("*") if f.is_file())
    file_count = sum(1 for f in final_dist.rglob("*") if f.is_file())
    size_mb = total_size / (1024 * 1024)

    print(f"\n{'=' * 60}")
    print(f"  构建成功!")
    print(f"  输出目录: {final_dist}")
    print(f"  可执行文件: {final_dist / 'PacketLens.exe'}")
    print(f"  总大小: {size_mb:.1f} MB ({file_count} 个文件)")
    print(f"{'=' * 60}")
    print(f"\n使用方法:")
    print(f"  1. 将 .env 文件放在 dist/ 目录下（与 PacketLens.exe 同目录）")
    print(f"  2. 确保目标机器已安装 Npcap (https://npcap.com)")
    print(f"  3. 右键 PacketLens.exe → 以管理员身份运行")
    print(f"\n分发: 将整个 dist/ 文件夹打包为 zip 即可分发")


if __name__ == "__main__":
    main()
