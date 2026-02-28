# -*- coding: utf-8 -*-
# dns_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import os
import pathlib
import sys

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.protocol_analyzer import DNSCovertChannelAnalyzer


def analyze_dns():
    """旧版兼容入口"""
    pcap_path = input("请输入 PCAP 路径: ").strip().strip('"')
    if not os.path.exists(pcap_path):
        print("[-] 文件不存在")
        return

    print("\n请选择解码模式:")
    print("[1] Hex 模式 (Hex -> Base64 -> GB2312)")
    print("[2] Base64 模式 (Base64 -> GB2312)")
    mode = input("输入选项 (1 或 2): ").strip()

    decode_mode = "hex" if mode == "1" else "base64"

    pcap_filename = pathlib.Path(pcap_path).stem
    output_file = str(PROJECT_ROOT / "output" / "dns" / f"{pcap_filename}.txt")

    print("\n" + "=" * 30)
    print(f"DNS 分析开始 [当前模式: {'Hex' if mode == '1' else 'Base64'}]")
    print("=" * 30)

    analyzer = DNSCovertChannelAnalyzer(decode_mode=decode_mode)
    result = analyzer.analyze_pcap(pcap_path, output_file=output_file)


if __name__ == "__main__":
    analyze_dns()
