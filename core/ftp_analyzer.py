# ftp_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import os
import pathlib
import sys

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.protocol_analyzer import FTPAnalyzer


def analyze_and_extract_ftp(pcap_file):
    """旧版兼容入口"""
    pcap_filename = os.path.splitext(os.path.basename(pcap_file))[0]
    output_dir = str(PROJECT_ROOT / "output" / "ftp" / pcap_filename)

    analyzer = FTPAnalyzer(output_dir=output_dir)

    print(f"[*] 正在处理: {pcap_file}")
    print(f"[*] 提取结果将保存至: {output_dir}")
    print("-" * 60)

    result = analyzer.analyze_pcap(pcap_file)

    for finding in result.findings:
        if finding.finding_type.value == "credential":
            for line in finding.data.split('\n'):
                parts = line.split(':')
                print(f"[+] 发现用户: {parts[0]}")
                if len(parts) > 1:
                    print(f"    ╰-> 密码: {parts[1]}")
        elif finding.finding_type.value == "file_extraction":
            print(f"\033[92m[DONE] {finding.title} ({finding.description})\033[0m")

    print("-" * 60)
    print(f"摘要: {result.summary}")


if __name__ == '__main__':
    path = input("请输入pcap文件路径:").strip().replace('"', '').replace("'", "")
    analyze_and_extract_ftp(path)
