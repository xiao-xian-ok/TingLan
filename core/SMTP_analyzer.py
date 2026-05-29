# SMTP_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import os
import pathlib
import sys

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.protocol_analyzer import SMTPAnalyzer


def extract_smtp_forensics(pcap_file):
    """旧版兼容入口"""
    pcap_name = os.path.splitext(os.path.basename(pcap_file))[0]
    output_dir = str(PROJECT_ROOT / "output" / "smtp" / pcap_name)

    analyzer = SMTPAnalyzer(output_dir=output_dir)

    print(f"\n[*] 正在深度扫描: {os.path.basename(pcap_file)}")
    print(f"[*] 结果将存入: {output_dir}")
    print("=" * 60)

    result = analyzer.analyze_pcap(pcap_file)

    for finding in result.findings:
        if finding.finding_type.value == "credential":
            for line in finding.data.split('\n'):
                parts = line.split(':')
                print(f"[AUTH] 账号: {parts[0]}")
                if len(parts) > 1:
                    print(f"[AUTH] 密码: {parts[1]}")
        elif finding.finding_type.value == "file_extraction":
            print(f"[+] {finding.title}")
            print(f"    {finding.description}")
        elif finding.finding_type.value == "info":
            print(f"{finding.data}")

    print(f"\n[*] 分析完毕。{result.summary}")


if __name__ == '__main__':
    path = input("请输入pcap文件路径:").strip().replace('"', '').replace("'", "")
    if os.path.exists(path):
        extract_smtp_forensics(path)
    else:
        print("[!] 文件不存在。")
