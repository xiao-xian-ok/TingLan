# mms_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import os
import pathlib
import sys

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.protocol_analyzer import MMSAnalyzer


def mms_extract_tool(pcap_file):
    """旧版兼容入口"""
    pcap_name = os.path.splitext(os.path.basename(pcap_file))[0]
    output_dir = str(PROJECT_ROOT / "output" / "mms" / pcap_name)

    analyzer = MMSAnalyzer(output_dir=output_dir)

    print(f"[*] 开始深度分析: {os.path.basename(pcap_file)}")
    print("-" * 50)

    result = analyzer.analyze_pcap(pcap_file)

    for finding in result.findings:
        if finding.is_flag:
            print(f"\n{'='*20} FLAG FOUND {'='*20}")
            print(f"内容: {finding.data}")
            print(f"{'='*52}\n")
        else:
            print(f"[+] {finding.title}: {finding.description}")

    print("-" * 50)
    print(f"[*] 分析完成。提取文件存放于: {os.path.abspath(output_dir)}")


if __name__ == '__main__':
    target_pcap = input("请输入pcap文件路径:").strip().replace('"', '').replace("'", "")
    mms_extract_tool(target_pcap)
