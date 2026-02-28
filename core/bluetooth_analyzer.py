# bluetooth_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import os
import pathlib
import sys

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.protocol_analyzer import BluetoothAnalyzer


def extract_bluetooth_data(pcap_file):
    """旧版兼容入口"""
    pcap_name = pathlib.Path(pcap_file).stem
    output_dir = str(PROJECT_ROOT / "output" / "bt_output" / pcap_name)

    analyzer = BluetoothAnalyzer(output_dir=output_dir)

    print(f"[*] 蓝牙数据将提取至: {output_dir}")
    print(f"[*] 正在分析: {pcap_name}")

    result = analyzer.analyze_pcap(pcap_file)

    for finding in result.findings:
        if finding.finding_type.value == "file_extraction":
            print(f"[+] [OBEX] 提取成功: {finding.title}")
        else:
            print(f"[*] {finding.title}: {finding.description}")

    print(f"[*] 任务完成。摘要: {result.summary}")


if __name__ == '__main__':
    path = input("请输入pcap文件路径: ").strip().strip('"').strip("'")
    extract_bluetooth_data(path)
