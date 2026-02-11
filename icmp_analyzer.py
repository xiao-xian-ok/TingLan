# icmp_analyzer.py - 兼容入口，核心功能在 core/protocol_analyzer.py
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
CORE_PATH = os.path.join(PROJECT_ROOT, "core")
if CORE_PATH not in sys.path:
    sys.path.insert(0, CORE_PATH)

from core.protocol_analyzer import (
    analyze_icmp,
    ICMPAnalyzer,
    ProtocolAnalysisResult
)

__all__ = ['analyze_icmp', 'ICMPAnalyzer', 'ProtocolAnalysisResult']


if __name__ == '__main__':
    from utils import read_pcap

    file_path = input("请输入pcap文件路径: ").strip('"')
    print(f"[*] 正在分析: {file_path}，请稍候...")

    try:
        cap = read_pcap(file_path)
        pkts = list(cap)
        cap.close()

        print("\n" + "=" * 20 + " ICMP 自动化综合分析 " + "=" * 20)
        result = analyze_icmp(pkts)

        print(f"\n分析完成，共处理 {result.packet_count} 个ICMP包")
        print(f"摘要: {result.summary}")

        if result.findings:
            print("\n" + "=" * 20 + " 发现摘要 " + "=" * 20)
            for f in result.findings:
                flag_mark = " [FLAG]" if f.is_flag else ""
                print(f"[{f.finding_type.value}] {f.title}{flag_mark}: {f.data}")
    except Exception as e:
        print(f"[!] 运行出错: {e}")
