# icmp_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import sys
import pathlib

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.protocol_analyzer import ICMPAnalyzer, analyze_icmp, ProtocolAnalysisResult

__all__ = ['ICMPAnalyzer', 'analyze_icmp', 'ProtocolAnalysisResult']


def analyze_icmp_interactive():
    """旧版兼容入口"""
    from utils import read_pcap

    file_path = input("请输入pcap文件路径: ").strip().strip('"').strip("'")
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


if __name__ == '__main__':
    analyze_icmp_interactive()
