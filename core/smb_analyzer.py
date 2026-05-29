# -*- coding: utf-8 -*-
# smb_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import os
import pathlib
import sys

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.protocol_analyzer import SMBAnalyzer


# 向后兼容: 模块级函数委托给 SMBAnalyzer 实例方法
_analyzer = SMBAnalyzer()


def find_tshark():
    from services.analysis_service import AnalysisService
    return AnalysisService().find_tshark()


def _run_tshark(tshark_path, args):
    return SMBAnalyzer._run_tshark(tshark_path, args)


def extract_smb_credentials(pcap_file, tshark_path):
    return _analyzer.extract_smb_credentials(pcap_file, tshark_path)


def extract_smb_files(pcap_file, tshark_path, output_dir):
    return _analyzer.extract_smb_files(pcap_file, tshark_path, output_dir)


def analyze_smb(pcap_file):
    """旧版兼容入口"""
    pcap_filename = os.path.splitext(os.path.basename(pcap_file))[0]
    output_dir = str(PROJECT_ROOT / "output" / "smb" / pcap_filename)
    analyzer = SMBAnalyzer(output_dir=output_dir)
    analyzer.analyze_pcap(pcap_file, output_dir=output_dir)


if __name__ == '__main__':
    path = input("请输入pcap文件路径:").strip().replace('"', '').replace("'", "")
    analyze_smb(path)
