# -*- coding: utf-8 -*-
# ssh_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import os
import pathlib
import sys

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.protocol_analyzer import SSHAnalyzer


# 向后兼容: 模块级函数委托给 SSHAnalyzer 实例方法
_analyzer = SSHAnalyzer()


def find_tshark():
    from services.analysis_service import AnalysisService
    return AnalysisService().find_tshark()


def _run_tshark(tshark_path, args):
    return SSHAnalyzer._run_tshark(tshark_path, args)


def extract_ssh_sessions(pcap_file, tshark_path):
    return _analyzer.extract_ssh_sessions(pcap_file, tshark_path)


def decrypt_ssh_with_key(pcap_file, tshark_path, key_file):
    return _analyzer.decrypt_ssh_with_key(pcap_file, tshark_path, key_file)


def detect_bruteforce(pcap_file, tshark_path, threshold=10):
    return _analyzer.detect_bruteforce(pcap_file, tshark_path, threshold)


def analyze_ssh(pcap_file, key_file=None):
    """旧版兼容入口"""
    analyzer = SSHAnalyzer(key_file=key_file)
    analyzer.analyze_pcap(pcap_file, key_file=key_file)


if __name__ == '__main__':
    pcap = input("请输入pcap文件路径:").strip().replace('"', '').replace("'", "")
    key = input("请输入SSH私钥路径 (无则回车跳过):").strip().replace('"', '').replace("'", "")
    analyze_ssh(pcap, key if key else None)
