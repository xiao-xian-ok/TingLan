# -*- coding: utf-8 -*-
# redis_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import os
import pathlib
import sys

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.protocol_analyzer import RedisAnalyzer


# 向后兼容: 模块级函数委托给 RedisAnalyzer 实例方法
_analyzer = RedisAnalyzer()


def find_tshark():
    from services.analysis_service import AnalysisService
    return AnalysisService().find_tshark()


def _run_tshark(tshark_path, args):
    return RedisAnalyzer._run_tshark(tshark_path, args)


def _parse_resp(data):
    return RedisAnalyzer._parse_resp(data)


def _format_command(parts):
    return RedisAnalyzer._format_command(parts)


def extract_redis_commands(pcap_file, tshark_path):
    return _analyzer.extract_redis_commands(pcap_file, tshark_path)


def analyze_redis_traffic(pcap_file, tshark_path):
    return _analyzer.analyze_redis_traffic(pcap_file, tshark_path)


def analyze_redis(pcap_file):
    """旧版兼容入口"""
    _analyzer.analyze_pcap(pcap_file)


if __name__ == '__main__':
    path = input("请输入pcap文件路径:").strip().replace('"', '').replace("'", "")
    analyze_redis(path)
