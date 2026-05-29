# -*- coding: utf-8 -*-
# rdp_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import os
import pathlib
import sys

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.protocol_analyzer import RDPAnalyzer


# 向后兼容: 模块级函数委托给 RDPAnalyzer 实例方法
_analyzer = RDPAnalyzer()


def find_tshark():
    from services.analysis_service import AnalysisService
    return AnalysisService().find_tshark()


def _run_tshark(tshark_path, args):
    return RDPAnalyzer._run_tshark(tshark_path, args)


def extract_rdp_sessions(pcap_file, tshark_path):
    return _analyzer.extract_rdp_sessions(pcap_file, tshark_path)


def extract_rdp_ntlm(pcap_file, tshark_path):
    return _analyzer.extract_rdp_ntlm(pcap_file, tshark_path)


def extract_rdp_certificates(pcap_file, tshark_path):
    return _analyzer.extract_rdp_certificates(pcap_file, tshark_path)


def decrypt_rdp_with_key(pcap_file, tshark_path, key_file, server_ip=None):
    return _analyzer.decrypt_rdp_with_key(pcap_file, tshark_path, key_file, server_ip)


def decrypt_rdp_with_keylog(pcap_file, tshark_path, keylog_file):
    return _analyzer.decrypt_rdp_with_keylog(pcap_file, tshark_path, keylog_file)


def analyze_rdp(pcap_file, key_file=None, keylog_file=None, server_ip=None):
    """旧版兼容入口"""
    analyzer = RDPAnalyzer(
        key_file=key_file,
        keylog_file=keylog_file,
        server_ip=server_ip,
    )
    analyzer.analyze_pcap(
        pcap_file,
        key_file=key_file,
        keylog_file=keylog_file,
        server_ip=server_ip,
    )


if __name__ == '__main__':
    pcap = input("请输入pcap文件路径:").strip().replace('"', '').replace("'", "")
    key = input("请输入RSA私钥路径 (无则回车跳过):").strip().replace('"', '').replace("'", "")
    keylog = input("请输入TLS keylog路径 (无则回车跳过):").strip().replace('"', '').replace("'", "")
    srv_ip = input("请输入RDP服务器IP (无则回车跳过):").strip()

    analyze_rdp(
        pcap,
        key_file=key if key else None,
        keylog_file=keylog if keylog else None,
        server_ip=srv_ip if srv_ip else None,
    )
