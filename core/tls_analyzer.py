# -*- coding: utf-8 -*-
# tls_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import os
import pathlib
import sys

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.protocol_analyzer import TLSAnalyzer


# 向后兼容: 模块级函数委托给 TLSAnalyzer 实例方法
_analyzer = TLSAnalyzer()


def find_tshark():
    from services.analysis_service import AnalysisService
    return AnalysisService().find_tshark()


def _run_tshark(tshark_path, args):
    return TLSAnalyzer._run_tshark(tshark_path, args)


def extract_tls_handshake(pcap_file, tshark_path):
    return _analyzer.extract_tls_handshake(pcap_file, tshark_path)


def extract_tls_sessions(pcap_file, tshark_path):
    return _analyzer.extract_tls_sessions(pcap_file, tshark_path)


def decrypt_with_key(pcap_file, tshark_path, key_file, server_ip=None, port='443'):
    return _analyzer.decrypt_with_key(pcap_file, tshark_path, key_file, server_ip, port)


def decrypt_with_keylog(pcap_file, tshark_path, keylog_file):
    return _analyzer.decrypt_with_keylog(pcap_file, tshark_path, keylog_file)


def export_decrypted_objects(pcap_file, tshark_path, output_dir, key_file=None, keylog_file=None):
    return _analyzer.export_decrypted_objects(pcap_file, tshark_path, output_dir, key_file, keylog_file)


def extract_keylog_from_pcap(pcap_file, tshark_path, output_dir):
    return _analyzer.extract_keylog_from_pcap(pcap_file, tshark_path, output_dir)


def search_and_highlight_flags(output_dir, exported_files):
    return _analyzer.search_and_highlight_flags(output_dir, exported_files)


def analyze_tls(pcap_file, key_file=None, keylog_file=None, server_ip=None, port='443'):
    """旧版兼容入口"""
    analyzer = TLSAnalyzer(
        key_file=key_file,
        keylog_file=keylog_file,
        server_ip=server_ip,
        port=port,
    )
    analyzer.analyze_pcap(
        pcap_file,
        key_file=key_file,
        keylog_file=keylog_file,
        server_ip=server_ip,
        port=port,
    )


if __name__ == '__main__':
    pcap = input('请输入pcap文件路径:').strip().replace('"', '').replace("'", '')
    key = input('请输入RSA私钥路径 (无则回车跳过):').strip().replace('"', '').replace("'", '')
    keylog = input('请输入TLS keylog路径 (无则回车跳过):').strip().replace('"', '').replace("'", '')
    srv_ip = input('请输入服务器IP (无则回车跳过):').strip()
    srv_port = input('请输入服务器端口 (默认443):').strip()

    analyze_tls(
        pcap,
        key_file=key if key else None,
        keylog_file=keylog if keylog else None,
        server_ip=srv_ip if srv_ip else None,
        port=srv_port if srv_port else '443',
    )
