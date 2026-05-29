# mms_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import os
import re
import base64
import pathlib
import sys
import subprocess

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.protocol_analyzer import MMSAnalyzer
from services.analysis_service import AnalysisService


def _extract_base64_images(pcap_file, output_dir):
    """从 MMS filedata 中提取 Base64 编码的 PNG 图片

    PNG 经 Base64 编码后固定以 iVBOR 开头，
    从 tshark 提取的 filedata hex 中搜索该特征并解码保存。
    """
    tshark_path = AnalysisService().find_tshark()
    if not tshark_path:
        return []

    # 用 tshark 提取所有 MMS filedata 的原始 hex
    cmd = [
        tshark_path, "-r", pcap_file,
        "-Y", "mms.filedata",
        "-T", "fields",
        "-e", "mms.filedata",
    ]
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding='utf-8'
        )
        stdout, _ = process.communicate()
    except FileNotFoundError:
        return []

    # 把所有 filedata hex 拼接, 转为字节再解码为文本
    all_text = ""
    for line in stdout.strip().splitlines():
        hex_str = line.strip().replace(":", "").replace(" ", "")
        if not hex_str:
            continue
        try:
            all_text += bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
        except ValueError:
            continue

    if not all_text:
        return []

    # 搜索所有 iVBOR 开头的 base64 段
    # Base64 字符集: A-Za-z0-9+/= ，可能含换行
    pattern = r'(iVBOR[A-Za-z0-9+/=\s]+)'
    matches = re.findall(pattern, all_text)

    if not matches:
        return []

    os.makedirs(output_dir, exist_ok=True)
    saved_files = []

    for idx, b64_str in enumerate(matches):
        # 去除空白字符
        b64_clean = re.sub(r'\s+', '', b64_str)

        # 补齐 base64 padding
        padding = 4 - len(b64_clean) % 4
        if padding != 4:
            b64_clean += '=' * padding

        try:
            img_data = base64.b64decode(b64_clean)
        except Exception:
            continue

        # 验证 PNG 文件头
        if img_data[:4] != b'\x89PNG':
            continue

        fname = f"mms_image_{idx}.png"
        fpath = os.path.join(output_dir, fname)
        with open(fpath, 'wb') as f:
            f.write(img_data)
        saved_files.append(fpath)
        print(f"[+] Base64 PNG 图片提取: {fname} ({len(img_data)} bytes)")

    return saved_files


def mms_extract_tool(pcap_file):
    """旧版兼容入口"""
    pcap_name = os.path.splitext(os.path.basename(pcap_file))[0]
    output_dir = str(PROJECT_ROOT / "output" / "mms" / pcap_name)

    analyzer = MMSAnalyzer(output_dir=output_dir)

    print(f"[*] 开始深度分析: {os.path.basename(pcap_file)}")
    print("-" * 50)

    result = analyzer.analyze_pcap(pcap_file)

    # 从 MMS filedata 中提取 Base64 编码的图片
    print("-" * 50)
    print("[*] 扫描 Base64 编码的图片...")
    images = _extract_base64_images(pcap_file, output_dir)
    if not images:
        print("[*] 未发现 Base64 编码的图片")

    print("-" * 50)
    print(f"[*] 分析完成。提取文件存放于: {os.path.abspath(output_dir)}")


if __name__ == '__main__':
    target_pcap = input("请输入pcap文件路径:").strip().replace('"', '').replace("'", "")
    mms_extract_tool(target_pcap)
