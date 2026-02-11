# ftp分析模块

import os
import pathlib
import sys
current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))
from utils import read_pcap

def analyze_and_extract_ftp(pcap_file):
    base_output = pathlib.Path(__file__).resolve().parent.parent / "output" / "ftp"

    pcap_filename = os.path.splitext(os.path.basename(pcap_file))[0]
    output_dir = os.path.join(base_output, pcap_filename)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"[*] 正在处理: {pcap_file}")
    print(f"[*] 提取结果将保存至: {output_dir}")

    packets = read_pcap(pcap_file)

    credentials = []
    filename_map = {}
    file_data_map = {}
    current_filename = "other_file"

    print("-" * 60)
    for i, pkt in enumerate(packets):
        # 控制流分析
        if 'FTP' in pkt:
            try:
                ftp = pkt.ftp
                if hasattr(ftp, 'request_command'):
                    cmd = ftp.request_command.upper()
                    arg = getattr(ftp, 'request_arg', '').strip()

                    if cmd == 'USER':
                        print(f"[+] 发现用户: {arg}")
                    elif cmd == 'PASS':
                        print(f"    ╰-> 密码: {arg}")
                        credentials.append(arg)
                    elif cmd in ['RETR', 'STOR']:
                        current_filename = arg
                        print(f"\033[93m[*] 发现文件传输指令: {cmd} {arg}\033[0m")

                if hasattr(ftp, 'response_code') and ftp.response_code == '230':
                    print("\033[92m[OK] 登录成功\033[0m")
            except Exception: pass

        # 数据流分析
        if 'FTP-DATA' in pkt or 'TCP' in pkt:
            try:
                stream_id = pkt.tcp.stream
                if 'FTP-DATA' in pkt:
                    if stream_id not in filename_map:
                        filename_map[stream_id] = current_filename

                    if stream_id not in file_data_map:
                        file_data_map[stream_id] = bytearray()

                    raw_hex = getattr(pkt['FTP-DATA'], 'data_text', None)
                    if raw_hex:
                        raw_bytes = bytes.fromhex(raw_hex.replace(':', ''))
                        file_data_map[stream_id].extend(raw_bytes)
                    elif hasattr(pkt.tcp, 'payload'):
                        file_data_map[stream_id].extend(pkt.tcp.payload.binary_value)
            except Exception: pass

    # 写入文件
    print("-" * 60)
    save_count = 0
    for s_id, data in file_data_map.items():
        if len(data) > 0:
            raw_fname = filename_map.get(s_id, "other_file")
            base_fname = "".join([c for c in raw_fname if c.isalnum() or c in "._-"])

            name_part, ext_part = os.path.splitext(base_fname)

            final_fname = base_fname
            save_path = os.path.join(output_dir, final_fname)
            counter = 1

            while os.path.exists(save_path):
                final_fname = f"{name_part}{counter}{ext_part}"
                save_path = os.path.join(output_dir, final_fname)
                counter += 1

            with open(save_path, "wb") as f:
                f.write(data)
            print(f"\033[92m[DONE] 文件已提取: {save_path} ({len(data)} bytes)\033[0m")
            save_count += 1

    if save_count == 0:
        print("[!] 未发现可提取的文件内容。")

if __name__ == '__main__':
    path = input("请输入pcap文件路径:").strip().replace('"', '').replace("'", "")
    analyze_and_extract_ftp(path)
