# fix_pcap.py - pcap修复工具

import struct
import os
import pathlib

def fix_cap_to_pcap(input_path):
    """将非标准.cap重组为标准.pcap"""
    output_base = pathlib.Path(__file__).resolve().parent.parent / "output" / "fix_pcap_output"

    # 如果 output 或 fix 不存在，均会被自动创建
    if not output_base.exists():
        output_base.mkdir(parents=True, exist_ok=True)
        print(f"[*] 已在上一级创建输出文件夹: {output_base}")

    # 获取输入文件名并拼接输出路径
    pcap_name = os.path.splitext(os.path.basename(input_path))[0]
    output_path = str(output_base / f"fixed_{pcap_name}.pcap")

    # 标准PCAP全局头 (Little Endian, Ethernet)
    PCAP_GLOBAL_HEADER = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'

    print(f"\n[*] 启动格式重构: {input_path}")
    print(f"[*] 导出目标: {output_path}")
    print("=" * 60)

    try:
        with open(input_path, 'rb') as f:
            raw_data = f.read()

        # 找第一个数据包: IPv4 (0x0800) + Header (0x45) 特征
        first_packet_pos = raw_data.find(b'\x08\x00\x45')
        if first_packet_pos == -1:
            print("[!] 未找到标准 IPv4 特征，尝试从偏移 128 开始暴力对齐...")
            first_packet_pos = 128
        else:
            first_packet_pos -= 12  # 回退到以太网帧MAC地址开头

        fixed_pcap = bytearray(PCAP_GLOBAL_HEADER)

        pos = first_packet_pos
        packet_count = 0
        file_size = len(raw_data)

        while pos < file_size - 60:
            try:
                next_sig = raw_data.find(b'\x08\x00\x45', pos + 14)

                if next_sig == -1:
                    current_incl_len = file_size - pos
                else:
                    packet_raw_end = next_sig - 12
                    current_incl_len = packet_raw_end - pos

                # 以太网帧通常60-1514字节
                if 40 <= current_incl_len <= 1514:
                    p_header = struct.pack('<IIII', 0, 0, current_incl_len, current_incl_len)

                    fixed_pcap.extend(p_header)
                    fixed_pcap.extend(raw_data[pos : pos + current_incl_len])
                    packet_count += 1
                    pos += current_incl_len
                else:
                    pos += 1
            except:
                pos += 1
                continue

        # 写文件
        if packet_count > 0:
            with open(output_path, 'wb') as f:
                f.write(fixed_pcap)
            print(f"[+] 修复完成！")
            print(f"[*] 从原始 cap 中成功剥离并重组了 {packet_count} 个数据包。")
            print(f"[*] 结果已存入: {output_path}")
        else:
            print("[!] 修复失败：未能在该文件中识别到有效的以太网帧数据。")

    except Exception as e:
        print(f"[!] 转换过程中发生异常: {e}")

if __name__ == '__main__':
    path = input("请输入文件路径: ").strip().strip('"').strip("'")
    if os.path.exists(path):
        fix_cap_to_pcap(path)
    else:
        print("[!] 路径无效，文件不存在。")
