# 蓝牙obex协议

import os
import binascii
import re
import sys
import pathlib
current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from utils import read_pcap, create_folder_if_not_exists

def clean_hex_string(raw_hex):
    if not raw_hex: return ""
    cleaned = re.sub(r'[^0-9a-fA-F]', '', str(raw_hex))
    if len(cleaned) % 2 != 0:
        cleaned = cleaned[:-1]
    return cleaned

def extract_bluetooth_data(pcap_file):
    output_base = pathlib.Path(__file__).resolve().parent.parent / "output" / "bt_output"
    output_base.mkdir(parents=True, exist_ok=True)

    pcap_name = pathlib.Path(pcap_file).stem
    case_dir = output_base / pcap_name
    case_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] 蓝牙数据将提取至: {case_dir}")

    cap = read_pcap(pcap_file)

    obex_sessions = {}
    l2cap_records = []
    gatt_records = []

    print(f"[*] 正在分析: {pcap_name}")

    try:
        for packet in cap:
            try:
                session_id = f"{packet.bluetooth.src}_{packet.bluetooth.dst}"
            except:
                session_id = "unknown"

            # OBEX文件传输
            if 'OBEX' in packet:
                obex = packet.obex
                if session_id not in obex_sessions:
                    obex_sessions[session_id] = {'filename': None, 'data': ''}

                if hasattr(obex, 'name'):
                    obex_sessions[session_id]['filename'] = os.path.basename(str(obex.name))

                if hasattr(obex, 'header_value_byte_sequence'):
                    obex_sessions[session_id]['data'] += str(obex.header_value_byte_sequence)

                is_final = False
                if hasattr(obex, 'final_flag') and str(obex.final_flag) == '1':
                    is_final = True
                elif int(getattr(obex, 'opcode', '0x00'), 16) & 0x80:
                    is_final = True

                if is_final:
                    session = obex_sessions[session_id]
                    # 同时有文件名和数据才保存
                    if session['filename'] and session['data']:
                        hex_str = clean_hex_string(session['data'])
                        if hex_str:
                            target_dir = os.path.join(case_dir, 'obex_files')
                            create_folder_if_not_exists(target_dir)

                            save_path = os.path.join(target_dir, session['filename'])
                            with open(save_path, 'wb') as f:
                                f.write(binascii.unhexlify(hex_str))
                            print(f"[+] [OBEX] 提取成功: {session['filename']}")

                        obex_sessions[session_id] = {'filename': None, 'data': ''}
                    else:
                        # 没文件名的可能是心跳/握手包，跳过
                        obex_sessions[session_id] = {'filename': None, 'data': ''}


            elif 'BT-L2CAP' in packet:
                if hasattr(packet.btl2cap, 'payload'):
                    payload = clean_hex_string(packet.btl2cap.payload)
                    if payload:
                        l2cap_records.append(f"[{packet.number}] {payload}\n")

            elif 'BTATT' in packet:
                if hasattr(packet.btatt, 'value'):
                    val = clean_hex_string(packet.btatt.value)
                    gatt_records.append(f"[{packet.number}] Handle {getattr(packet.btatt, 'handle', 'N/A')}: {val}\n")

    except Exception as e:
        print(f"[!] 异常: {e}")
    finally:
        cap.close()

    print(f"[*] 任务完成。")

if __name__ == '__main__':
    path = input("请输入pcap文件路径: ").strip().strip('"').strip("'")
    extract_bluetooth_data(path)
