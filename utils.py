from datetime import datetime
import os
import subprocess
import platform
import pyshark
import pathlib

def create_folder_if_not_exists(folder_path):     #创建文件夹
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        return False
    else:
        return True

def threading_directory(path):
    current_os = platform.system()
    if current_os == "Windows":
        os.startfile(path.replace('/', '\\'))
    elif current_os == "Linux":
        subprocess.call(["xdg-open", path])  # windows 工作目录
    else:
        print("不支持的操作系统")

def picture(packet):                #保存图片
    if hasattr(packet.http, 'file_data'):
        print(f"[*]找到图片数据，正在提取...")
        hex_data = packet.http.file_data.replace(':', '')  # 去掉冒号

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            filename = f'{timestamp}.png'
            binary_data = bytes.fromhex(hex_data)

            with open(filename, 'wb') as f:
                f.write(binary_data)

            print("[*]图片已保存为{0}".format(filename))

        except Exception as e:
            print(f"保存失败: {e}")


def read_pcap(pcap_file):
    # 1. 动态获取 tshark 路径
    current_dir = pathlib.Path(__file__).resolve().parent
    tshark_exe = current_dir / "wireshark" / "tshark.exe"
    
    # 2. 使用 FileCapture 并指定路径
    cap = pyshark.FileCapture(
        str(pcap_file), 
        tshark_path=str(tshark_exe),
        keep_packets=False 
    )
    return cap
def hex_to_string(hex_data):
    if not hex_data: return None
    hex_str = str(hex_data).replace(':', '').replace(' ', '').replace('0x', '')
    try:
        return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
    except Exception:
        return None