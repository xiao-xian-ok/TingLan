import subprocess
import os
import sys
import pathlib
import matplotlib.pyplot as plt
import numpy as np

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from utils import read_pcap


def get_tshark_path():
    """动态定位项目内置的 tshark.exe"""
    tshark_exe = PROJECT_ROOT / "wireshark" / "tshark.exe"
    return str(tshark_exe) if tshark_exe.exists() else "tshark"

# 映射表与常量定义
KEY_MAP = {
    0x04: "a", 0x05: "b", 0x06: "c", 0x07: "d", 0x08: "e", 0x09: "f", 0x0a: "g", 0x0b: "h", 0x0c: "i", 0x0d: "j", 0x0e: "k", 0x0f: "l", 0x10: "m", 0x11: "n", 0x12: "o", 0x13: "p", 0x14: "q", 0x15: "r", 0x16: "s", 0x17: "t", 0x18: "u", 0x19: "v", 0x1a: "w", 0x1b: "x", 0x1c: "y", 0x1d: "z",
    0x1e: "1", 0x1f: "2", 0x20: "3", 0x21: "4", 0x22: "5", 0x23: "6", 0x24: "7", 0x25: "8", 0x26: "9", 0x27: "0", 0x28: "\n", 0x2c: " ", 0x2d: "-", 0x2e: "=", 0x2f: "[", 0x30: "]", 0x31: "\\", 0x33: ";", 0x34: "'", 0x36: ",", 0x37: ".", 0x38: "/"
}

SHIFT_MAP = {
    "a": "A", "b": "B", "c": "C", "d": "D", "e": "E", "f": "F", "g": "G", "h": "H", "i": "I", "j": "J", "k": "K", "l": "L", "m": "M", "n": "N", "o": "O", "p": "P", "q": "Q", "r": "R", "s": "S", "t": "T", "u": "U", "v": "V", "w": "W", "x": "X", "y": "Y", "z": "Z",
    "1": "!", "2": "@", "3": "#", "4": "$", "5": "%", "6": "^", "7": "&", "8": "*", "9": "(", "0": ")", "-": "_", "=": "+", "[": "{", "]": "}", "\\": "|", ";": ":", "'": "\"", ",": "<", ".": ">", "/": "?"
}


# 核心功能函数
def analyze_usb_traffic(pcap_file):
    tshark_path = get_tshark_path()
    
    # 提取多字段：usbhid.data, usb.capdata, 以及 data.data (保底)
    cmd = [
        tshark_path, "-r", pcap_file, 
        "-T", "fields", 
        "-e", "usbhid.data", 
        "-e", "usb.capdata",
        "-e", "data.data"
    ]
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
    stdout, stderr = process.communicate()
    
    kb_result, mouse_trace = [], []
    cur_x, cur_y = 0, 0

    for line in stdout.strip().split('\n'):
        # 提取第一个非空数据串并清洗
        data = "".join(line.split()).replace(':', '')
        if not data: continue
        
        d_len = len(data)

        # 情况 A: 12字符 (12-bit 坐标鼠标)
        if d_len == 12:
            try:
                btn = int(data[2:4], 16)
                b1, b2, b3 = int(data[4:6], 16), int(data[6:8], 16), int(data[8:10], 16)
                x = b1 | ((b2 & 0x0f) << 8)
                y = (b2 >> 4) | (b3 << 4)
                if x > 2047: x -= 4096
                if y > 2047: y -= 4096
                cur_x += x; cur_y += y
                if btn != 0: mouse_trace.append((cur_x, cur_y))
            except: continue

        # 情况 B: 8字符 (标准 3 字节鼠标)
        elif d_len == 8:
            try:
                btn = int(data[0:2], 16)
                x, y = int(data[2:4], 16), int(data[4:6], 16)
                if x > 127: x -= 256
                if y > 127: y -= 256
                cur_x += x; cur_y += y
                if btn & 0x7: mouse_trace.append((cur_x, cur_y))
            except: continue

        # 情况 C: 16字符 (标准键盘)
        elif d_len == 16:
            try:
                mod = int(data[0:2], 16)
                key = int(data[4:6], 16)
                if key == 0: continue
                char = KEY_MAP.get(key, "")
                if char:
                    # 左右 Shift 键位检测 (0x02 或 0x20)
                    is_shift = (mod & 0x02) or (mod & 0x20)
                    kb_result.append(SHIFT_MAP.get(char, char.upper()) if is_shift else char)
            except: continue

    return "".join(kb_result), mouse_trace

def plot_mouse_trace(mouse_trace):
    """生成带时间渐变色的鼠标轨迹图"""
    if not mouse_trace:
        print("[!] 没有坐标点可以绘画")
        return

    x = np.array([p[0] for p in mouse_trace])
    y = np.array([p[1] for p in mouse_trace])
    
    # 时间渐变：越晚生成的点颜色越深
    time_index = np.linspace(0, 1, len(mouse_trace))

    plt.figure(figsize=(10, 6))
    
    # 绘制轨迹连线 (淡灰色)
    plt.plot(x, y, color='gray', linewidth=0.5, alpha=0.3)
    
    # 绘制渐变散点 (jet: 蓝 -> 绿 -> 红)
    scatter = plt.scatter(x, y, c=time_index, cmap='jet', s=15, edgecolors='none', zorder=5)
    
    # 装饰
    cbar = plt.colorbar(scatter)
    cbar.set_label('Time Progression (Start: Blue -> End: Red)')
    
    plt.gca().invert_yaxis() # 坐标系习惯：向上为负
    plt.axis('equal')
    plt.title("Mouse Movement Trace (Gradient Analysis)")
    plt.grid(True, linestyle=':', alpha=0.6)
    
    print("[+] 轨迹图已生成，正在显示...")
    plt.show()


if __name__ == '__main__':
    pcap_input = input("请输入pcap文件路径: ").strip().strip('"').strip("'")
    
    if os.path.exists(pcap_input):
        print(f"[*] 正在通过 TShark 解析: {os.path.basename(pcap_input)}")
        kb_content, mouse_points = analyze_usb_traffic(pcap_input)
        
        print("\n" + "="*50)
        print(f"键盘还原内容: {kb_content if kb_content else '[未检测到按键数据]'}")
        print(f"鼠标轨迹点数: {len(mouse_points)}")
        print("="*50)
        
        if mouse_points:
            plot_mouse_trace(mouse_points)
    else:
        print(f"[!] 错误: 文件路径不存在 -> {pcap_input}")