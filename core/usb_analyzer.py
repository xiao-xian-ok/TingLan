# usb_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import os
import sys
import pathlib

current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.protocol_analyzer import USBAnalyzer


def analyze_usb_traffic(pcap_file):
    """旧版兼容入口, 返回 (keyboard_text, mouse_trace)"""
    analyzer = USBAnalyzer(generate_plot=False)
    result = analyzer.analyze_pcap(pcap_file)

    kb_text = result.metadata.get('keyboard_text', '')
    mouse_trace = result.metadata.get('mouse_trace', [])
    return kb_text, mouse_trace


def plot_mouse_trace(mouse_trace):
    """生成带时间渐变色的鼠标轨迹图"""
    if not mouse_trace:
        print("[!] 没有坐标点可以绘画")
        return

    import matplotlib.pyplot as plt
    import numpy as np

    x = np.array([p[0] for p in mouse_trace])
    y = np.array([p[1] for p in mouse_trace])
    time_index = np.linspace(0, 1, len(mouse_trace))

    plt.figure(figsize=(10, 6))
    plt.plot(x, y, color='gray', linewidth=0.5, alpha=0.3)
    scatter = plt.scatter(x, y, c=time_index, cmap='jet', s=15, edgecolors='none', zorder=5)
    cbar = plt.colorbar(scatter)
    cbar.set_label('Time Progression (Start: Blue -> End: Red)')
    plt.gca().invert_yaxis()
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

        print("\n" + "=" * 50)
        print(f"键盘还原内容: {kb_content if kb_content else '[未检测到按键数据]'}")
        print(f"鼠标轨迹点数: {len(mouse_points)}")
        print("=" * 50)

        if mouse_points:
            plot_mouse_trace(mouse_points)
    else:
        print(f"[!] 错误: 文件路径不存在 -> {pcap_input}")
