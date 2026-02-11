# SMTP邮件分析

import os
import base64
import re
import sys
import pathlib
current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))
from utils import read_pcap


def safe_decode(b64_str):
    """处理SMTP认证的Base64"""
    try:
        clean_str = re.sub(r'^[CS]:\s*', '', b64_str).strip()
        missing_padding = len(clean_str) % 4
        if missing_padding:
            clean_str += '=' * (4 - missing_padding)
        return base64.b64decode(clean_str).decode('utf-8', errors='ignore')
    except:
        return None


def clean_all(line):
    """洗掉转义和换行"""
    if not line: return ""
    return line.replace('\\xd\\xa', '').replace('\r', '').replace('\n', '').strip()


def extract_images_from_raw(mail_buffer, folder_path):
    """根据文件头还原Base64图片附件"""
    full_text = "".join(mail_buffer)
    b64_blocks = re.findall(r'[A-Za-z0-9+/=\s]{100,}', full_text)

    img_count = 0
    for block in b64_blocks:
        clean_block = block.replace('\n', '').replace('\r', '').replace(' ', '')
        try:
            data = base64.b64decode(clean_block)
            ext = ""
            if data.startswith(b'\xff\xd8\xff'): ext = "jpg"
            elif data.startswith(b'\x89PNG\r\n\x1a\n'): ext = "png"
            elif data.startswith(b'GIF8'): ext = "gif"

            if ext:
                img_count += 1
                img_name = f"attachment_{img_count:02d}.{ext}"
                with open(os.path.join(folder_path, img_name), 'wb') as f:
                    f.write(data)
                print(f"    [#] 图片还原成功: {img_name}")
        except:
            continue


def extract_smtp_forensics(pcap_file):
    cap = read_pcap(pcap_file)

    base_output = pathlib.Path(__file__).resolve().parent.parent / "output" / "smtp"
    pcap_name = os.path.splitext(os.path.basename(pcap_file))[0]
    pcap_output_dir = os.path.join(base_output, pcap_name)

    if not os.path.exists(pcap_output_dir):
        os.makedirs(pcap_output_dir)
        print(f"[*] SMTP输出目录已就绪: {pcap_output_dir}")

    mail_count = 0
    is_collecting_data = False
    current_mail_buffer = []

    tracking_sender = "Unknown"
    tracking_receiver = "Unknown"
    auth_stage = 0

    print(f"\n[*] 正在深度扫描: {os.path.basename(pcap_file)}")
    print(f"[*] 结果将存入: {pcap_output_dir}")
    print("=" * 60)

    try:
        for packet in cap:
            msg = ""
            if 'SMTP' in packet:
                msg = getattr(packet.smtp, 'command_line', "") or getattr(packet.smtp, 'response_line', "")
            if not msg and 'TCP' in packet and hasattr(packet.tcp, 'payload'):
                try:
                    msg = bytes.fromhex(packet.tcp.payload.replace(':', '')).decode('utf-8', errors='ignore')
                except: continue
            if not msg: continue

            raw_line = clean_all(msg)
            if not raw_line: continue

            # 认证追踪
            if "AUTH LOGIN" in raw_line.upper():
                auth_stage = 1
                continue
            if auth_stage == 1 and (raw_line.startswith('C:') or len(raw_line) > 10):
                u = safe_decode(raw_line)
                if u:
                    print(f"[AUTH] 账号: {u}")
                    auth_stage = 2
                    continue
            if auth_stage == 2 and (raw_line.startswith('C:') or len(raw_line) > 10):
                p = safe_decode(raw_line)
                if p:
                    print(f"[AUTH] 密码: {p}")
                    auth_stage = 0
                    continue

            # 捕获发件人和收件人
            if "MAIL FROM:" in raw_line.upper():
                tracking_sender = raw_line[10:].split(' ')[0].strip('<>')
                print(f"发现发送端: {tracking_sender}")
            elif "RCPT TO:" in raw_line.upper():
                tracking_receiver = raw_line[8:].strip('<>')
                print(f"发现接收端: {tracking_receiver}")

            # 邮件内容抓取
            if "DATA" in raw_line.upper():
                is_collecting_data = True
                current_mail_buffer = []
                continue

            if is_collecting_data:
                if raw_line == ".":
                    is_collecting_data = False
                    mail_count += 1

                    mail_subject = "NoSubject"
                    for line in current_mail_buffer:
                        if line.upper().startswith("SUBJECT:"):
                            mail_subject = line[8:].strip()
                            break

                    safe_subject = re.sub(r'[\\/:*?"<>|]', '_', mail_subject)[:40]
                    folder_name = os.path.join(pcap_output_dir, f"Mail_{mail_count:02d}_{safe_subject}")
                    os.makedirs(folder_name, exist_ok=True)

                    with open(os.path.join(folder_name, "content.html"), "w", encoding="utf-8") as f:
                        f.write("\n".join(current_mail_buffer))

                    extract_images_from_raw(current_mail_buffer, folder_name)

                    print(f"发件人: {tracking_sender}")
                    print(f"主  题: {mail_subject}")
                    print(f"[+] 邮件 {mail_count} 导出完毕 -> {folder_name}")
                    print("-" * 60 + "\n")
                    continue
                else:
                    current_mail_buffer.append(raw_line)
                    continue

    except Exception as e:
        print(f"[!] 发生错误: {e}")
    finally:
        cap.close()

    print(f"[*] 分析完毕。PCAP '{pcap_name}' 共导出 {mail_count} 封邮件。")

if __name__ == '__main__':
    path = input("请输入pcap文件路径:").strip().replace('"', '').replace("'", "") 
    if os.path.exists(path):
        extract_smtp_forensics(path)
    else:
        print("[!] 文件不存在。")
