# CS_analyzer.py - 向后兼容包装 (核心逻辑已移至 protocol_analyzer.py)

import os
import sys
import base64
import pathlib

current_dir = pathlib.Path(__file__).resolve().parent
root_dir = current_dir.parent
sys.path.append(str(root_dir))

from core.protocol_analyzer import CobaltStrikeAnalyzer


def main():
    """交互式入口 (复原 cs_yb.py 完整流程)"""
    from utils import read_pcap

    # --- 阶段 1: 抓包提取 Cookie ---
    pcap_path = input("1. 请输入 PCAP 路径: ").strip().strip('"')
    if not os.path.exists(pcap_path):
        print("[-] 文件不存在")
        return

    print(f"\n[*] [步骤1] 正在分析 PCAP: {os.path.basename(pcap_path)}")
    cap = read_pcap(pcap_path)

    seen_cookies = set()
    cookies_list = []

    try:
        for pkt in cap:
            if 'HTTP' in pkt:
                try:
                    cookie = getattr(pkt.http, 'cookie', '')
                    if cookie and len(cookie) > 30 and cookie not in seen_cookies:
                        print(f"[+] 捕获新 Cookie: {cookie}")
                        seen_cookies.add(cookie)
                        cookies_list.append(cookie)
                except AttributeError:
                    continue
    except Exception as e:
        print(f"[-]读取 PCAP 出错: {e}")
    finally:
        if hasattr(cap, 'close'):
            cap.close()

    print(f"[OK] 共找到 {len(cookies_list)} 个潜在的 Metadata Cookie。\n")

    if not cookies_list:
        print("[-] 未发现 Cookie，无法继续。")
        return

    # --- 阶段 2: 提取 RSA Key ---
    key_file_path = input("2. 请输入 CS Key 文件路径 (如 .cobaltstrike.beacon_keys): ").strip().strip('"')
    if not os.path.exists(key_file_path):
        print("[-] 文件不存在")
        return

    print(f"[*] [步骤2] 正在提取密钥文件: {key_file_path}")
    try:
        import javaobj.v2 as javaobj

        with open(key_file_path, "rb") as fd:
            pobj = javaobj.load(fd)

        private_key_bytes = pobj.array.value.privateKey.encoded.data
        public_key_bytes = pobj.array.value.publicKey.encoded.data

        private_key_data = bytes(b & 0xFF for b in private_key_bytes)
        public_key_data = bytes(b & 0xFF for b in public_key_bytes)

        private_pem = (
            b"-----BEGIN PRIVATE KEY-----\n" +
            base64.encodebytes(private_key_data) +
            b"-----END PRIVATE KEY-----"
        )

        public_pem = (
            b"-----BEGIN PUBLIC KEY-----\n" +
            base64.encodebytes(public_key_data) +
            b"-----END PUBLIC KEY-----"
        )

        pcap_name = os.path.splitext(os.path.basename(pcap_path))[0]

        output_base = pathlib.Path(__file__).resolve().parent.parent / "output" / "cs"
        output_dir = output_base / pcap_name

        if not output_dir.exists():
            output_dir.mkdir(parents=True, exist_ok=True)
            print(f"[*] 已创建分类输出文件夹: {output_dir}")

        priv_path = output_dir / "cs_private.pem"
        pub_path = output_dir / "cs_public.pem"

        with open(priv_path, "wb") as f:
            f.write(private_pem)
        with open(pub_path, "wb") as f:
            f.write(public_pem)
            print(f"[+] 私钥已保存: {priv_path}")
            print(f"[+] 公钥已保存: {pub_path}")
            print("-" * 20)

    except Exception as e:
        print(f"[-] 密钥提取失败: {e}")
        return

    # --- 阶段 3: 解密 Cookie 获取 AES Key ---
    print("\n准备解密 Cookie...\n")
    priv_key_path = input(f"3. 请输入私钥路径 : ").strip().strip('"')
    if not priv_key_path:
        priv_key_path = str(priv_path)

    print(f"[*] [步骤3] 正在加载私钥并解密 Cookie...")

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        with open(priv_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        print(f"[-] 加载私钥失败: {e}")
        return

    sessions = []
    for idx, cookie_b64 in enumerate(cookies_list):
        print(f"\n--- 分析第 {idx+1} 个 Cookie ---")
        try:
            ciphertext = base64.b64decode(cookie_b64)
            plaintext = private_key.decrypt(ciphertext, padding.PKCS1v15())
            session_info = CobaltStrikeAnalyzer._parse_metadata(plaintext)
            if session_info:
                sessions.append(session_info)
        except Exception as e:
            print(f"[-] 该 Cookie 解密或解析失败 (可能不是 Metadata): {e}")

    if not sessions:
        print("[-] 未能成功解密任何 Session，无法进行后续流量解密。")
        return

    print(f"\n[+] 成功获取 {len(sessions)} 个 Beacon 会话密钥。")

    # 将 sessions 存入 analyzer 以便 decrypt_traffic 使用
    analyzer = CobaltStrikeAnalyzer()
    analyzer._sessions = sessions

    # --- 阶段 4: 解密具体流量 ---
    while True:
        print("\n" + "=" * 40)
        traffic_hex = input("4. 请输入要解密的 CS 传输数据 Hex (输入 'q' 退出): ").strip()
        if traffic_hex.lower() == 'q':
            break

        print(f"[*] 正在尝试匹配 {len(sessions)} 个已知的 Key...")
        for i, session in enumerate(sessions):
            print(f"\n--- 尝试使用 Session #{i+1} (ID: {session['bid']}) ---")
            analyzer.decrypt_traffic(traffic_hex, session_index=i)


if __name__ == '__main__':
    main()
