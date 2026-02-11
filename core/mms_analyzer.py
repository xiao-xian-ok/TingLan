# mms协议分析

import os
import binascii
import sys
import pathlib
current_script = pathlib.Path(__file__).resolve()
PROJECT_ROOT = current_script.parent.parent
sys.path.append(str(PROJECT_ROOT))
from utils import read_pcap

sys.stdout.reconfigure(encoding='utf-8')

def mms_extract_tool(pcap_file):
    """追踪InvokeID，提取MMS文件传输数据"""
    base_output = pathlib.Path(__file__).resolve().parent.parent / "output" / "mms"

    pcap_name = os.path.splitext(os.path.basename(pcap_file))[0]
    save_dir = os.path.join(base_output, pcap_name)
    
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
        print(f"[*] 提取目录: {save_dir}")

    cap = read_pcap(pcap_file)

    # 状态追踪: Open请求 -> FRSMID绑定 -> Read请求 -> 数据提取
    open_inv_to_name = {}   # InvokeID -> 文件名 (72 Request)
    frsm_to_name = {}       # FRSMID -> 文件名 (72 Response绑定)
    read_inv_to_name = {}   # InvokeID -> 文件名 (73 Request)

    print(f"[*] 开始深度分析: {os.path.basename(pcap_file)}")
    print("-" * 50)

    for pkt in cap:
        try:
            if 'mms' not in [l.layer_name for l in pkt.layers]:
                continue

            mms = pkt.mms
            pkt_num = pkt.number

            inv_id = getattr(mms, "invokeid", None)

            # 文件打开请求 (Confirmed-RequestPDU, 72)
            if hasattr(mms, "confirmedservicerequest") and int(mms.confirmedservicerequest) == 72:
                if hasattr(mms, "filename_item"):
                    try:
                        raw_fname = mms.filename_item.fields[0].get_default_value()
                        fname = os.path.basename(str(raw_fname))

                        if inv_id:
                            open_inv_to_name[inv_id] = fname

                        print(f"[#Pkt:{pkt_num} | ID:{inv_id}] 发现 Open 请求: {fname}")
                    except:
                        pass

            # 绑定FRSMID (Confirmed-ResponsePDU, 72)
            elif hasattr(mms, "confirmedserviceresponse") and int(mms.confirmedserviceresponse) == 72:
                if inv_id in open_inv_to_name:
                    fname = open_inv_to_name.pop(inv_id)
                    if hasattr(mms, "frsmid"):
                        f_id = str(mms.frsmid)
                        frsm_to_name[f_id] = fname
                        print(f"[#Pkt:{pkt_num} | ID:{inv_id}] Open 成功: {fname} (获得 FRSMID: {f_id})")

            # 文件读取请求 (Confirmed-RequestPDU, 73)
            elif hasattr(mms, "confirmedservicerequest") and int(mms.confirmedservicerequest) == 73:
                if hasattr(mms, "fileread"):
                    f_id = str(mms.fileread)
                    if f_id in frsm_to_name:
                        fname = frsm_to_name[f_id]
                        if inv_id:
                            read_inv_to_name[inv_id] = fname
                        if "flag" in fname.lower():
                            print(f"\n{'='*60}")
                            print(f"[!] [#Pkt:{pkt_num} | ID:{inv_id}] 关键读取: 正在请求 {fname}")
                            print(f"{'='*60}\n")

            # 提取文件数据 (Confirmed-ResponsePDU, 73)
            elif hasattr(mms, "confirmedserviceresponse") and int(mms.confirmedserviceresponse) == 73:
                if inv_id in read_inv_to_name:
                    fname = read_inv_to_name.pop(inv_id)
                    file_path = os.path.join(save_dir, fname)

                    if hasattr(mms, "filedata"):
                        raw_val = str(mms.filedata).replace(":", "").replace(" ", "")
                        try:
                            data_to_save = binascii.unhexlify(raw_val)
                        except:
                            data_to_save = raw_val.encode('utf-8')

                        with open(file_path, "ab") as f:
                            f.write(data_to_save)

                        if "flag" in fname.lower():
                            decoded_content = data_to_save.decode(errors='ignore')
                            print(f"\n{'='*20} FLAG FOUND {'='*20}")
                            print(f"数据包号: {pkt_num}")
                            print(f"InvokeID: {inv_id} (Wireshark 过滤器: mms.invokeID == {inv_id})")
                            print(f"文件内容: {decoded_content}")
                            print(f"{'='*52}\n")
                        else:
                            print(f"[+] [#Pkt:{pkt_num} | ID:{inv_id}] 已还原数据到: {fname}")

                # 孤立的带数据响应包
                elif hasattr(mms, "filedata"):
                     print(f"[?] [#Pkt:{pkt_num} | ID:{inv_id}] 发现未匹配数据的响应，请检查该 ID")

        except Exception as e:
            continue

    cap.close()
    print("-" * 50)
    print(f"[*] 分析完成。提取文件存放于: {os.path.abspath(save_dir)}")
    print(">>> wireshark搜索 mms.invokeID == ID号 可进一步查看内容")

if __name__ == '__main__':
    target_pcap = input("请输入pcap文件路径:").strip().replace('"', '').replace("'", "")
    mms_extract_tool(target_pcap)
