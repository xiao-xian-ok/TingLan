# TingLan MCP 使用说明

mcp_server.py v1.0

## 设计思路

v1.0就一个核心：**一键分析**

调analyze_pcap就完事了，它会自己判断要跑什么：
- 有HTTP就检测Webshell和攻击
- 有ICMP就跑隐写分析
- 有可疑数据就自动解码

不用一个个工具调了。

---

## 工具清单

### analyze_pcap - 主力工具

**丢个pcap进去，自动全套分析**

```json
{
  "pcap_path": "D:/test/sample.pcap",
  "max_packets": 0
}
```

会自动做这些事：
1. 协议统计
2. Webshell检测（蚁剑/菜刀/冰蝎/哥斯拉）
3. OWASP攻击检测
4. ICMP隐写（ICMP包够多的话）
5. 自动解码

返回示例：
```json
{
  "ok": true,
  "total_packets": 1234,
  "protocol_stats": [...],
  "threat_count": 6,
  "webshell_detections": [...],
  "attack_detections": [...],
  "icmp_analysis": {...},
  "auto_decoded": [...]
}
```

---

### 其他工具（按需用）

#### auto_decode - 解码

手动解码用的

```json
{
  "data": "YmFzZTY0X2VuY29kZWRfZGF0YQ==",
  "crib": "flag\\{.*\\}"
}
```

支持：Base64/32/58、Hex、URL、Binary、Morse、Gzip、Zlib、ROT13

---

#### detect_attack - 攻击检测

```json
{
  "data": "' OR 1=1--"
}
```

---

#### analyze_entropy - 熵分析

```json
{
  "data": "SGVsbG8gV29ybGQh"
}
```

---

#### identify_file_type - 文件类型

```json
{
  "data_hex": "89504E470D0A1A0A"
}
```

---

#### analyze_php_ast - PHP分析

```json
{
  "code": "<?php eval($_POST['cmd']); ?>"
}
```

---

## 使用建议

1. **直接用analyze_pcap**，它会自动跑需要的检测
2. 其他工具是给手动分析用的
3. 大文件可以设max_packets限制包数

---

## 配置

### 依赖

```bash
pip install mcp pyshark
```

### TShark

需要装Wireshark：
- Windows: `C:\Program Files\Wireshark\tshark.exe`
- Linux: `/usr/bin/tshark`
- macOS: `/usr/local/bin/tshark`

### Claude Desktop配置

```json
{
  "mcpServers": {
    "TingLan": {
      "command": "python",
      "args": ["/path/to/TingLan/mcp_server.py"]
    }
  }
}
```

---

## 更新记录

### v1.0
- 一站式分析，不用手动调多个工具了
- 自动ICMP隐写
- 自动攻击检测
- 自动解码
