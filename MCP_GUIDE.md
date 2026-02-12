# 听澜 MCP 开发与扩展指南

> 适用范围：`mcp_server.py`（v4.1）

## 1. 核心设计理念

v4.1 的核心思想：**一个工具完成所有分析**

`analyze_pcap` 会自动根据流量内容智能调用相关分析模块：
- 检测到 HTTP 流量 → 自动运行 Webshell 检测 + 攻击检测
- 检测到 ICMP 流量 → 自动运行 ICMP 隐写分析
- 检测到 FTP 流量 → 自动提取凭据和文件信息
- 检测到 SMTP 流量 → 自动提取邮件和认证信息
- 检测到 USB 流量 → 自动还原键盘/鼠标数据
- 检测到蓝牙流量 → 自动提取 OBEX/L2CAP/GATT 数据
- 检测到可疑数据 → 自动尝试解码

无需手动依次调用多个工具，一次调用返回完整分析结果。

---

## 2. MCP 工具列表

### 2.1 主要工具

#### `analyze_pcap` - 智能流量分析（推荐）

**一站式分析，自动完成所有检测**

```json
{
  "pcap_path": "D:/test/sample.pcap",
  "max_packets": 0
}
```

**参数说明：**
- `pcap_path`: PCAP 文件路径（必填）
- `tshark_path`: 可选，显式指定 tshark 路径
- `max_packets`: 只分析前 N 个包（0 表示使用默认值 10000）

**自动执行的分析：**
1. 协议统计（HTTP/TCP/UDP/ICMP/DNS/FTP/SMTP/USB/蓝牙等）
2. Webshell 检测（蚁剑/菜刀/冰蝎/哥斯拉）
3. OWASP 攻击检测（SQLi/XSS/RCE/XXE 等）
4. ICMP 隐写分析（如果 ICMP 包 ≥ 5 个）
5. 自动解码可疑数据
6. FTP 分析（如果有 FTP 流量）
7. SMTP 分析（如果有 SMTP 流量）
8. USB 分析（如果有 USB 流量）
9. 蓝牙分析（如果有蓝牙流量）

**返回示例：**
```json
{
  "ok": true,
  "version": "v4.1",
  "file_path": "sample.pcap",
  "total_packets": 1234,
  "analysis_time": 2.5,
  "protocol_stats": [
    {"protocol": "HTTP", "count": 100, "percentage": 8.1}
  ],
  "threat_count": 6,
  "webshell_detections": [...],
  "attack_detections": [...],
  "icmp_analysis": {...},
  "auto_decoded": [...],
  "ftp_analysis": {"available": true, "credentials": [...], "files": [...]},
  "smtp_analysis": {"available": true, "credentials": [...], "emails_found": 3},
  "usb_analysis": {"available": true, "keyboard_data": "...", "mouse_point_count": 500},
  "bluetooth_analysis": {"available": true, "obex_count": 2, "l2cap_count": 100},
  "warnings": []
}
```

---

### 2.2 辅助工具（按需使用）

#### `auto_decode` - 自动解码

手动解码特定数据（CyberChef 风格）

```json
{
  "data": "YmFzZTY0X2VuY29kZWRfZGF0YQ==",
  "crib": "flag\\{.*\\}"
}
```

支持：Base64/32/58、Hex、URL、Binary、Morse、Gzip、Zlib、ROT13

---

#### `detect_attack` - 攻击检测

检测特定数据中的 OWASP Top 10 攻击签名

```json
{
  "data": "' OR 1=1--"
}
```

---

#### `analyze_entropy` - 熵分析

分析数据的信息熵，检测加密/混淆数据

```json
{
  "data": "SGVsbG8gV29ybGQh"
}
```

---

#### `identify_file_type` - 文件类型识别

基于 Magic Number 识别文件类型

```json
{
  "data_hex": "89504E470D0A1A0A"
}
```

---

#### `analyze_php_ast` - PHP AST 分析

基于语法树的 Webshell 检测（污点追踪）

```json
{
  "code": "<?php eval($_POST['cmd']); ?>"
}
```

---

### 2.3 新增工具（v4.1）

#### `analyze_ftp` - FTP 协议分析

分析 FTP 流量，提取登录凭据和传输文件信息

```json
{"pcap_path": "D:/test/ftp.pcap"}
```

---

#### `analyze_smtp` - SMTP 邮件分析

分析 SMTP 邮件流量，提取认证信息和邮件内容

```json
{"pcap_path": "D:/test/smtp.pcap"}
```

---

#### `analyze_usb` - USB 协议分析

分析 USB 流量，还原键盘输入和鼠标轨迹

```json
{"pcap_path": "D:/test/usb.pcap"}
```

---

#### `analyze_bluetooth` - 蓝牙协议分析

分析蓝牙流量（OBEX/L2CAP/GATT）

```json
{"pcap_path": "D:/test/bluetooth.pcap"}
```

---

#### `decrypt_webshell` - Webshell 解密

解密冰蝎/哥斯拉加密流量

```json
{
  "encrypted_data": "加密数据...",
  "shell_type": "behinder",
  "custom_key": "e45e329feb5d925b"
}
```

默认密钥：冰蝎 `e45e329feb5d925b`，哥斯拉 `3c6e0b8a9c15224a`

---

#### `fix_pcap` - PCAP 修复

修复损坏的 PCAP 文件

```json
{"pcap_path": "D:/test/broken.cap"}
```

---

#### `extract_files` - 文件提取

从流量中提取 HTTP/IMF/SMB/TFTP 等协议的文件

```json
{"pcap_path": "D:/test/traffic.pcap", "protocol": "http"}
```

---

## 3. 使用建议

### 3.1 典型工作流

```
1. 调用 analyze_pcap 分析流量文件
   ↓
2. 查看返回结果（自动包含所有分析）
   ↓
3. 如需深入分析，使用辅助工具
```

### 3.2 最佳实践

1. **优先使用 `analyze_pcap`**：它会自动完成所有常见分析
2. **辅助工具按需使用**：只在需要深入分析特定数据时调用
3. **大文件使用 `max_packets`**：限制分析包数量，加快速度

---

## 4. 配置说明

### 4.1 安装依赖

```bash
pip install mcp pyshark pycryptodome
```

### 4.2 TShark 配置

需要安装 Wireshark 并确保 TShark 可用：
- Windows: `C:\Program Files\Wireshark\tshark.exe`
- Linux: `/usr/bin/tshark`
- macOS: `/usr/local/bin/tshark`

### 4.3 Claude Desktop 配置

```json
{
  "mcpServers": {
    "tinglan": {
      "command": "python",
      "args": ["/path/to/TingLan/mcp_server.py"]
    }
  }
}
```

---

## 5. 版本更新

### v4.1 (当前版本)
- **新增 FTP 分析**：自动提取 FTP 凭据和文件传输信息
- **新增 SMTP 分析**：自动提取邮件认证和内容
- **新增 USB 分析**：自动还原键盘输入和鼠标轨迹
- **新增蓝牙分析**：自动提取 OBEX/L2CAP/GATT 数据
- **新增 Webshell 解密**：支持冰蝎/哥斯拉流量解密
- **新增 PCAP 修复**：修复损坏的 PCAP 文件
- **新增文件提取**：从流量中提取 HTTP/SMB 等文件
- **增强 analyze_pcap**：自动调用所有新增分析模块

### v4.0 历史版本
- 智能一站式分析
- 自动 ICMP 隐写检测
- 自动攻击检测
- 自动解码

---

## 6. 与前端 GUI 的一致性

| 功能 | 前端 GUI | MCP Server |
|------|----------|------------|
| Webshell 检测 | ✓ | ✓ |
| 攻击检测 | ✓ | ✓ |
| ICMP 隐写 | ✓ | ✓（自动） |
| 自动解码 | ✓ | ✓（自动） |
| 协议统计 | ✓ | ✓ |
| FTP 分析 | ✓ | ✓（自动） |
| SMTP 分析 | ✓ | ✓（自动） |
| USB 分析 | ✓ | ✓（自动） |
| 蓝牙分析 | ✓ | ✓（自动） |
| Webshell 解密 | ✓ | ✓ |
| PCAP 修复 | ✓ | ✓ |
| 文件提取 | ✓ | ✓ |
